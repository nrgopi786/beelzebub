"""Tails every Xpod's beelzebub.log (and rotated .gz archives) into the OpenSearch
event store as source="xpod" documents.

File offsets live in SQLite (ingest_files/ingest_archives): they are console-local
bookkeeping, not shared data. De-duplication of the events themselves is by document
_id in the store, so overlap between a rotated archive and the live log is harmless.
"""
import gzip
import hashlib
import json
import logging
import os
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

from . import config, db, store

log = logging.getLogger("console.ingest")

MAX_LINE = 2 * 1024 * 1024
MAX_FIELD = 64 * 1024
MAX_RAW = 256 * 1024
READ_CHUNK = 32 * 1024 * 1024
HEAD_BYTES = 256
TS_FORMAT = "%Y-%m-%dT%H:%M:%S.%fZ"

# beelzebub tracer.Event field -> store field
FIELDS = {
    "Protocol": "protocol", "Status": "status", "Msg": "msg", "ID": "session",
    "SourcePort": "src_port", "User": "user", "Password": "password",
    "Command": "command", "CommandOutput": "output", "HTTPMethod": "method",
    "RequestURI": "uri", "UserAgent": "user_agent", "HostHTTPRequest": "host",
    "Body": "body", "Client": "client_ver", "Description": "description",
    "Handler": "handler", "TLSServerName": "tls_sni",
}


def _clip(value) -> str:
    if value is None:
        return ""
    if not isinstance(value, str):
        value = str(value)
    return value[:MAX_FIELD]


def _norm_ts(value) -> str:
    if isinstance(value, str) and value:
        try:
            dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt.astimezone(timezone.utc).strftime(TS_FORMAT)
        except ValueError:
            pass
    return datetime.now(timezone.utc).strftime(TS_FORMAT)


def parse_line(client: str, line: bytes) -> dict | None:
    """Return a store document for an attacker event line, or None."""
    line = line.strip()
    if not line or len(line) > MAX_LINE or not line.startswith(b"{"):
        return None
    try:
        rec = json.loads(line)
    except ValueError:
        return None
    ev = rec.get("event") if isinstance(rec, dict) else None
    if not isinstance(ev, dict):
        return None

    src_ip = _clip(ev.get("SourceIp"))
    if not src_ip:
        remote = _clip(ev.get("RemoteAddr"))
        src_ip = remote.rsplit(":", 1)[0].strip("[]") if ":" in remote else remote
    doc = {"_id": hashlib.sha1(client.encode() + b"\0" + line).hexdigest(),
           "source": "xpod", "client": client,
           "ts": _norm_ts(ev.get("DateTime") or rec.get("time")),
           "raw": line.decode("utf-8", "replace")[:MAX_RAW]}
    if src_ip:
        doc["src_ip"] = src_ip
    for key, field in FIELDS.items():
        val = _clip(ev.get(key))
        if val:
            doc[field] = val
    return doc


def _index(client: str, lines) -> int:
    docs = [d for d in (parse_line(client, ln) for ln in lines) if d]
    return store.bulk_index(docs)


def _ingest_archive(conn, client: str, path: Path) -> None:
    if conn.execute("SELECT 1 FROM ingest_archives WHERE path=?", (str(path),)).fetchone():
        return
    added = 0
    try:
        with gzip.open(path, "rb") as fh:
            batch = []
            for line in fh:
                batch.append(line)
                if len(batch) >= 2000:
                    added += _index(client, batch)
                    batch.clear()
            added += _index(client, batch)
    except (OSError, EOFError) as exc:
        log.warning("skipping unreadable archive %s: %s", path, exc)
        return
    conn.execute("INSERT OR IGNORE INTO ingest_archives(path) VALUES (?)", (str(path),))
    conn.commit()
    if added:
        log.info("ingested %d events from %s", added, path.name)


def _tail_live(conn, client: str, path: Path) -> None:
    try:
        st = path.stat()
        with open(path, "rb") as fh:
            head = fh.read(HEAD_BYTES)
            state = conn.execute(
                "SELECT inode, offset, head FROM ingest_files WHERE path=?", (str(path),)
            ).fetchone()
            offset = 0
            if state and state["inode"] == st.st_ino and st.st_size >= state["offset"]:
                old_head = state["head"] or b""
                if head[: len(old_head)] == old_head:
                    offset = state["offset"]
            if st.st_size == offset and state:
                return
            fh.seek(offset)
            data = fh.read(min(st.st_size - offset, READ_CHUNK))
    except FileNotFoundError:
        return

    last_nl = data.rfind(b"\n")
    if last_nl < 0:
        if len(data) <= MAX_LINE:
            return
        consumed, lines = len(data), []
    else:
        consumed, lines = last_nl + 1, data[:last_nl].split(b"\n")
    added = _index(client, lines)
    conn.execute(
        "INSERT INTO ingest_files(path, inode, offset, head) VALUES (?,?,?,?) "
        "ON CONFLICT(path) DO UPDATE SET inode=excluded.inode, offset=excluded.offset, head=excluded.head",
        (str(path), st.st_ino, offset + consumed, head))
    conn.commit()
    if added:
        log.info("ingested %d events for %s", added, client)


def scan_once(conn) -> None:
    if not config.CLIENTS_DIR.is_dir():
        return
    for client_dir in sorted(config.CLIENTS_DIR.iterdir()):
        logs = client_dir / "data" / "logs"
        if not logs.is_dir():
            continue
        client = client_dir.name
        for archive in sorted(logs.glob("beelzebub-*.log.gz")):
            _ingest_archive(conn, client, archive)
        _tail_live(conn, client, logs / "beelzebub.log")


def purge(conn=None) -> None:
    if config.RETENTION_DAYS <= 0:
        return
    deleted = store.purge_older_than(config.RETENTION_DAYS)
    if deleted:
        log.info("retention: purged %d events from store", deleted)


def _run(stop: threading.Event) -> None:
    # Wait for the store to accept the index template before ingesting.
    while not stop.is_set() and not store.ensure_ready():
        stop.wait(5)
    last_purge = 0.0
    while not stop.is_set():
        try:
            with db.session() as conn:
                scan_once(conn)
                if time.monotonic() - last_purge > 3600:
                    purge()
                    last_purge = time.monotonic()
        except Exception:
            log.exception("ingest pass failed")
        stop.wait(config.INGEST_INTERVAL)


def start() -> threading.Event:
    stop = threading.Event()
    threading.Thread(target=_run, args=(stop,), name="ingest", daemon=True).start()
    return stop
