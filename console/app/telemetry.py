"""Browser telemetry ingest for the transparent, consent-based Chrome extension.

Devices are enrolled by an admin, who issues a token. The extension posts visited
page URLs (and titles/timestamps) with that token. The console writes them into the
same OpenSearch store as source="browser", so the frontend shows browser activity and
Xpod activity together.

Scope guardrails enforced here, not just in the extension:
- Only http/https page URLs are accepted; other schemes are dropped.
- URL credentials (user:pass@host) and fragments are stripped.
- Only url/title/ts/visit_type are read; any other field a client sends is ignored, so
  this endpoint cannot become a keystroke/form/password sink.
"""
import hashlib
import hmac
import logging
import re
import secrets
import time
from datetime import datetime, timezone
from urllib.parse import urlsplit, urlunsplit

from . import db, store

log = logging.getLogger("console.telemetry")

MAX_EVENTS_PER_POST = 500
MAX_URL = 4096
MAX_TITLE = 1024
LABEL_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 _.-]{0,48}$")


def create_enrollment(label: str, user: str) -> dict:
    label = label.strip()
    if not LABEL_RE.match(label):
        raise ValueError("label: letters, digits, space, . _ - (max 49 chars)")
    token = "xpt_" + secrets.token_urlsafe(30)
    tid = secrets.token_hex(8)
    with db.session() as conn:
        conn.execute(
            "INSERT INTO telemetry_enrollments(id, label, token_hash, created, created_by, revoked) "
            "VALUES (?, ?, ?, strftime('%Y-%m-%dT%H:%M:%SZ','now'), ?, 0)",
            (tid, label, _hash(token), user))
        db.audit(conn, user, "telemetry.enroll", label, tid)
    return {"id": tid, "label": label, "token": token}


def list_enrollments() -> list[dict]:
    with db.session() as conn:
        return [dict(r) for r in conn.execute(
            "SELECT id, label, created, created_by, revoked, last_seen, event_count "
            "FROM telemetry_enrollments ORDER BY created DESC")]


def revoke_enrollment(tid: str, user: str) -> bool:
    with db.session() as conn:
        cur = conn.execute("UPDATE telemetry_enrollments SET revoked=1 WHERE id=?", (tid,))
        if cur.rowcount:
            db.audit(conn, user, "telemetry.revoke", tid)
        return cur.rowcount > 0


def _hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def _verify(token: str) -> dict | None:
    if not token or not token.startswith("xpt_"):
        return None
    th = _hash(token)
    with db.session() as conn:
        row = conn.execute(
            "SELECT id, label, token_hash, revoked FROM telemetry_enrollments WHERE token_hash=?", (th,)
        ).fetchone()
    if not row or row["revoked"] or not hmac.compare_digest(row["token_hash"], th):
        return None
    return {"id": row["id"], "label": row["label"]}


def _clean_url(raw) -> str | None:
    if not isinstance(raw, str) or len(raw) > MAX_URL:
        return None
    try:
        p = urlsplit(raw.strip())
    except ValueError:
        return None
    if p.scheme not in ("http", "https") or not p.netloc:
        return None
    host = p.hostname or ""              # drops any user:pass@
    if p.port:
        host = f"{host}:{p.port}"
    return urlunsplit((p.scheme, host, p.path, p.query, ""))  # drop fragment


def _norm_ts(value) -> str:
    if isinstance(value, (int, float)):
        try:
            return datetime.fromtimestamp(value / 1000 if value > 1e12 else value, timezone.utc)\
                .strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        except (ValueError, OverflowError, OSError):
            pass
    if isinstance(value, str) and value:
        try:
            dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
            return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        except ValueError:
            pass
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def ingest(token: str, payload: dict, src_ip: str) -> dict:
    enr = _verify(token)
    if not enr:
        return {"ok": False, "code": 401, "error": "invalid or revoked token"}
    device = str(payload.get("device", ""))[:64] or "unknown"
    events = payload.get("events")
    if not isinstance(events, list):
        return {"ok": False, "code": 400, "error": "events must be a list"}

    docs = []
    for ev in events[:MAX_EVENTS_PER_POST]:
        if not isinstance(ev, dict):
            continue
        url = _clean_url(ev.get("url"))
        if not url:
            continue
        ts = _norm_ts(ev.get("ts"))
        doc = {"_id": hashlib.sha1(f"{enr['id']}\0{device}\0{ts}\0{url}".encode()).hexdigest(),
               "source": "browser", "protocol": "WEB", "client": enr["label"],
               "browser_user": enr["label"], "device": device, "session": f"{enr['id']}:{device}",
               "status": "Visit", "msg": "Page visit", "ts": ts, "url": url,
               "visit_type": str(ev.get("visit_type", "navigation"))[:32], "src_ip": src_ip}
        title = ev.get("title")
        if isinstance(title, str) and title.strip():
            doc["title"] = title.strip()[:MAX_TITLE]
        docs.append(doc)

    created = store.bulk_index(docs)
    with db.session() as conn:
        conn.execute(
            "UPDATE telemetry_enrollments SET last_seen=strftime('%Y-%m-%dT%H:%M:%SZ','now'), "
            "event_count=event_count+? WHERE id=?", (created, enr["id"]))
    return {"ok": True, "accepted": len(docs), "stored": created}
