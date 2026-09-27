import sqlite3
from contextlib import contextmanager

from . import config

SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    id          INTEGER PRIMARY KEY,
    hash        BLOB NOT NULL UNIQUE,
    client      TEXT NOT NULL,
    ts          TEXT NOT NULL,
    protocol    TEXT, status TEXT, msg TEXT, session TEXT,
    src_ip      TEXT, src_port TEXT,
    user        TEXT, password TEXT,
    command     TEXT, output TEXT,
    method      TEXT, uri TEXT, user_agent TEXT, host TEXT, body TEXT,
    client_ver  TEXT, description TEXT, handler TEXT, tls_sni TEXT,
    raw         TEXT
);
CREATE INDEX IF NOT EXISTS ix_events_ts      ON events(ts);
CREATE INDEX IF NOT EXISTS ix_events_client  ON events(client, ts);
CREATE INDEX IF NOT EXISTS ix_events_ip      ON events(src_ip, ts);
CREATE INDEX IF NOT EXISTS ix_events_session ON events(session);
CREATE INDEX IF NOT EXISTS ix_events_proto   ON events(protocol, ts);

CREATE TABLE IF NOT EXISTS ingest_files (
    path TEXT PRIMARY KEY, inode INTEGER, offset INTEGER, head BLOB
);
CREATE TABLE IF NOT EXISTS ingest_archives (path TEXT PRIMARY KEY);

CREATE TABLE IF NOT EXISTS ip_notes (
    ip TEXT PRIMARY KEY, tags TEXT NOT NULL DEFAULT '', note TEXT NOT NULL DEFAULT '',
    updated TEXT NOT NULL, updated_by TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS assistant_conversations (
    id TEXT PRIMARY KEY, user TEXT NOT NULL, title TEXT NOT NULL, created TEXT NOT NULL, updated TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS assistant_messages (
    id INTEGER PRIMARY KEY, conv_id TEXT NOT NULL, role TEXT NOT NULL, content TEXT NOT NULL,
    meta TEXT NOT NULL DEFAULT '{}', created TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_assistant_messages_conv ON assistant_messages(conv_id, id);
CREATE TABLE IF NOT EXISTS app_config (
    key TEXT PRIMARY KEY, value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS telemetry_enrollments (
    id TEXT PRIMARY KEY, label TEXT NOT NULL, token_hash TEXT NOT NULL UNIQUE,
    created TEXT NOT NULL, created_by TEXT NOT NULL, revoked INTEGER NOT NULL DEFAULT 0,
    last_seen TEXT, event_count INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS audit (
    id INTEGER PRIMARY KEY, ts TEXT NOT NULL, user TEXT NOT NULL,
    action TEXT NOT NULL, target TEXT NOT NULL, detail TEXT NOT NULL DEFAULT ''
);
"""


def connect() -> sqlite3.Connection:
    conn = sqlite3.connect(config.DB_PATH, timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.execute("PRAGMA busy_timeout=30000")
    return conn


@contextmanager
def session():
    conn = connect()
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def init() -> None:
    config.DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    with session() as conn:
        conn.executescript(SCHEMA)


def audit(conn, user: str, action: str, target: str, detail: str = "") -> None:
    conn.execute(
        "INSERT INTO audit(ts, user, action, target, detail) "
        "VALUES (strftime('%Y-%m-%dT%H:%M:%SZ','now'), ?, ?, ?, ?)",
        (user, action, target, detail[:4000]),
    )
