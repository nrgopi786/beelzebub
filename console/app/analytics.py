"""Read-side queries over ingested events for the dashboard and investigations."""
import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

PRESETS = {"1h": timedelta(hours=1), "24h": timedelta(days=1), "7d": timedelta(days=7),
           "30d": timedelta(days=30), "90d": timedelta(days=90)}
TS_RE = re.compile(r"^\d{4}-\d{2}-\d{2}(T\d{2}:\d{2}(:\d{2})?Z?)?$")

# Columns listed in the event table; raw JSON is fetched per event only.
LIST_COLS = ("id, client, ts, protocol, status, msg, session, src_ip, src_port, user, password, "
             "command, method, uri, user_agent, description")
SEARCH_COLS = ("command", "uri", "user", "password", "user_agent", "body", "output", "host", "tls_sni")


def _iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def resolve_since(since: str | None) -> str | None:
    if not since or since == "all":
        return None
    if since in PRESETS:
        return _iso(datetime.now(timezone.utc) - PRESETS[since])
    if TS_RE.match(since):
        return since
    raise ValueError("since must be a preset (1h, 24h, 7d, 30d, 90d, all) or an ISO timestamp")


@dataclass
class Filters:
    client: str | None = None
    protocol: str | None = None
    ip: str | None = None
    session: str | None = None
    status: str | None = None
    q: str | None = None
    since: str | None = "24h"
    until: str | None = None

    def where(self, alias: str = "") -> tuple[str, list]:
        p = f"{alias}." if alias else ""
        clauses, args = [], []
        for col, val in (("client", self.client), ("protocol", self.protocol), ("src_ip", self.ip),
                         ("session", self.session), ("status", self.status)):
            if val:
                clauses.append(f"{p}{col} = ?")
                args.append(val)
        since = resolve_since(self.since)
        if since:
            clauses.append(f"{p}ts >= ?")
            args.append(since)
        if self.until:
            if not TS_RE.match(self.until):
                raise ValueError("until must be an ISO timestamp")
            clauses.append(f"{p}ts <= ?")
            args.append(self.until)
        if self.q:
            like = "%" + self.q.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"
            clauses.append("(" + " OR ".join(f"{p}{c} LIKE ? ESCAPE '\\'" for c in SEARCH_COLS) + ")")
            args.extend([like] * len(SEARCH_COLS))
        return (" WHERE " + " AND ".join(clauses)) if clauses else "", args


def _rows(cur) -> list[dict]:
    return [dict(r) for r in cur.fetchall()]


def _top(conn, f: Filters, expr: str, extra: str = "", limit: int = 10) -> list[dict]:
    where, args = f.where()
    cond = f"{expr} IS NOT NULL AND {expr} != ''" + (f" AND {extra}" if extra else "")
    where = f"{where} AND {cond}" if where else f" WHERE {cond}"
    return _rows(conn.execute(
        f"SELECT {expr} AS key, COUNT(*) AS count FROM events{where} "
        f"GROUP BY key ORDER BY count DESC LIMIT ?", (*args, limit)))


def stats(conn, f: Filters) -> dict:
    where, args = f.where()
    kpi = dict(conn.execute(
        "SELECT COUNT(*) AS events, COUNT(DISTINCT NULLIF(src_ip,'')) AS ips, "
        "COUNT(DISTINCT CASE WHEN status != 'Stateless' THEN session END) AS sessions, "
        "SUM(CASE WHEN password != '' THEN 1 ELSE 0 END) AS logins, "
        "SUM(CASE WHEN command != '' AND protocol IN ('SSH','TELNET') THEN 1 ELSE 0 END) AS commands, "
        "MIN(ts) AS first, MAX(ts) AS last "
        f"FROM events{where}", args).fetchone())

    # Hourly buckets for short windows, daily otherwise.
    span_hours = 24
    since = resolve_since(f.since)
    if since and kpi["last"]:
        start = datetime.fromisoformat(since.replace("Z", "+00:00")) if "T" in since else \
            datetime.fromisoformat(since).replace(tzinfo=timezone.utc)
        span_hours = (datetime.now(timezone.utc) - start).total_seconds() / 3600
    elif kpi["first"] and kpi["last"]:
        a = datetime.fromisoformat(kpi["first"].replace("Z", "+00:00"))
        b = datetime.fromisoformat(kpi["last"].replace("Z", "+00:00"))
        span_hours = (b - a).total_seconds() / 3600
    bucket_len = 13 if span_hours <= 72 else 10  # 'YYYY-MM-DDTHH' vs 'YYYY-MM-DD'
    timeline = _rows(conn.execute(
        f"SELECT substr(ts,1,{bucket_len}) AS bucket, protocol, COUNT(*) AS count FROM events{where} "
        "GROUP BY bucket, protocol ORDER BY bucket", args))

    return {
        "kpi": kpi,
        "bucket": "hour" if bucket_len == 13 else "day",
        "timeline": timeline,
        "protocols": _top(conn, f, "protocol"),
        "clients": _top(conn, f, "client"),
        "ips": _top(conn, f, "src_ip", limit=15),
        "users": _top(conn, f, "user", "password != ''"),
        "passwords": _top(conn, f, "password"),
        "credentials": _top(conn, f, "user || ' : ' || password", "password != ''"),
        "commands": _top(conn, f, "command", "protocol IN ('SSH','TELNET')", limit=15),
        "uris": _top(conn, f, "method || ' ' || uri", "protocol = 'HTTP'", limit=15),
        "agents": _top(conn, f, "user_agent"),
        "tcp_payloads": _top(conn, f, "description || ' — ' || substr(command,1,80)",
                             "protocol = 'TCP' AND command != ''"),
    }


def events(conn, f: Filters, limit: int = 100, before: int | None = None) -> dict:
    where, args = f.where()
    if before:
        where = f"{where} AND id < ?" if where else " WHERE id < ?"
        args.append(before)
    rows = _rows(conn.execute(
        f"SELECT {LIST_COLS} FROM events{where} ORDER BY id DESC LIMIT ?", (*args, limit + 1)))
    more = len(rows) > limit
    rows = rows[:limit]
    return {"events": rows, "next": rows[-1]["id"] if more and rows else None}


def event(conn, event_id: int) -> dict | None:
    row = conn.execute("SELECT * FROM events WHERE id = ?", (event_id,)).fetchone()
    if not row:
        return None
    d = dict(row)
    d.pop("hash", None)
    return d


def sessions(conn, f: Filters, limit: int = 100, offset: int = 0) -> list[dict]:
    where, args = f.where()
    cond = "session != '' AND status != 'Stateless'"
    where = f"{where} AND {cond}" if where else f" WHERE {cond}"
    return _rows(conn.execute(
        "SELECT session, client, MAX(protocol) AS protocol, MAX(src_ip) AS src_ip, "
        "MAX(user) AS user, MAX(description) AS description, MIN(ts) AS start, MAX(ts) AS end, "
        "SUM(status = 'Interaction') AS interactions, COUNT(*) AS events "
        f"FROM events{where} GROUP BY session, client ORDER BY start DESC LIMIT ? OFFSET ?",
        (*args, limit, offset)))


def session_detail(conn, session_id: str) -> list[dict]:
    return _rows(conn.execute(
        "SELECT id, client, ts, protocol, status, msg, src_ip, src_port, user, password, command, "
        "output, method, uri, user_agent, description FROM events WHERE session = ? ORDER BY ts, id",
        (session_id,)))


def attackers(conn, f: Filters, limit: int = 200) -> list[dict]:
    where, args = f.where("e")
    cond = "e.src_ip != ''"
    where = f"{where} AND {cond}" if where else f" WHERE {cond}"
    return _rows(conn.execute(
        "SELECT e.src_ip AS ip, COUNT(*) AS events, COUNT(DISTINCT e.protocol) AS protocols, "
        "GROUP_CONCAT(DISTINCT e.protocol) AS protocol_list, GROUP_CONCAT(DISTINCT e.client) AS clients, "
        "SUM(e.password != '') AS logins, MIN(e.ts) AS first, MAX(e.ts) AS last, "
        "n.tags AS tags "
        f"FROM events e LEFT JOIN ip_notes n ON n.ip = e.src_ip{where} "
        "GROUP BY e.src_ip ORDER BY events DESC LIMIT ?", (*args, limit)))


def ip_profile(conn, ip: str) -> dict:
    f = Filters(ip=ip, since="all")
    summary = dict(conn.execute(
        "SELECT COUNT(*) AS events, MIN(ts) AS first, MAX(ts) AS last, "
        "COUNT(DISTINCT CASE WHEN status != 'Stateless' THEN session END) AS sessions, "
        "SUM(password != '') AS logins FROM events WHERE src_ip = ?", (ip,)).fetchone())
    note = conn.execute("SELECT tags, note, updated, updated_by FROM ip_notes WHERE ip = ?", (ip,)).fetchone()
    return {
        "ip": ip,
        "summary": summary,
        "protocols": _top(conn, f, "protocol"),
        "clients": _top(conn, f, "client"),
        "credentials": _top(conn, f, "user || ' : ' || password", "password != ''", limit=50),
        "commands": _top(conn, f, "command", "protocol IN ('SSH','TELNET')", limit=50),
        "uris": _top(conn, f, "method || ' ' || uri", "protocol = 'HTTP'", limit=50),
        "agents": _top(conn, f, "user_agent", limit=20),
        "clients_ver": _top(conn, f, "client_ver", limit=20),
        "sessions": sessions(conn, f, limit=50),
        "activity": _rows(conn.execute(
            "SELECT substr(ts,1,10) AS bucket, COUNT(*) AS count FROM events WHERE src_ip = ? "
            "GROUP BY bucket ORDER BY bucket", (ip,))),
        "note": dict(note) if note else {"tags": "", "note": "", "updated": None, "updated_by": None},
    }


def save_note(conn, ip: str, tags: str, note: str, user: str) -> None:
    conn.execute(
        "INSERT INTO ip_notes(ip, tags, note, updated, updated_by) "
        "VALUES (?, ?, ?, strftime('%Y-%m-%dT%H:%M:%SZ','now'), ?) "
        "ON CONFLICT(ip) DO UPDATE SET tags=excluded.tags, note=excluded.note, "
        "updated=excluded.updated, updated_by=excluded.updated_by",
        (ip, tags, note, user))


def client_counts(conn) -> dict[str, dict]:
    return {r["client"]: dict(r) for r in conn.execute(
        "SELECT client, COUNT(*) AS events, MAX(ts) AS last, "
        "SUM(ts >= strftime('%Y-%m-%dT%H:%M:%SZ','now','-1 day')) AS last24h "
        "FROM events GROUP BY client")}
