"""Read-side analytics over the OpenSearch event store, for the dashboard,
investigations and the assistant. Return shapes match the previous SQLite version
so the API, assistant and frontend are unchanged, except event ids are now the
document _id (string) and event pagination uses an opaque cursor.

IP notes live in SQLite (console metadata); everything else comes from the store.
"""
import base64
import json
import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from . import mitre, store

PRESETS = {"1h": timedelta(hours=1), "24h": timedelta(days=1), "7d": timedelta(days=7),
           "30d": timedelta(days=30), "90d": timedelta(days=90)}
TS_RE = re.compile(r"^\d{4}-\d{2}-\d{2}(T\d{2}:\d{2}(:\d{2})?(\.\d+)?Z?)?$")

INTERACTIVE = ["SSH", "TELNET"]


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
    source: str | None = None
    technique: str | None = None
    tactic: str | None = None

    def query(self) -> dict:
        return store.build_query(self)


# --------------------------------------------------------------------------- agg helpers

def _exists(field):
    return {"exists": {"field": field}}


def _filter_agg(cond, sub):
    return {"filter": cond, "aggs": {"v": sub}}


def _terms(field, size=10):
    return {"terms": {"field": field, "size": size}}


def _multi(fields, size=10):
    return {"multi_terms": {"terms": [{"field": f} for f in fields], "size": size}}


def _buckets(agg) -> list[dict]:
    # Unwrap an optional filter wrapper, then read terms buckets.
    node = agg.get("v", agg)
    out = []
    for b in node.get("buckets", []):
        key = b["key"]
        if isinstance(key, list):
            key = " : ".join(str(k) for k in key)
        out.append({"key": key, "count": b["doc_count"]})
    return out


def _top(agg, joiner=None) -> list[dict]:
    rows = _buckets(agg)
    if joiner:
        for r in rows:
            r["key"] = r["key"].replace(" : ", joiner)
    return rows


def _fmt(rows, n=8):
    return rows[:n]


def _techniques(agg) -> list[dict]:
    rows = _buckets(agg)
    for r in rows:
        info = mitre.TECHNIQUES.get(r["key"])
        r["name"] = info[0] if info else r["key"]
        r["tactic"] = info[1] if info else ""
        r["id"] = r["key"]
        r["key"] = f"{r['id']} {r['name']}"
    return rows


# --------------------------------------------------------------------------- stats

def stats(conn, f: Filters) -> dict:
    q = f.query()
    since = resolve_since(f.since)
    span_hours = 24.0
    if since:
        start = datetime.fromisoformat(since.replace("Z", "+00:00"))
        span_hours = max(1, (datetime.now(timezone.utc) - start).total_seconds() / 3600)
    interval = "hour" if span_hours <= 72 else "day"
    fmt = "yyyy-MM-dd'T'HH" if interval == "hour" else "yyyy-MM-dd"

    ssh_telnet = {"terms": {"protocol": INTERACTIVE}}
    aggs = {
        "ips": _terms("src_ip", 15),
        "protocols": _terms("protocol"),
        "clients": _terms("client"),
        "agents": _terms("user_agent"),
        "passwords": _terms("password"),
        "users": _filter_agg(_exists("password"), _terms("user")),
        "credentials": _filter_agg(_exists("password"), _multi(["user", "password"])),
        "commands": _filter_agg({"bool": {"filter": [ssh_telnet, _exists("command")]}}, _terms("command", 15)),
        "uris": _filter_agg({"term": {"protocol": "HTTP"}}, _multi(["method", "uri"], 15)),
        "urls": _filter_agg({"term": {"source": "browser"}}, _terms("url", 15)),
        "tcp_payloads": _filter_agg({"bool": {"filter": [{"term": {"protocol": "TCP"}}, _exists("command")]}},
                                    _multi(["description", "command"])),
        "tactics": _terms("tactics", 15),
        "techniques": _terms("techniques", 20),
        "uniq_ip": {"cardinality": {"field": "src_ip"}},
        "sessions": _filter_agg({"bool": {"must_not": [{"term": {"status": "Stateless"}}]}},
                                {"cardinality": {"field": "session"}}),
        "logins": {"filter": _exists("password")},
        "cmd_count": {"filter": {"bool": {"filter": [ssh_telnet, _exists("command")]}}},
        "first": {"min": {"field": "ts"}},
        "last": {"max": {"field": "ts"}},
        "timeline": {"date_histogram": {"field": "ts", "calendar_interval": interval, "format": fmt},
                     "aggs": {"protocol": _terms("protocol", 6)}},
    }
    res = store.search(q, size=0, aggs=aggs, track_total=True)
    a = res["aggregations"]
    total = res["hits"]["total"]["value"]

    def ts_of(node):
        v = node.get("value_as_string")
        return v[:19] + "Z" if v else None

    kpi = {"events": total, "ips": a["uniq_ip"]["value"], "sessions": a["sessions"]["v"]["value"],
           "logins": a["logins"]["doc_count"], "commands": a["cmd_count"]["doc_count"],
           "first": ts_of(a["first"]), "last": ts_of(a["last"])}
    timeline = []
    for b in a["timeline"]["buckets"]:
        for pb in b["protocol"]["buckets"]:
            timeline.append({"bucket": b["key_as_string"], "protocol": pb["key"], "count": pb["doc_count"]})
    return {"kpi": kpi, "bucket": interval, "timeline": timeline,
            "protocols": _fmt(_buckets(a["protocols"])), "clients": _fmt(_buckets(a["clients"])),
            "ips": _fmt(_buckets(a["ips"]), 15), "users": _fmt(_buckets(a["users"])),
            "passwords": _fmt(_buckets(a["passwords"])),
            "credentials": _fmt(_top(a["credentials"], " : ")),
            "commands": _fmt(_buckets(a["commands"]), 15),
            "uris": _fmt(_top(a["uris"], " "), 15),
            "urls": _fmt(_buckets(a["urls"]), 15),
            "agents": _fmt(_buckets(a["agents"])),
            "tcp_payloads": _fmt(_top(a["tcp_payloads"], " — ")),
            "tactics": _fmt(_buckets(a["tactics"]), 15),
            "techniques": _fmt(_techniques(a["techniques"]), 20)}


# --------------------------------------------------------------------------- events

_EVENT_FIELDS = ["ts", "client", "protocol", "status", "msg", "session", "src_ip", "src_port",
                 "user", "password", "command", "method", "uri", "user_agent", "description",
                 "source", "url", "title", "device", "browser_user", "techniques", "tactics"]


def _row(hit) -> dict:
    src = hit["_source"]
    row = {"id": hit["_id"]}
    for k in _EVENT_FIELDS:
        row[k] = src.get(k, "")
    return row


def _cursor_encode(sort) -> str:
    return base64.urlsafe_b64encode(json.dumps(sort).encode()).decode()


def _cursor_decode(cur) -> list | None:
    try:
        return json.loads(base64.urlsafe_b64decode(cur))
    except (ValueError, TypeError):
        return None


def events(conn, f: Filters, limit: int = 100, before=None) -> dict:
    sort = [{"ts": "desc"}, {"_id": "desc"}]
    after = _cursor_decode(before) if before else None
    res = store.search(f.query(), size=limit, sort=sort, search_after=after)
    hits = res["hits"]["hits"]
    nxt = _cursor_encode(hits[-1]["sort"]) if len(hits) == limit and hits else None
    return {"events": [_row(h) for h in hits], "next": nxt}


def event(conn, event_id: str) -> dict | None:
    res = store.search({"ids": {"values": [str(event_id)]}}, size=1)
    hits = res["hits"]["hits"]
    if not hits:
        return None
    d = dict(hits[0]["_source"])
    d["id"] = hits[0]["_id"]
    return d


# --------------------------------------------------------------------------- sessions

def _session_aggs(size):
    return {
        "terms": {"field": "session", "size": size, "order": {"start": "desc"}},
        "aggs": {"start": {"min": {"field": "ts"}}, "end": {"max": {"field": "ts"}},
                 "interactions": {"filter": {"term": {"status": "Interaction"}}},
                 "top": {"top_hits": {"size": 1, "_source": ["client", "protocol", "src_ip", "user", "description"]}}}}


def _session_rows(agg) -> list[dict]:
    rows = []
    for b in agg["buckets"]:
        src = b["top"]["hits"]["hits"][0]["_source"] if b["top"]["hits"]["hits"] else {}
        rows.append({"session": b["key"], "client": src.get("client", ""), "protocol": src.get("protocol", ""),
                     "src_ip": src.get("src_ip", ""), "user": src.get("user", ""),
                     "description": src.get("description", ""),
                     "start": b["start"]["value_as_string"], "end": b["end"]["value_as_string"],
                     "interactions": b["interactions"]["doc_count"], "events": b["doc_count"]})
    return rows


def sessions(conn, f: Filters, limit: int = 100, offset: int = 0) -> list[dict]:
    q = f.query()
    q.setdefault("bool", {}).setdefault("must_not", []).append({"term": {"status": "Stateless"}})
    q["bool"].setdefault("filter", []).append(_exists("session"))
    res = store.search(q, size=0, aggs={"sessions": _session_aggs(limit + offset)})
    return _session_rows(res["aggregations"]["sessions"])[offset:offset + limit]


def session_detail(conn, session_id: str) -> list[dict]:
    res = store.search({"term": {"session": session_id}}, size=1000, sort=[{"ts": "asc"}, {"_id": "asc"}])
    out = []
    for h in res["hits"]["hits"]:
        s = h["_source"]
        out.append({"id": h["_id"], "client": s.get("client", ""), "ts": s.get("ts", ""),
                    "protocol": s.get("protocol", ""), "status": s.get("status", ""), "msg": s.get("msg", ""),
                    "src_ip": s.get("src_ip", ""), "src_port": s.get("src_port", ""), "user": s.get("user", ""),
                    "password": s.get("password", ""), "command": s.get("command", ""),
                    "output": s.get("output", ""), "method": s.get("method", ""), "uri": s.get("uri", ""),
                    "user_agent": s.get("user_agent", ""), "description": s.get("description", "")})
    return out


# --------------------------------------------------------------------------- attackers / IPs

def attackers(conn, f: Filters, limit: int = 200) -> list[dict]:
    aggs = {"ips": {"terms": {"field": "src_ip", "size": limit},
                    "aggs": {"protocols": {"cardinality": {"field": "protocol"}},
                             "protocol_list": _terms("protocol", 10),
                             "clients": _terms("client", 20),
                             "logins": {"filter": _exists("password")},
                             "first": {"min": {"field": "ts"}}, "last": {"max": {"field": "ts"}}}}}
    res = store.search(f.query(), size=0, aggs=aggs)
    rows = []
    ips = []
    for b in res["aggregations"]["ips"]["buckets"]:
        ips.append(b["key"])
        rows.append({"ip": b["key"], "events": b["doc_count"], "protocols": b["protocols"]["value"],
                     "protocol_list": ",".join(x["key"] for x in b["protocol_list"]["buckets"]),
                     "clients": ",".join(x["key"] for x in b["clients"]["buckets"]),
                     "logins": b["logins"]["doc_count"],
                     "first": b["first"]["value_as_string"], "last": b["last"]["value_as_string"], "tags": None})
    tags = _note_tags(conn, ips)
    for r in rows:
        r["tags"] = tags.get(r["ip"])
    return rows


def ip_profile(conn, ip: str) -> dict:
    q = {"term": {"src_ip": ip}}
    ssh_telnet = {"terms": {"protocol": INTERACTIVE}}
    aggs = {
        "protocols": _terms("protocol"), "clients": _terms("client", 20),
        "credentials": _filter_agg(_exists("password"), _multi(["user", "password"], 50)),
        "commands": _filter_agg({"bool": {"filter": [ssh_telnet, _exists("command")]}}, _terms("command", 50)),
        "uris": _filter_agg({"term": {"protocol": "HTTP"}}, _multi(["method", "uri"], 15)),
        "urls": _filter_agg({"term": {"source": "browser"}}, _terms("url", 30)),
        "agents": _terms("user_agent", 20), "clients_ver": _terms("client_ver", 20),
        "tactics": _terms("tactics", 15), "techniques": _terms("techniques", 20),
        "uniq_ip": {"cardinality": {"field": "src_ip"}},
        "sessions_c": _filter_agg({"bool": {"must_not": [{"term": {"status": "Stateless"}}]}},
                                  {"cardinality": {"field": "session"}}),
        "logins": {"filter": _exists("password")},
        "first": {"min": {"field": "ts"}}, "last": {"max": {"field": "ts"}},
        "activity": {"date_histogram": {"field": "ts", "calendar_interval": "day", "format": "yyyy-MM-dd"}},
        "sessions": _session_aggs(50),
    }
    res = store.search(q, size=0, aggs=aggs, track_total=True)
    a = res["aggregations"]
    total = res["hits"]["total"]["value"]
    summary = {"events": total, "first": a["first"].get("value_as_string"),
               "last": a["last"].get("value_as_string"), "sessions": a["sessions_c"]["v"]["value"],
               "logins": a["logins"]["doc_count"]}
    note = _note(conn, ip)
    return {"ip": ip, "summary": summary, "protocols": _buckets(a["protocols"]),
            "clients": _buckets(a["clients"]), "credentials": _top(a["credentials"], " : ")[:50],
            "commands": _buckets(a["commands"])[:50], "uris": _top(a["uris"], " ")[:15],
            "urls": _buckets(a["urls"])[:30],
            "agents": _buckets(a["agents"]), "clients_ver": _buckets(a["clients_ver"]),
            "tactics": _buckets(a["tactics"]), "techniques": _techniques(a["techniques"]),
            "sessions": _session_rows(a["sessions"])[:10],
            "activity": [{"bucket": b["key_as_string"], "count": b["doc_count"]} for b in a["activity"]["buckets"]],
            "note": note}


def attack_matrix(conn, f: Filters) -> dict:
    """ATT&CK tactics -> techniques with counts, for the matrix view."""
    aggs = {"tactics": {"terms": {"field": "tactics", "size": 20},
                        "aggs": {"techniques": {"terms": {"field": "techniques", "size": 30}}}},
            "classified": {"filter": _exists("techniques")}}
    res = store.search(f.query(), size=0, aggs=aggs, track_total=True)
    a = res["aggregations"]
    by_tactic = {}
    for tb in a["tactics"]["buckets"]:
        techs = []
        for xb in tb["techniques"]["buckets"]:
            info = mitre.TECHNIQUES.get(xb["key"])
            if info and info[1] == tb["key"]:  # technique belongs to this tactic
                techs.append({"id": xb["key"], "name": info[0], "count": xb["doc_count"]})
        by_tactic[tb["key"]] = {"tactic": tb["key"], "count": tb["doc_count"], "techniques": techs}
    ordered = [by_tactic[t] for t in mitre.TACTICS if t in by_tactic]
    return {"total": res["hits"]["total"]["value"], "classified": a["classified"]["doc_count"],
            "tactics": ordered}


def client_counts(conn) -> dict[str, dict]:
    aggs = {"clients": {"terms": {"field": "client", "size": 500},
                        "aggs": {"last": {"max": {"field": "ts"}},
                                 "last24h": {"filter": {"range": {"ts": {"gte": "now-24h"}}}}}}}
    res = store.search({"match_all": {}}, size=0, aggs=aggs)
    return {b["key"]: {"client": b["key"], "events": b["doc_count"],
                       "last": b["last"].get("value_as_string"), "last24h": b["last24h"]["doc_count"]}
            for b in res["aggregations"]["clients"]["buckets"]}


# --------------------------------------------------------------------------- notes (SQLite)

def _note(conn, ip: str) -> dict:
    row = conn.execute("SELECT tags, note, updated, updated_by FROM ip_notes WHERE ip = ?", (ip,)).fetchone()
    return dict(row) if row else {"tags": "", "note": "", "updated": None, "updated_by": None}


def _note_tags(conn, ips: list[str]) -> dict[str, str]:
    if not ips:
        return {}
    marks = ",".join("?" * len(ips))
    return {r["ip"]: r["tags"] for r in
            conn.execute(f"SELECT ip, tags FROM ip_notes WHERE ip IN ({marks})", ips)}


def save_note(conn, ip: str, tags: str, note: str, user: str) -> None:
    conn.execute(
        "INSERT INTO ip_notes(ip, tags, note, updated, updated_by) "
        "VALUES (?, ?, ?, strftime('%Y-%m-%dT%H:%M:%SZ','now'), ?) "
        "ON CONFLICT(ip) DO UPDATE SET tags=excluded.tags, note=excluded.note, "
        "updated=excluded.updated, updated_by=excluded.updated_by",
        (ip, tags, note, user))
