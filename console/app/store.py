"""OpenSearch-backed event store, shared by Xpod activity and browser telemetry.

One unified document schema, distinguished by `source` ("xpod" | "browser"). Events are
written to daily indices events-YYYY.MM.DD and searched through the events-* pattern.
De-duplication is by document _id (a content hash), so replaying a rotated log or a
retried telemetry batch is idempotent.

Console metadata (login, IP notes, audit, assistant chats) stays in SQLite; only events
live here, so the store scales horizontally without touching that.
"""
import json
import logging
import urllib.error
import urllib.request
from datetime import datetime, timezone

from . import config

log = logging.getLogger("console.store")

INDEX_PATTERN = "events-*"
TEMPLATE = "xpods-events"

# Fields the free-text q searches (case-insensitive substring). Kept as keyword+lowercase.
SEARCH_FIELDS = ("command", "uri", "user", "password", "user_agent", "body", "output",
                 "host", "tls_sni", "url", "title")
KEYWORD = ("source", "client", "protocol", "status", "msg", "session", "src_ip", "src_port",
           "user", "password", "method", "uri", "user_agent", "host", "client_ver",
           "description", "handler", "tls_sni", "url", "title", "device", "browser_user",
           "visit_type", "techniques", "tactics")

_MAPPING = {
    "index_patterns": [INDEX_PATTERN],
    "template": {
        "settings": {"number_of_shards": 1, "number_of_replicas": 0,
                     "analysis": {"normalizer": {"lc": {"type": "custom", "filter": ["lowercase"]}}}},
        "mappings": {
            "dynamic": False,
            "properties": {
                "source": {"type": "keyword"},
                "ts": {"type": "date"},
                "client": {"type": "keyword"},
                "protocol": {"type": "keyword"},
                "status": {"type": "keyword"},
                "msg": {"type": "keyword"},
                "session": {"type": "keyword"},
                "src_ip": {"type": "keyword"},
                "src_port": {"type": "keyword"},
                "user": {"type": "keyword", "normalizer": "lc"},
                "password": {"type": "keyword", "normalizer": "lc"},
                "command": {"type": "keyword", "normalizer": "lc", "ignore_above": 32766},
                "output": {"type": "keyword", "normalizer": "lc", "ignore_above": 32766},
                "method": {"type": "keyword"},
                "uri": {"type": "keyword", "normalizer": "lc", "ignore_above": 32766},
                "user_agent": {"type": "keyword", "normalizer": "lc", "ignore_above": 8192},
                "host": {"type": "keyword", "normalizer": "lc"},
                "body": {"type": "keyword", "normalizer": "lc", "ignore_above": 32766},
                "client_ver": {"type": "keyword"},
                "description": {"type": "keyword"},
                "handler": {"type": "keyword"},
                "tls_sni": {"type": "keyword", "normalizer": "lc"},
                # browser telemetry
                "url": {"type": "keyword", "normalizer": "lc", "ignore_above": 32766},
                "title": {"type": "keyword", "normalizer": "lc", "ignore_above": 8192},
                "device": {"type": "keyword"},
                "browser_user": {"type": "keyword"},
                "visit_type": {"type": "keyword"},
                "techniques": {"type": "keyword"},
                "tactics": {"type": "keyword"},
                "classified": {"type": "boolean"},
                "raw": {"type": "text", "index": False},
            },
        },
    },
}


class StoreError(RuntimeError):
    pass


def _req(method: str, path: str, body=None, timeout: int = 30, ndjson: bool = False):
    data = None
    headers = {}
    if body is not None:
        if ndjson:
            data = body.encode() if isinstance(body, str) else body
            headers["Content-Type"] = "application/x-ndjson"
        else:
            data = json.dumps(body).encode()
            headers["Content-Type"] = "application/json"
    req = urllib.request.Request(config.OS_URL + path, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.load(r)
    except urllib.error.HTTPError as e:
        detail = e.read().decode(errors="replace")[:500]
        raise StoreError(f"{method} {path} -> {e.code}: {detail}") from None
    except (urllib.error.URLError, OSError) as e:
        raise StoreError(f"{method} {path} -> {e}") from None


ATTACK_PROPS = {"techniques": {"type": "keyword"}, "tactics": {"type": "keyword"},
                "classified": {"type": "boolean"}}


def ensure_ready() -> bool:
    try:
        _req("PUT", f"/_index_template/{TEMPLATE}", _MAPPING, timeout=10)
        put_mapping(ATTACK_PROPS)  # add ATT&CK fields to any pre-existing indices
        return True
    except StoreError as e:
        log.warning("store not ready: %s", e)
        return False


def put_mapping(props: dict) -> None:
    """Add new fields to existing indices' mappings (no-op when none match)."""
    try:
        _req("PUT", f"/{INDEX_PATTERN}/_mapping", {"properties": props}, timeout=15)
    except StoreError as e:
        if "index_not_found" not in str(e) and "no such index" not in str(e).lower():
            log.warning("put_mapping: %s", e)


def scan(query: dict, fields, batch: int = 1000):
    """Yield (_id, index, _source) across the whole result set via search_after."""
    after = None
    while True:
        res = search(query, size=batch, sort=[{"ts": "asc"}, {"_id": "asc"}], source=fields,
                     search_after=after)
        hits = res["hits"]["hits"]
        if not hits:
            return
        for h in hits:
            yield h["_id"], h["_index"], h["_source"]
        if len(hits) < batch:
            return
        after = hits[-1]["sort"]


def bulk_update(updates: list[tuple]) -> int:
    """updates: list of (index, _id, partial_doc). Returns number updated."""
    if not updates:
        return 0
    lines = []
    for index, _id, doc in updates:
        lines.append(json.dumps({"update": {"_index": index, "_id": _id}}))
        lines.append(json.dumps({"doc": doc}, default=str))
    res = _req("POST", "/_bulk", "\n".join(lines) + "\n", ndjson=True, timeout=120)
    return sum(1 for it in res.get("items", []) if it.get("update", {}).get("status") in (200, 201))


def health() -> dict:
    try:
        h = _req("GET", "/_cluster/health", timeout=5)
        c = _req("GET", f"/{INDEX_PATTERN}/_count", timeout=5).get("count", 0) if h else 0
        return {"reachable": True, "status": h.get("status"), "docs": c}
    except StoreError as e:
        return {"reachable": False, "error": str(e)}


def _index_for(ts: str) -> str:
    try:
        d = datetime.fromisoformat(ts.replace("Z", "+00:00")).astimezone(timezone.utc)
    except (ValueError, AttributeError):
        d = datetime.now(timezone.utc)
    return d.strftime("events-%Y.%m.%d")


def bulk_index(docs: list[dict]) -> int:
    """Index docs (each must carry _id and ts). Returns the number newly created."""
    if not docs:
        return 0
    lines = []
    for d in docs:
        doc = dict(d)
        _id = doc.pop("_id")
        lines.append(json.dumps({"create": {"_index": _index_for(doc["ts"]), "_id": _id}}))
        lines.append(json.dumps(doc, default=str))
    res = _req("POST", "/_bulk", "\n".join(lines) + "\n", ndjson=True, timeout=120)
    created = 0
    for item in res.get("items", []):
        status = item.get("create", {}).get("status")
        if status in (200, 201):
            created += 1
        elif status != 409:  # 409 = already exists (dedup), expected
            log.debug("bulk item error: %s", item)
    return created


def purge_older_than(days: int) -> int:
    if days <= 0:
        return 0
    body = {"query": {"range": {"ts": {"lt": f"now-{days}d"}}}}
    try:
        res = _req("POST", f"/{INDEX_PATTERN}/_delete_by_query?conflicts=proceed", body, timeout=120)
        return res.get("deleted", 0)
    except StoreError as e:
        log.warning("purge failed: %s", e)
        return 0


# --------------------------------------------------------------------------- query building

def build_query(f) -> dict:
    """Translate an analytics.Filters into an OpenSearch bool query."""
    from .analytics import resolve_since, TS_RE
    must, filt = [], []
    for field, val in (("source", getattr(f, "source", None)), ("client", f.client),
                       ("protocol", f.protocol), ("src_ip", f.ip), ("session", f.session),
                       ("status", f.status), ("techniques", getattr(f, "technique", None)),
                       ("tactics", getattr(f, "tactic", None))):
        if val:
            filt.append({"term": {field: val}})
    rng = {}
    since = resolve_since(f.since)
    if since:
        rng["gte"] = since
    if f.until:
        if not TS_RE.match(f.until):
            raise ValueError("until must be an ISO timestamp")
        rng["lte"] = f.until
    if rng:
        filt.append({"range": {"ts": rng}})
    if f.q:
        ql = f.q.lower()
        # Escape wildcard specials so q is a literal substring.
        esc = ql.replace("\\", "\\\\").replace("*", "\\*").replace("?", "\\?")
        must.append({"bool": {"minimum_should_match": 1,
                     "should": [{"wildcard": {field: {"value": f"*{esc}*"}}} for field in SEARCH_FIELDS]}})
    query = {"bool": {}}
    if must:
        query["bool"]["must"] = must
    if filt:
        query["bool"]["filter"] = filt
    return query or {"match_all": {}}


def search(query: dict, size: int = 100, sort=None, search_after=None,
           source=True, aggs=None, track_total=False) -> dict:
    body = {"query": query, "size": size}
    if sort:
        body["sort"] = sort
    if search_after:
        body["search_after"] = search_after
    if source is not True:
        body["_source"] = source
    if aggs:
        body["aggs"] = aggs
    if track_total:
        body["track_total_hits"] = True
    return _req("POST", f"/{INDEX_PATTERN}/_search", body)


def terms_agg(field: str, size: int = 10, order_field: str | None = None) -> dict:
    agg: dict = {"terms": {"field": field, "size": size}}
    if order_field:
        agg["terms"]["order"] = {order_field: "desc"}
    return agg


def refresh() -> None:
    """Make recently indexed docs searchable now (tests; production relies on the 1s refresh)."""
    try:
        _req("POST", f"/{INDEX_PATTERN}/_refresh", timeout=10)
    except StoreError:
        pass


def delete_by_client(client: str) -> None:
    try:
        _req("POST", f"/{INDEX_PATTERN}/_delete_by_query?conflicts=proceed&refresh=true",
             {"query": {"term": {"client": client}}}, timeout=30)
    except StoreError:
        pass
