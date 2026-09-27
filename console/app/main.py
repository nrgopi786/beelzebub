import csv
import hashlib
import io
import ipaddress
import json
import logging
import sys
from contextlib import asynccontextmanager

from fastapi import Body, Depends, FastAPI, HTTPException, Query, Request, Response
from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles

from . import analytics, auth, config, db, ingest, manager
from .analytics import Filters

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
log = logging.getLogger("console")

STATIC = __import__("pathlib").Path(__file__).parent / "static"
throttle = auth.LoginThrottle()


@asynccontextmanager
async def lifespan(_app):
    if len(config.SECRET_KEY) < 32 or not config.ADMIN_PASSWORD_HASH:
        log.critical("CONSOLE_SECRET_KEY (>=32 chars) and CONSOLE_ADMIN_PASSWORD_HASH must be set; "
                     "run ./console.sh init")
        sys.exit(1)
    db.init()
    stop = ingest.start()
    yield
    stop.set()


app = FastAPI(title="Xpods Console", lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)

CSP = ("default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
       "connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")


@app.middleware("http")
async def security(request: Request, call_next):
    path = request.url.path
    if path.startswith("/api/") and path != "/api/login":
        user = auth.read_token(request.cookies.get(auth.COOKIE))
        if not user:
            return JSONResponse({"detail": "authentication required"}, status_code=401)
        # CSRF: SameSite=Strict cookie + a header a cross-site form cannot set.
        if request.method not in ("GET", "HEAD") and request.headers.get("x-requested-with") != "console":
            return JSONResponse({"detail": "missing CSRF header"}, status_code=403)
        request.state.user = user
    response = await call_next(request)
    response.headers["Content-Security-Policy"] = CSP
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    if path.startswith("/api/"):
        response.headers["Cache-Control"] = "no-store"
    elif path.startswith("/static/"):
        response.headers["Cache-Control"] = "no-cache"
    return response


def current_user(request: Request) -> str:
    return request.state.user


def filters(client: str | None = None, protocol: str | None = None, ip: str | None = None,
            session: str | None = None, status: str | None = None, q: str | None = None,
            since: str | None = "24h", until: str | None = None) -> Filters:
    f = Filters(client or None, protocol or None, ip or None, session or None, status or None,
                (q or "").strip()[:200] or None, since, until or None)
    try:
        f.where()
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from None
    return f


def valid_ip(ip: str) -> str:
    try:
        return str(ipaddress.ip_address(ip))
    except ValueError:
        raise HTTPException(400, "invalid IP address") from None


# --------------------------------------------------------------------------- auth

@app.post("/api/login")
def login(request: Request, response: Response, body: dict = Body(...)):
    key = request.client.host if request.client else "unknown"
    wait = throttle.retry_after(key)
    if wait:
        raise HTTPException(429, f"too many failed attempts, retry in {wait}s")
    if not auth.check_login(str(body.get("username", "")), str(body.get("password", ""))):
        throttle.failure(key)
        log.warning("failed console login from %s", key)
        raise HTTPException(401, "invalid username or password")
    throttle.success(key)
    response.set_cookie(auth.COOKIE, auth.issue_token(config.ADMIN_USER), httponly=True,
                        samesite="strict", secure=config.COOKIE_SECURE,
                        max_age=config.SESSION_HOURS * 3600, path="/")
    with db.session() as conn:
        db.audit(conn, config.ADMIN_USER, "login", key)
    return {"user": config.ADMIN_USER}


@app.post("/api/logout")
def logout(response: Response):
    response.delete_cookie(auth.COOKIE, path="/")
    return {"ok": True}


@app.get("/api/me")
def me(user: str = Depends(current_user)):
    return {"user": user}


# --------------------------------------------------------------------------- analysis

@app.get("/api/stats")
def get_stats(f: Filters = Depends(filters)):
    with db.session() as conn:
        return analytics.stats(conn, f)


@app.get("/api/events")
def get_events(f: Filters = Depends(filters), limit: int = Query(100, ge=1, le=500),
               before: int | None = None):
    with db.session() as conn:
        return analytics.events(conn, f, limit, before)


@app.get("/api/events/{event_id}")
def get_event(event_id: int):
    with db.session() as conn:
        ev = analytics.event(conn, event_id)
    if not ev:
        raise HTTPException(404, "event not found")
    return ev


@app.get("/api/sessions")
def get_sessions(f: Filters = Depends(filters), limit: int = Query(100, ge=1, le=500),
                 offset: int = Query(0, ge=0)):
    with db.session() as conn:
        return analytics.sessions(conn, f, limit, offset)


@app.get("/api/sessions/{session_id}")
def get_session(session_id: str):
    with db.session() as conn:
        rows = analytics.session_detail(conn, session_id[:64])
    if not rows:
        raise HTTPException(404, "session not found")
    return rows


@app.get("/api/attackers")
def get_attackers(f: Filters = Depends(filters), limit: int = Query(200, ge=1, le=1000)):
    with db.session() as conn:
        return analytics.attackers(conn, f, limit)


@app.get("/api/ips/{ip}")
def get_ip(ip: str):
    with db.session() as conn:
        return analytics.ip_profile(conn, valid_ip(ip))


@app.put("/api/ips/{ip}/note")
def put_ip_note(ip: str, body: dict = Body(...), user: str = Depends(current_user)):
    ip = valid_ip(ip)
    tags = " ".join(str(body.get("tags", "")).replace(",", " ").split())[:500]
    note = str(body.get("note", ""))[:20000]
    with db.session() as conn:
        analytics.save_note(conn, ip, tags, note, user)
        db.audit(conn, user, "ip.note", ip, tags)
    return {"ok": True}


EXPORT_COLS = ["id", "ts", "client", "protocol", "status", "msg", "session", "src_ip", "src_port",
               "user", "password", "command", "method", "uri", "user_agent", "host", "description"]


def _csv_safe(value) -> str:
    s = "" if value is None else str(value)
    # Neutralise spreadsheet formula injection from attacker-controlled fields.
    return "'" + s if s[:1] in ("=", "+", "-", "@", "\t", "\r") else s


@app.get("/api/export")
def export(f: Filters = Depends(filters), format: str = Query("csv", pattern="^(csv|json|ioc)$"),
           user: str = Depends(current_user)):
    where, args = f.where()
    with db.session() as conn:
        db.audit(conn, user, "export", format, json.dumps(f.__dict__))

    def stream():
        conn = db.connect()
        try:
            if format == "ioc":
                cond = "src_ip != ''"
                w = f"{where} AND {cond}" if where else f" WHERE {cond}"
                yield "# Xpod source IPs\n"
                for row in conn.execute(f"SELECT DISTINCT src_ip FROM events{w} ORDER BY src_ip", args):
                    yield row[0] + "\n"
                return
            cur = conn.execute(f"SELECT {', '.join(EXPORT_COLS)} FROM events{where} ORDER BY id", args)
            if format == "json":
                for row in cur:
                    yield json.dumps(dict(row), ensure_ascii=False) + "\n"
                return
            buf = io.StringIO()
            writer = csv.writer(buf)
            writer.writerow(EXPORT_COLS)
            for row in cur:
                writer.writerow([_csv_safe(v) for v in row])
                if buf.tell() > 65536:
                    yield buf.getvalue()
                    buf.seek(0)
                    buf.truncate()
            yield buf.getvalue()
        finally:
            conn.close()

    media = {"csv": "text/csv", "json": "application/x-ndjson", "ioc": "text/plain"}[format]
    ext = {"csv": "csv", "json": "ndjson", "ioc": "txt"}[format]
    return StreamingResponse(stream(), media_type=media,
                             headers={"Content-Disposition": f'attachment; filename="xpod-events.{ext}"'})


# --------------------------------------------------------------------------- management

def _client_errors(fn, *args):
    try:
        return fn(*args)
    except manager.ValidationError as exc:
        raise HTTPException(400, str(exc)) from None
    except KeyError:
        raise HTTPException(404, "unknown client") from None


@app.get("/api/clients")
def get_clients():
    clients = manager.list_clients()
    with db.session() as conn:
        counts = analytics.client_counts(conn)
    for c in clients:
        c["stats"] = counts.get(c["name"], {"events": 0, "last": None, "last24h": 0})
    return clients


@app.post("/api/clients")
def post_client(body: dict = Body(...), user: str = Depends(current_user)):
    name = str(body.get("name", "")).strip()
    out = _client_errors(manager.create_client, name, str(body.get("domain", "")).strip(),
                         str(body.get("hostname", "")).strip() or "srv01")
    with db.session() as conn:
        db.audit(conn, user, "client.create", name, str(body.get("domain", "")))
    return {"ok": True, "output": out}


@app.get("/api/clients/{client}")
def get_client(client: str):
    env = _client_errors(manager.read_env, client)
    return {"name": client, "env": env, "editable": sorted(manager.EDITABLE),
            "secrets": sorted(manager.SECRET_KEYS), "services": manager.available_services(),
            "custom": manager.list_custom(client),
            "containers": manager.container_status().get(client, []),
            "job": manager.jobs.running_for(client)}


@app.put("/api/clients/{client}/settings")
def put_settings(client: str, body: dict = Body(...), user: str = Depends(current_user)):
    changed = _client_errors(manager.update_env, client, body)
    if changed:
        with db.session() as conn:
            db.audit(conn, user, "client.settings", client, ", ".join(changed))
    return {"changed": changed}


@app.post("/api/clients/{client}/actions/{action}")
def post_action(client: str, action: str, user: str = Depends(current_user)):
    try:
        job = manager.jobs.start(client, action, user)
    except manager.ValidationError as exc:
        raise HTTPException(400, str(exc)) from None
    except KeyError:
        raise HTTPException(404, "unknown client") from None
    except RuntimeError as exc:
        raise HTTPException(409, str(exc)) from None
    with db.session() as conn:
        db.audit(conn, user, f"client.{action}", client, job.id)
    return job.to_dict()


@app.get("/api/clients/{client}/firewall")
def get_firewall(client: str):
    _client_errors(manager.read_env, client)
    rc, out = manager.run_sync(["firewall", client], timeout=30)
    return {"ok": rc == 0, "output": out}


@app.get("/api/clients/{client}/custom/{name}")
def get_custom(client: str, name: str):
    return {"name": name, "content": _client_errors(manager.read_custom, client, name)}


@app.put("/api/clients/{client}/custom/{name}")
def put_custom(client: str, name: str, body: dict = Body(...), user: str = Depends(current_user)):
    _client_errors(manager.write_custom, client, name, str(body.get("content", "")))
    with db.session() as conn:
        db.audit(conn, user, "custom.write", f"{client}/{name}")
    return {"ok": True}


@app.delete("/api/clients/{client}/custom/{name}")
def delete_custom(client: str, name: str, user: str = Depends(current_user)):
    _client_errors(manager.delete_custom, client, name)
    with db.session() as conn:
        db.audit(conn, user, "custom.delete", f"{client}/{name}")
    return {"ok": True}


@app.get("/api/jobs")
def get_jobs():
    return manager.jobs.recent()


@app.get("/api/jobs/{job_id}")
def get_job(job_id: str):
    job = manager.jobs.get(job_id)
    if not job:
        raise HTTPException(404, "job not found")
    return job.to_dict()


@app.get("/api/audit")
def get_audit(limit: int = Query(200, ge=1, le=1000)):
    with db.session() as conn:
        return [dict(r) for r in conn.execute("SELECT * FROM audit ORDER BY id DESC LIMIT ?", (limit,))]


# --------------------------------------------------------------------------- frontend

app.mount("/static", StaticFiles(directory=STATIC), name="static")


def _asset_version() -> str:
    h = hashlib.sha256()
    for name in ("app.js", "style.css"):
        h.update((STATIC / name).read_bytes())
    return h.hexdigest()[:12]


# Asset URLs carry a content hash so a redeploy never runs against a stale cached script.
INDEX_HTML = (STATIC / "index.html").read_text().replace("__V__", _asset_version())


@app.get("/")
def index():
    return HTMLResponse(INDEX_HTML, headers={"Cache-Control": "no-cache"})
