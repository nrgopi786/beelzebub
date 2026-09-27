import json
import os
import sqlite3
import time

import pytest

os.environ.setdefault("CONSOLE_SECRET_KEY", "x" * 48)

from app import analytics, auth, config, db, ingest, manager, store  # noqa: E402
from app.main import _csv_safe  # noqa: E402


def event_line(i, **kw):
    ev = {"DateTime": f"2026-09-27T09:00:{i:02d}.123456789Z", "Protocol": "SSH", "Status": "Interaction",
          "Msg": "SSH Terminal Session Interaction", "ID": "s1", "Command": f"cmd{i}",
          "SourceIp": "203.0.113.9", "SourcePort": "4000", **kw}
    return json.dumps({"event": ev, "level": "info", "msg": "New Event"}) + "\n"


@pytest.fixture
def repo(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "CLIENTS_DIR", tmp_path / "clients")
    monkeypatch.setattr(config, "SERVICES_DIR", tmp_path / "services")
    monkeypatch.setattr(config, "DB_PATH", tmp_path / "console.db")
    (tmp_path / "services").mkdir()
    for s in ("ssh-22", "http-80"):
        (tmp_path / "services" / f"{s}.yaml").write_text("x")
    logs = tmp_path / "clients" / "acme" / "data" / "logs"
    logs.mkdir(parents=True)
    (tmp_path / "clients" / "acme" / ".env").write_text(
        '# comment\nHP_CLIENT=acme\nHP_HOSTNAME=web01\nHP_SERVICES="ssh-22"\nHP_SHIP_AUTH_HEADER="Bearer s3cret"\n')
    db.init()
    store.ensure_ready()
    store.delete_by_client("acme")
    yield logs
    store.delete_by_client("acme")


def store_count(client="acme"):
    store.refresh()
    return store.search({"term": {"client": client}}, size=0, track_total=True)["hits"]["total"]["value"]


# ------------------------------------------------------------------ ingest

def test_parse_line_event_and_noise():
    doc = ingest.parse_line("acme", event_line(1).encode())
    assert doc["ts"] == "2026-09-27T09:00:01.123456Z"
    assert doc["command"] == "cmd1" and doc["src_ip"] == "203.0.113.9"
    assert doc["source"] == "xpod" and doc["client"] == "acme" and doc["_id"]
    assert ingest.parse_line("acme", b'{"level":"info","msg":"Init service"}') is None
    assert ingest.parse_line("acme", b"not json") is None
    assert ingest.parse_line("acme", b"{" + b"a" * (ingest.MAX_LINE + 1)) is None


def test_parse_line_remote_addr_fallback():
    doc = ingest.parse_line("acme", event_line(1, SourceIp="", RemoteAddr="[2001:db8::1]:5555").encode())
    assert doc["src_ip"] == "2001:db8::1"


def test_tail_partial_lines_and_rotation(repo):
    live = repo / "beelzebub.log"
    live.write_text(event_line(1) + event_line(2) + event_line(3)[:40])
    with db.session() as conn:
        ingest.scan_once(conn)
        assert store_count() == 2  # partial third line waits

        with open(live, "a") as fh:
            fh.write(event_line(3)[40:])
        ingest.scan_once(conn)
        assert store_count() == 3

        # Rotation: copy to archive, truncate, then new events longer than before.
        import gzip
        with gzip.open(repo / "beelzebub-20260927T090000Z.log.gz", "wt") as gz:
            gz.write(live.read_text() + event_line(4))  # event 4 only reached the archive
        live.write_text("".join(event_line(i) for i in range(5, 12)))
        ingest.scan_once(conn)
        assert store_count() == 11  # 1-3 deduped, 4 from archive, 5-11 from live file

        ingest.scan_once(conn)
        assert store_count() == 11


# ------------------------------------------------------------------ env editing

def test_update_env_validates_and_preserves(repo):
    changed = manager.update_env("acme", {"HP_HOSTNAME": "erp-prod", "HP_SERVICES": "ssh-22  http-80"})
    assert changed == ["HP_HOSTNAME", "HP_SERVICES"]
    text = (config.CLIENTS_DIR / "acme" / ".env").read_text()
    assert text.startswith("# comment\n")
    assert 'HP_HOSTNAME="erp-prod"' in text and 'HP_SERVICES="ssh-22 http-80"' in text

    for bad in ({"HP_HOSTNAME": "x;reboot"}, {"HP_SHIP_URL": "http://a/$(id)"},
                {"HP_SERVICES": "ssh-22 nope"}, {"HP_CLIENT": "other"}, {"HP_BIND_IP": "1.2.3"}):
        with pytest.raises(manager.ValidationError):
            manager.update_env("acme", bad)


def test_secrets_masked_and_mask_not_written(repo):
    assert manager.read_env("acme")["HP_SHIP_AUTH_HEADER"] == manager.MASK
    assert manager.update_env("acme", {"HP_SHIP_AUTH_HEADER": manager.MASK}) == []
    assert manager.read_env("acme", mask=False)["HP_SHIP_AUTH_HEADER"] == "Bearer s3cret"


def test_client_and_custom_names_are_confined(repo):
    with pytest.raises(manager.ValidationError):
        manager.read_env("../acme")
    with pytest.raises(manager.ValidationError):
        manager.write_custom("acme", "../../.env", "x")
    manager.write_custom("acme", "vpn-8443.yaml", "apiVersion: v1")
    assert manager.list_custom("acme")[0]["name"] == "vpn-8443.yaml"


# ------------------------------------------------------------------ auth / export / filters

def test_password_and_token():
    h = auth.hash_password("correct horse")
    assert "$" not in h and auth.verify_password("correct horse", h)
    assert not auth.verify_password("wrong", h)
    tok = auth.issue_token("admin")
    assert auth.read_token(tok) == "admin"
    payload, sig = tok.rsplit(".", 1)
    assert auth.read_token(payload + "." + "0" * len(sig)) is None
    assert auth.read_token("garbage") is None


def test_throttle_locks_out():
    t = auth.LoginThrottle(free_attempts=2)
    t.failure("ip"); assert t.retry_after("ip") == 0
    t.failure("ip"); assert t.retry_after("ip") > 0
    t.success("ip"); assert t.retry_after("ip") == 0


def test_csv_formula_injection():
    assert _csv_safe("=cmd|' /C calc'!A0") == "'=cmd|' /C calc'!A0"
    assert _csv_safe("@SUM(1)") == "'@SUM(1)"
    assert _csv_safe("root") == "root" and _csv_safe(None) == ""


def test_search_escapes_like_wildcards(repo):
    live = repo / "beelzebub.log"
    live.write_text(event_line(1, Command="100%_done") + event_line(2, Command="100xydone"))
    with db.session() as conn:
        ingest.scan_once(conn)
        store.refresh()
        rows = analytics.events(conn, analytics.Filters(q="100%_", since="all", client="acme"))["events"]
    assert [r["command"] for r in rows] == ["100%_done"]
