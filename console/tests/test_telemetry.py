import pytest

from app import store, telemetry
from tests.test_core import repo  # noqa: F401  (fixture: db init + store ready)


def test_url_cleaning():
    assert telemetry._clean_url("https://user:pass@host.test/p?q=1#frag") == "https://host.test/p?q=1"
    assert telemetry._clean_url("http://a.test:8080/x") == "http://a.test:8080/x"
    assert telemetry._clean_url("ftp://a.test/x") is None
    assert telemetry._clean_url("javascript:alert(1)") is None
    assert telemetry._clean_url("chrome://settings") is None
    assert telemetry._clean_url("x" * 5000) is None


def test_label_validation(repo):  # noqa: F811
    with pytest.raises(ValueError):
        telemetry.create_enrollment("bad/label!", "admin")
    with pytest.raises(ValueError):
        telemetry.create_enrollment("", "admin")


def test_enroll_ingest_and_scope(repo):  # noqa: F811
    enr = telemetry.create_enrollment("QA Laptop", "admin")
    label = enr["label"]
    try:
        assert enr["token"].startswith("xpt_")
        assert telemetry._verify(enr["token"])["label"] == label
        assert telemetry._verify("xpt_bogus") is None

        payload = {"device": "chrome-1", "events": [
            {"url": "https://a.test/one", "title": "One", "ts": 1790000000000},
            {"url": "https://user:secret@b.test/two", "title": "Two", "ts": "2026-09-27T10:00:00Z"},
            {"url": "ftp://drop.test/x"},                     # dropped: scheme
            {"note": "not a url"},                            # dropped: no url
            {"keystrokes": "hunter2"},                        # ignored: unknown field, no url
        ]}
        res = telemetry.ingest(enr["token"], payload, "203.0.113.5")
        assert res["ok"] and res["accepted"] == 2

        # bad token is rejected, nothing stored
        assert telemetry.ingest("xpt_wrong", payload, "203.0.113.5")["code"] == 401

        store.refresh()
        hits = store.search({"term": {"client": label}}, size=10)["hits"]["hits"]
        srcs = [h["_source"] for h in hits]
        assert len(srcs) == 2
        assert all(s["source"] == "browser" and s["protocol"] == "WEB" for s in srcs)
        urls = sorted(s["url"] for s in srcs)
        assert urls == ["https://a.test/one", "https://b.test/two"]  # creds stripped
        # the endpoint never stores anything resembling captured input
        assert all("keystrokes" not in s and "hunter2" not in str(s) for s in srcs)
    finally:
        store.delete_by_client(label)


def test_revoke_blocks_ingest(repo):  # noqa: F811
    enr = telemetry.create_enrollment("Temp Device", "admin")
    telemetry.revoke_enrollment(enr["id"], "admin")
    assert telemetry.ingest(enr["token"], {"device": "d", "events": []}, "203.0.113.9")["code"] == 401
