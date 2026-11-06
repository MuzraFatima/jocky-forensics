"""Response compression, short-lived live snapshots, cache headers and pagination."""

import threading
import time

from fastapi.testclient import TestClient

from backend.app.collectors import snapshot
from backend.app.evidence import _default_vault
from backend.app.main import app

client = TestClient(app)


def test_large_responses_are_gzip_compressed():
    resp = client.get("/api/forensics/techniques", headers={"Accept-Encoding": "gzip"})
    assert resp.status_code == 200
    assert resp.headers.get("content-encoding") == "gzip"


def test_static_data_is_cacheable_but_live_data_is_not():
    assert client.get("/api/forensics/detections/rules").headers["cache-control"] == "private, max-age=300"
    assert "cache-control" not in client.get("/api/forensics/vault/list").headers


def test_snapshot_shares_one_collection_between_concurrent_callers():
    snapshot.clear()
    calls = []

    def slow_collect():
        calls.append(1)
        time.sleep(0.2)
        return {"n": len(calls)}

    results = []
    threads = [threading.Thread(target=lambda: results.append(snapshot.cached("perf-test", slow_collect, ttl=5)))
               for _ in range(5)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert len(calls) == 1
    assert all(r == {"n": 1} for r in results)


def test_snapshot_expires_and_can_be_switched_off():
    snapshot.clear()
    counter = iter(range(100))
    first = snapshot.cached("perf-ttl", lambda: next(counter), ttl=0.05)
    time.sleep(0.1)
    assert snapshot.cached("perf-ttl", lambda: next(counter), ttl=0.05) == first + 1
    a = snapshot.cached("perf-off", lambda: next(counter), ttl=0)
    b = snapshot.cached("perf-off", lambda: next(counter), ttl=0)
    assert a != b


def test_vault_list_pages_newest_first():
    for i in range(3):
        _default_vault.seal_artifact("CASE-PAGING", "system", {"i": i})
    full = client.get("/api/forensics/vault/list?case_id=CASE-PAGING").json()
    page = client.get("/api/forensics/vault/list?case_id=CASE-PAGING&limit=2&offset=1").json()
    assert page["total_artifacts"] == full["total_artifacts"] >= 3
    assert len(page["artifacts"]) == 2
    assert page["artifacts"] == full["artifacts"][1:3]
    stamps = [a["timestamp_utc"] for a in full["artifacts"]]
    assert stamps == sorted(stamps, reverse=True)
