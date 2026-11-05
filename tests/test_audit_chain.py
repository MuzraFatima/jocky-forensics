"""Hash-chained, tamper-evident audit trail."""

import json

from fastapi.testclient import TestClient

from backend.app.security.audit import GENESIS_HASH, AuditLogger, verify_chain, verify_log_file


def _logger(n=5, **kwargs):
    log = AuditLogger(**kwargs)
    for i in range(n):
        log.record("LOGIN", user=f"user{i}", details={"i": i})
    return log


def _chain(log):
    return list(reversed(log.get_events(limit=10_000)))


def test_entries_link_to_each_other():
    entries = _chain(_logger())
    assert entries[0]["prev_hash"] == GENESIS_HASH
    for prev, cur in zip(entries, entries[1:], strict=False):
        assert cur["prev_hash"] == prev["entry_hash"]
        assert cur["seq"] == prev["seq"] + 1
    assert verify_chain(entries)["valid"] is True


def test_editing_an_entry_is_detected():
    entries = _chain(_logger())
    entries[2]["user"] = "someone_else"
    result = verify_chain(entries)
    assert result["valid"] is False
    assert result["first_bad_seq"] == 3
    assert "modified" in result["reason"]


def test_deleting_an_entry_is_detected():
    entries = _chain(_logger())
    del entries[1]
    result = verify_chain(entries)
    assert result["valid"] is False
    assert "removed or reordered" in result["reason"]


def test_recomputing_one_hash_still_breaks_the_next_link():
    entries = _chain(_logger())
    from backend.app.security.audit import _entry_digest

    entries[1]["action"] = "LOGOUT"
    entries[1]["entry_hash"] = _entry_digest(entries[1])
    result = verify_chain(entries)
    assert result["valid"] is False
    assert result["first_bad_seq"] == 3


def test_rolling_buffer_keeps_a_verifiable_anchor():
    log = _logger(n=8, max_entries=3)
    assert len(log.get_events(limit=100)) == 3
    assert log.verify()["valid"] is True


def test_secrets_are_redacted_before_hashing():
    log = AuditLogger()
    entry = log.record("LOGIN", details={"password": "hunter2", "api_key": "x"})
    assert entry["details"] == {"password": "[REDACTED]", "api_key": "[REDACTED]"}
    assert "hunter2" not in json.dumps(entry)


def test_persisted_log_keeps_full_chain_and_resumes(tmp_path):
    path = tmp_path / "audit.jsonl"
    first = _logger(n=3, persist_path=path, max_entries=2)
    assert verify_log_file(path)["checked"] == 3

    resumed = AuditLogger(persist_path=path)
    resumed.record("LOGOUT", user="user0")
    assert verify_log_file(path) == {"valid": True, "checked": 4, "first_bad_seq": None, "reason": "chain intact"}
    assert resumed.verify()["valid"] is True
    assert first.verify()["persisted"]["valid"] is True

    lines = path.read_text(encoding="utf-8").splitlines()
    tampered = json.loads(lines[1])
    tampered["result"] = "FAILURE"
    lines[1] = json.dumps(tampered)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    assert verify_log_file(path)["first_bad_seq"] == 2


def test_verify_endpoint_reports_an_intact_chain():
    from backend.app.main import app

    client = TestClient(app)
    client.post("/api/auth/login", json={"username": "nobody@example.com", "password": "wrong"})
    body = client.get("/api/security/audit/verify").json()
    assert body["success"] is True
    assert body["valid"] is True
    assert len(body["head_hash"]) == 64
