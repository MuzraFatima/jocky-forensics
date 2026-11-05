"""Collector result envelope (§6.2) and normalized process schema (§5.3)."""

from backend.app.collectors.contract import (
    PROCESS_SCHEMA_FIELDS,
    make_result,
    normalize_process,
    normalize_process_list,
    unsupported,
)

ENVELOPE_KEYS = {
    "collector",
    "collector_version",
    "read_only",
    "platform",
    "endpoint",
    "collected_at",
    "collection_status",
    "count",
    "items",
    "errors",
    "provenance",
}


def test_envelope_has_every_contract_field():
    result = make_result("services", [{"name": "a"}], method="unit", platform_name="Linux")
    assert set(result) >= ENVELOPE_KEYS
    assert result["read_only"] is True
    assert result["count"] == 1
    assert result["collection_status"] == "collected"
    assert result["provenance"]["collector"] == "services"


def test_status_is_derived_from_items_and_errors():
    assert make_result("x", [], method="m", platform_name="Linux", errors=["boom"])["collection_status"] == "error"
    partial = make_result("x", [{"a": 1}], method="m", platform_name="Linux", errors=["/etc/x: denied"])
    assert partial["collection_status"] == "partial"
    assert make_result("x", [], method="m", platform_name="Linux")["collection_status"] == "collected"


def test_unsupported_result_carries_a_reason():
    result = unsupported("drivers", "Darwin", "kext inventory needs kextstat")
    assert result["collection_status"] == "unsupported"
    assert result["reason"] == "kext inventory needs kextstat"
    assert result["items"] == []


def test_full_process_record_normalizes_as_collected():
    raw = {
        "pid": 42,
        "ppid": 1,
        "name": "sshd",
        "exe": "/usr/sbin/sshd",
        "username": "root",
        "create_time": "2026-11-05T00:00:00+00:00",
        "cmdline": ["/usr/sbin/sshd", "-D"],
    }
    norm = normalize_process(raw, "Linux")
    assert tuple(norm) == PROCESS_SCHEMA_FIELDS
    assert norm["command_line"] == "/usr/sbin/sshd -D"
    assert norm["source_platform"] == "Linux"
    assert norm["collection_status"] == "collected"


def test_access_denied_details_are_reported():
    norm = normalize_process({"pid": 4, "ppid": 0, "name": "System"}, "Windows")
    assert norm["collection_status"] == "denied"
    partial = normalize_process({"pid": 5, "name": "x", "exe": "C:/x.exe"}, "Windows")
    assert partial["collection_status"] == "partial"
    assert normalize_process({"name": "ghost"}, "Linux")["collection_status"] == "error"


def test_unknown_name_becomes_none_and_lists_map():
    out = normalize_process_list([{"pid": 1, "name": "unknown"}], "Linux")
    assert out[0]["process_name"] is None


def test_collect_api_returns_normalized_processes():
    from fastapi.testclient import TestClient

    from backend.app.main import app

    body = TestClient(app).get("/api/forensics/collect/processes?normalized=true").json()
    artifact = body["artifact"]
    assert artifact["schema"] == "jocky.process.v1"
    assert artifact["processes"], "expected at least the test process itself"
    for proc in artifact["processes"]:
        assert tuple(proc) == PROCESS_SCHEMA_FIELDS
