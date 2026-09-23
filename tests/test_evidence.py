"""
Unit tests for JOCKY Evidence Store, SHA-256 Integrity, and Chain of Custody.
"""

import json
from pathlib import Path
import pytest

from backend.app.evidence import (
    CustodyRecord,
    EvidenceStore,
    compute_sha256,
    verify_sha256,
)


def test_sha256_consistency():
    """1. Verify SHA-256 computation is deterministic and key-order independent."""
    payload_a = {"alpha": 1, "beta": "forensics", "nested": {"x": [1, 2, 3]}}
    payload_b = {"nested": {"x": [1, 2, 3]}, "beta": "forensics", "alpha": 1}

    hash_a1 = compute_sha256(payload_a)
    hash_a2 = compute_sha256(payload_a)
    hash_b = compute_sha256(payload_b)

    # Identical data yields identical hash
    assert hash_a1 == hash_a2
    # Dict key order variations yield identical hash (canonical JSON)
    assert hash_a1 == hash_b
    assert len(hash_a1) == 64  # Standard SHA-256 hex length

    # Different data yields distinct hash
    different_payload = {"alpha": 2, "beta": "forensics"}
    assert compute_sha256(different_payload) != hash_a1


def test_evidence_creation(tmp_path: Path):
    """2. Verify evidence record creation and persistence in local JSON store."""
    store = EvidenceStore(base_dir=str(tmp_path))

    sample_data = {
        "collector": "system",
        "hostname": "TARGET-PC",
        "os": "Windows",
    }

    record = store.save_evidence(
        case_id="LAB-2026-001",
        source="system",
        data=sample_data,
        who="Special Agent Fox",
        why="Investigative triage",
    )

    # Verify required top-level attributes
    assert "evidence_id" in record
    assert record["evidence_id"].startswith("EVID-LAB-2026-001-system-")
    assert record["case_id"] == "LAB-2026-001"
    assert record["source"] == "system"
    assert "timestamp_utc" in record
    assert "sha256" in record
    assert record["data"] == sample_data
    assert len(record["custody_log"]) == 1

    # Verify disk retrieval
    retrieved = store.get_evidence(record["evidence_id"])
    assert retrieved is not None
    assert retrieved["evidence_id"] == record["evidence_id"]
    assert retrieved["sha256"] == record["sha256"]


def test_hash_verification(tmp_path: Path):
    """3. Verify evidence integrity verification succeeds when data is unmodified."""
    store = EvidenceStore(base_dir=str(tmp_path))

    data = {"processes": [{"pid": 1, "name": "init"}], "count": 1}
    record = store.save_evidence(case_id="LAB-002", source="processes", data=data)

    verification = store.verify_evidence(
        record["evidence_id"],
        who="Integrity Officer",
        why="Routine verification audit",
    )

    assert verification["valid"] is True
    assert verification["stored_hash"] == verification["recomputed_hash"]
    assert verification["custody_entry"]["action"] == "VERIFIED"
    assert verification["custody_entry"]["integrity_valid"] is True

    # Check updated custody log has 2 entries (ACQUIRED, VERIFIED)
    updated = store.get_evidence(record["evidence_id"])
    assert len(updated["custody_log"]) == 2
    assert updated["custody_log"][1]["action"] == "VERIFIED"


def test_tamper_detection(tmp_path: Path):
    """4. Verify that any modification of stored data causes integrity check to fail."""
    store = EvidenceStore(base_dir=str(tmp_path))

    original_data = {"connections": [{"local_port": 8000, "status": "LISTEN"}]}
    record = store.save_evidence(case_id="LAB-003", source="network", data=original_data)
    evidence_id = record["evidence_id"]

    # Directly tamper with the stored JSON file on disk
    json_path = store._get_evidence_path(evidence_id, case_id="LAB-003")
    with open(json_path, "r", encoding="utf-8") as f:
        stored_json = json.load(f)

    # Tampering: attacker changes port 8000 to port 4444 (unauthorized backdoor)
    stored_json["data"]["connections"][0]["local_port"] = 4444
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(stored_json, f, indent=2)

    # Run integrity verification on tampered record
    verification = store.verify_evidence(evidence_id)

    assert verification["valid"] is False
    assert verification["stored_hash"] != verification["recomputed_hash"]
    assert verification["custody_entry"]["integrity_valid"] is False

    # Also verify direct helper function
    assert verify_sha256(stored_json["data"], record["sha256"]) is False


def test_custody_record_fields():
    """5. Verify all chain-of-custody fields (who, what, when, why, action, sha256)."""
    custody = CustodyRecord.create(
        who="Investigator Jane",
        what="Active TCP Connections Dump",
        why="Court Order #41029",
        action="ACQUIRED",
        sha256="abc1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
    )

    record_dict = custody.to_dict()

    assert record_dict["who"] == "Investigator Jane"
    assert record_dict["what"] == "Active TCP Connections Dump"
    assert record_dict["why"] == "Court Order #41029"
    assert record_dict["action"] == "ACQUIRED"
    assert "when" in record_dict
    assert record_dict["sha256"] == "abc1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"


def test_evidence_json_serialization(tmp_path: Path):
    """6. Verify evidence records are fully JSON serializable."""
    store = EvidenceStore(base_dir=str(tmp_path))

    data = {
        "hardware": {"cpu": "AMD64", "ram_gb": 16},
        "flags": [True, False, None],
    }

    record = store.save_evidence(case_id="LAB-004", source="system", data=data)

    serialized = json.dumps(record)
    assert isinstance(serialized, str)

    deserialized = json.loads(serialized)
    assert deserialized["evidence_id"] == record["evidence_id"]
    assert deserialized["data"]["hardware"]["cpu"] == "AMD64"
    assert len(deserialized["custody_log"]) == 1


def test_evidence_list(tmp_path: Path):
    """Verify evidence store can list artifacts filtered by case ID."""
    store = EvidenceStore(base_dir=str(tmp_path))

    store.save_evidence("CASE-A", "system", {"k": 1})
    store.save_evidence("CASE-A", "network", {"k": 2})
    store.save_evidence("CASE-B", "processes", {"k": 3})

    all_evidence = store.list_evidence()
    assert len(all_evidence) == 3

    case_a_evidence = store.list_evidence(case_id="CASE-A")
    assert len(case_a_evidence) == 2
    for item in case_a_evidence:
        assert item["case_id"] == "CASE-A"
