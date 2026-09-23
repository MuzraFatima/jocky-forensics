"""
Tests for Phase 6: JOCKY Forensic Evidence Vault & Tamper-Evident Chain of Custody.

Validates:
1. Cryptographic SHA-256 artifact sealing with execution metadata.
2. Chain-of-custody tracking across acquisition, verification, and access.
3. Mathematical tamper detection (direct disk mutation detected immediately).
4. Full-vault cryptographic integrity audit (INTACT vs COMPROMISED).
5. Chronological audit ledger aggregation.
6. Cryptographically signed bundle export with manifest SHA-256.
7. REST API endpoints for Evidence Vault operations.
"""

import os
import shutil
import tempfile
import pytest
from pathlib import Path
from fastapi.testclient import TestClient

from backend.app.evidence.vault import EvidenceVault
from backend.app.evidence.hashing import compute_sha256, verify_sha256
from backend.app.main import app


@pytest.fixture
def temp_vault():
    """Provides an isolated temporary EvidenceVault instance for testing."""
    temp_dir = tempfile.mkdtemp(prefix="jocky_vault_test_")
    vault = EvidenceVault(base_dir=temp_dir)
    yield vault
    shutil.rmtree(temp_dir, ignore_errors=True)


client = TestClient(app)


# ---------------------------------------------------------------------------
# Unit Tests: EvidenceVault Core Engine
# ---------------------------------------------------------------------------

def test_seal_artifact_computes_sha256_and_custody(temp_vault):
    sample_data = {
        "hostname": "FORENSIC-WORKSTATION-01",
        "os": "Windows 11 Pro",
        "cpu_count": 8,
    }

    sealed = temp_vault.seal_artifact(
        case_id="CASE-VAULT-001",
        source="system",
        data=sample_data,
        who="Detective Vance",
        why="Initial triage acquisition",
        execution_id="EXEC-TEST-9988",
        collector_identity="JOCKY-WinCollector",
        collector_version="1.2.0",
        target_host="FORENSIC-WORKSTATION-01",
    )

    assert sealed["evidence_id"].startswith("EVID-CASE-VAULT-001-system-")
    assert sealed["case_id"] == "CASE-VAULT-001"
    assert sealed["source"] == "system"
    assert sealed["execution_id"] == "EXEC-TEST-9988"
    assert sealed["collector_identity"] == "JOCKY-WinCollector"
    assert sealed["collector_version"] == "1.2.0"
    assert sealed["target_host"] == "FORENSIC-WORKSTATION-01"

    # Verify SHA-256 hash matches compute_sha256
    expected_hash = compute_sha256(sample_data)
    assert sealed["sha256"] == expected_hash

    # Check custody log
    custody_log = sealed["custody_log"]
    assert len(custody_log) == 1
    assert custody_log[0]["action"] == "ACQUIRED"
    assert custody_log[0]["who"] == "Detective Vance"
    assert custody_log[0]["sha256"] == expected_hash
    assert custody_log[0]["integrity_valid"] is True


def test_verify_artifact_intact(temp_vault):
    data = {"processes": [{"pid": 101, "name": "explorer.exe"}]}
    sealed = temp_vault.seal_artifact(
        case_id="CASE-INTACT",
        source="processes",
        data=data,
        who="Investigator",
    )
    evidence_id = sealed["evidence_id"]

    # Verify integrity
    res = temp_vault.verify_artifact(evidence_id, who="Auditor")
    assert res["valid"] is True
    assert res["tampered"] is False
    assert res["stored_hash"] == res["recomputed_hash"]
    assert res["custody_entry"]["action"] == "VERIFIED"
    assert res["custody_entry"]["integrity_valid"] is True

    # Artifact should now have 2 custody records (ACQUIRED + VERIFIED)
    updated = temp_vault.get_artifact(evidence_id)
    assert len(updated["custody_log"]) == 2
    assert updated["custody_log"][1]["action"] == "VERIFIED"


def test_tamper_detection_flags_mutated_data(temp_vault):
    data = {"files": [{"path": "C:\\Windows\\System32\\cmd.exe", "sha256": "aaaa"}]}
    sealed = temp_vault.seal_artifact(
        case_id="CASE-TAMPER",
        source="files",
        data=data,
    )
    evidence_id = sealed["evidence_id"]

    # Simulate unauthorized tampering on disk
    tampered = temp_vault.simulate_tampering(evidence_id, key_to_alter="tampered_injection", new_val="MALICIOUS")
    assert tampered is True

    # Verify artifact -> must detect tampering!
    res = temp_vault.verify_artifact(evidence_id, who="Security Auditor")
    assert res["valid"] is False
    assert res["tampered"] is True
    assert res["stored_hash"] != res["recomputed_hash"]
    assert res["custody_entry"]["action"] == "TAMPER_DETECTED"
    assert res["custody_entry"]["integrity_valid"] is False

    # Check custody record logs TAMPER_DETECTED
    updated = temp_vault.get_artifact(evidence_id)
    assert len(updated["custody_log"]) == 2
    assert updated["custody_log"][1]["action"] == "TAMPER_DETECTED"


def test_vault_audit_identifies_intact_and_compromised_vaults(temp_vault):
    # Empty vault audit
    audit = temp_vault.verify_vault_integrity()
    assert audit["vault_status"] == "INTACT"
    assert audit["total_artifacts"] == 0

    # Add 2 intact artifacts
    s1 = temp_vault.seal_artifact("CASE-AUDIT", "system", {"host": "pc1"})
    s2 = temp_vault.seal_artifact("CASE-AUDIT", "network", {"connections": []})

    audit2 = temp_vault.verify_vault_integrity(case_id="CASE-AUDIT")
    assert audit2["vault_status"] == "INTACT"
    assert audit2["total_artifacts"] == 2
    assert audit2["valid_count"] == 2
    assert audit2["tampered_count"] == 0

    # Tamper with one artifact
    temp_vault.simulate_tampering(s1["evidence_id"])

    audit3 = temp_vault.verify_vault_integrity(case_id="CASE-AUDIT")
    assert audit3["vault_status"] == "COMPROMISED"
    assert audit3["total_artifacts"] == 2
    assert audit3["valid_count"] == 1
    assert audit3["tampered_count"] == 1
    assert len(audit3["tampered_artifacts"]) == 1
    assert audit3["tampered_artifacts"][0]["evidence_id"] == s1["evidence_id"]


def test_audit_ledger_chronological_ordering(temp_vault):
    s1 = temp_vault.seal_artifact("CASE-LEDGER", "system", {"item": 1}, who="User A")
    s2 = temp_vault.seal_artifact("CASE-LEDGER", "processes", {"item": 2}, who="User B")
    temp_vault.verify_artifact(s1["evidence_id"], who="Verifier")

    ledger = temp_vault.get_audit_ledger(case_id="CASE-LEDGER")
    assert len(ledger) == 3
    # Check that events have evidence_id attached
    assert all("evidence_id" in entry for entry in ledger)
    assert all("action" in entry for entry in ledger)
    # Check ordering
    timestamps = [e.get("when", "") for e in ledger]
    assert timestamps == sorted(timestamps)


def test_export_vault_bundle_creates_verifiable_manifest(temp_vault):
    temp_vault.seal_artifact("CASE-EXPORT-01", "system", {"cpu": "x86_64"})
    temp_vault.seal_artifact("CASE-EXPORT-01", "network", {"ports": [80, 443]})

    bundle = temp_vault.export_vault_bundle(case_id="CASE-EXPORT-01")
    assert bundle["format"] == "JOCKY_FORENSIC_BUNDLE_V1"
    assert bundle["case_id"] == "CASE-EXPORT-01"
    assert "manifest" in bundle
    manifest = bundle["manifest"]
    assert manifest["artifact_count"] == 2
    assert len(manifest["artifacts"]) == 2
    assert "manifest_sha256" in manifest

    # Validate that manifest sha256 verifies against artifact list
    expected_manifest_hash = compute_sha256(manifest["artifacts"])
    assert manifest["manifest_sha256"] == expected_manifest_hash


# ---------------------------------------------------------------------------
# Integration Tests: Vault REST Endpoints
# ---------------------------------------------------------------------------

def test_api_vault_seal_and_verify():
    # 1. Seal an artifact via POST /api/forensics/vault/seal
    payload = {
        "case_id": "API-TEST-CASE",
        "source": "processes",
        "data": {"process_count": 42, "items": [{"pid": 1234, "name": "svchost.exe"}]},
        "who": "Investigator Jones",
        "why": "Process memory forensic snapshot",
        "execution_id": "EXEC-API-101",
        "collector_identity": "JOCKY-FastAPI",
        "collector_version": "1.0.0",
        "target_host": "SEC-OPS-01",
    }
    seal_res = client.post("/api/forensics/vault/seal", json=payload)
    assert seal_res.status_code == 200
    seal_json = seal_res.json()
    assert seal_json["success"] is True
    evidence_id = seal_json["evidence_id"]
    sha256 = seal_json["sha256"]
    assert len(sha256) == 64

    # 2. Retrieve artifact via GET /api/forensics/vault/artifact/{id}
    art_res = client.get(f"/api/forensics/vault/artifact/{evidence_id}")
    assert art_res.status_code == 200
    art_json = art_res.json()
    assert art_json["success"] is True
    assert art_json["artifact"]["evidence_id"] == evidence_id
    assert art_json["artifact"]["execution_id"] == "EXEC-API-101"

    # 3. Verify artifact via POST /api/forensics/vault/verify
    verify_res = client.post("/api/forensics/vault/verify", json={"evidence_id": evidence_id, "who": "Lead Verifier"})
    assert verify_res.status_code == 200
    v_data = verify_res.json()
    assert v_data["success"] is True
    assert v_data["verification"]["valid"] is True
    assert v_data["verification"]["tampered"] is False

    # 4. Simulate tampering via POST /api/forensics/vault/simulate-tampering
    t_res = client.post("/api/forensics/vault/simulate-tampering", json={"evidence_id": evidence_id})
    assert t_res.status_code == 200
    assert t_res.json()["tampered"] is True

    # 5. Verify artifact again -> should detect tampering!
    verify_tampered = client.post("/api/forensics/vault/verify", json={"evidence_id": evidence_id})
    assert verify_tampered.status_code == 200
    vt_data = verify_tampered.json()
    assert vt_data["success"] is True
    assert vt_data["verification"]["valid"] is False
    assert vt_data["verification"]["tampered"] is True


def test_api_vault_list_and_audit():
    # Audit vault
    audit_res = client.get("/api/forensics/vault/audit?case_id=API-TEST-CASE")
    assert audit_res.status_code == 200
    audit_json = audit_res.json()
    assert audit_json["success"] is True
    assert "vault_status" in audit_json
    assert "custody_ledger" in audit_json

    # List artifacts
    list_res = client.get("/api/forensics/vault/list?case_id=API-TEST-CASE")
    assert list_res.status_code == 200
    list_json = list_res.json()
    assert list_json["success"] is True
    assert "artifacts" in list_json


def test_api_vault_export_bundle():
    res = client.get("/api/forensics/vault/export/API-TEST-CASE")
    assert res.status_code == 200
    data = res.json()
    assert data["success"] is True
    bundle = data["bundle"]
    assert bundle["case_id"] == "API-TEST-CASE"
    assert "manifest" in bundle
