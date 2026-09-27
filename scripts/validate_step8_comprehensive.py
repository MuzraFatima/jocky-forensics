"""
Step 8: Comprehensive Final Validation & Security Verification Script
"""
import sys
import os
import json
import time
import hashlib
import platform
import subprocess
import urllib.request
import urllib.error
from pathlib import Path

repo_root = Path(__file__).resolve().parent.parent
if str(repo_root) not in sys.path:
    sys.path.insert(0, str(repo_root))

from fastapi.testclient import TestClient
from backend.app.main import app
from backend.app.agents.manager import AgentManager, get_agent_manager
from backend.app.evidence.vault import EvidenceVault
from backend.app.engine.hardening import (
    SecurityValidationError,
    sanitize_case_id,
    sanitize_forensic_path,
)

client = TestClient(app)

results = {}

def log_check(name, passed, detail=""):
    results[name] = {"passed": passed, "detail": detail}
    status = "[PASS]" if passed else "[FAIL]"
    print(f"{status} {name}: {detail}")

print("======================================================================")
print("JOCKY STEP 8: COMPREHENSIVE FINAL VALIDATION")
print("======================================================================")

# 1. Investigator Auth
login_res = client.post("/api/auth/login", json={"username": "investigator@jocky.local", "password": "jocky-forensics-2026"})
token = login_res.json()["session"]["token"]
auth_headers = {"Authorization": f"Bearer {token}"}
log_check("Investigator Auth", login_res.status_code == 200, f"Token obtained ({token[:16]}...)")

# 2. Pairing Code Generation & Single-Use
pair_gen = client.post("/api/agents/pairing/generate", json={"device_name": "Val-Host"}, headers=auth_headers).json()
code = pair_gen["pairing_code"]
log_check("Pairing Code Generation", len(code) == 8, f"Code: {code}, TTL: {pair_gen['ttl_seconds']}s")

# Test Pairing Code Exchange
pair_res1 = client.post("/api/agents/pair", json={"pairing_code": code, "hostname": "Val-Host-1", "platform": "Windows 11"})
log_check("Pairing Code Exchange", pair_res1.status_code == 200, f"Device ID: {pair_res1.json().get('device_id')}")

# Test Single-Use (Re-using the same code must fail)
pair_res2 = client.post("/api/agents/pair", json={"pairing_code": code, "hostname": "Val-Host-2", "platform": "Windows 11"})
log_check("Pairing Code Single-Use Enforcement", pair_res2.status_code == 400, f"Second use status: {pair_res2.status_code}")

dev1 = pair_res1.json()
dev1_id = dev1["device_id"]
dev1_token = dev1["device_token"]
dev1_headers = {"Authorization": f"Bearer {dev1_token}", "X-Device-Id": dev1_id}

import datetime
from backend.app.agents.models import AgentJob, CollectorOperation, AllowedCollector

# 3. Heartbeat & Online Status
now_utc = datetime.datetime.now(datetime.timezone.utc).isoformat()
hb_res = client.post(
    "/api/agents/heartbeat",
    json={
        "device_id": dev1_id,
        "timestamp": now_utc,
        "hostname": "Val-Host-1",
        "platform": "Windows 11",
        "agent_version": "1.0.0",
    },
    headers=dev1_headers,
)
log_check("Heartbeat Dispatch", hb_res.status_code == 200 and hb_res.json().get("acknowledged") is True)

devs_res = client.get("/api/agents/devices", headers=auth_headers).json()
dev1_record = next((d for d in devs_res["devices"] if d["device_id"] == dev1_id), None)
log_check("Device Listed with Online Status", dev1_record is not None and dev1_record.get("is_online") is True)

# Check Safe Metadata (No secrets exposed)
has_token = "token" in dev1_record or "token_hash" in dev1_record or "device_token" in dev1_record
log_check("Safe Metadata Guarantee (No tokens/hashes in GET /devices)", not has_token)

# 4. Multi-Device Isolation
pair_gen2 = client.post("/api/agents/pairing/generate", json={"device_name": "Val-Host-2"}, headers=auth_headers).json()
code2 = pair_gen2["pairing_code"]
pair_res3 = client.post("/api/agents/pair", json={"pairing_code": code2, "hostname": "Val-Host-2", "platform": "Linux Ubuntu"})
dev2 = pair_res3.json()
dev2_id = dev2["device_id"]
dev2_token = dev2["device_token"]
dev2_headers = {"Authorization": f"Bearer {dev2_token}", "X-Device-Id": dev2_id}

# Enqueue job for dev1 only
manager = get_agent_manager()
job = AgentJob(
    job_id="JOB-ISO-00000001",
    user_id="investigator@jocky.local",
    device_id=dev1_id,
    case_id="CASE-ISO",
    execution_id="EXEC-ISO-01",
    allowed_operations=[CollectorOperation(collector=AllowedCollector.SYSTEM)],
)
manager.enqueue_job(dev1_id, job)

# dev2 polls jobs -> must receive nothing for itself
dev2_poll = client.get("/api/agents/jobs", headers=dev2_headers).json()
log_check("Multi-Device Isolation (Dev 2 cannot poll Dev 1's jobs)", dev2_poll.get("job") is None)

# dev1 polls jobs -> receives the job
dev1_poll = client.get("/api/agents/jobs", headers=dev1_headers).json()
log_check("Targeted Job Polling (Dev 1 receives its job)", dev1_poll.get("job") is not None and dev1_poll["job"]["job_id"] == job.job_id)

from backend.app.evidence.hashing import compute_sha256

# 5. Evidence Submission, SHA-256 Integrity, and Tamper Detection
sample_payload = {"hostname": "Val-Host-1", "os": "Windows", "cpu": 4}
real_sha256 = compute_sha256(sample_payload)
fake_sha256 = "0" * 64

# Submitting with tampered/invalid SHA-256 must be rejected
tampered_sub = client.post("/api/agents/result", json={
    "device_id": dev1_id,
    "execution_id": "EXEC-ISO-01",
    "collector": "system",
    "collector_version": "1.0.0",
    "acquisition_timestamp": "2026-09-27T12:00:00Z",
    "payload": sample_payload,
    "agent_sha256": fake_sha256
}, headers=dev1_headers)
log_check("Evidence Submission Tamper Detection (Mismatched SHA-256 rejected)", tampered_sub.status_code == 400)

# Submitting with genuine SHA-256 succeeds
valid_sub = client.post("/api/agents/result", json={
    "device_id": dev1_id,
    "execution_id": "EXEC-ISO-01",
    "collector": "system",
    "collector_version": "1.0.0",
    "acquisition_timestamp": "2026-09-27T12:00:00Z",
    "payload": sample_payload,
    "agent_sha256": real_sha256
}, headers=dev1_headers)
log_check("Evidence Submission Integrity (Genuine SHA-256 accepted)", valid_sub.status_code == 200, f"Status: {valid_sub.status_code}")

# Verify agent manager recorded the verified submission
sub_results = manager.get_results("EXEC-ISO-01")
log_check("In-Memory Result Registry Recorded Verified Submission", len(sub_results) == 1 and sub_results[0].agent_sha256 == real_sha256)

# Seal artifact in vault to test custody & tamper verification
vault = EvidenceVault()
sealed = vault.seal_artifact(
    case_id="CASE-ISO",
    source="system",
    data=sample_payload,
    execution_id="EXEC-ISO-01",
    collector_identity=f"JOCKY-EndpointAgent-{dev1_id}",
    target_host="Val-Host-1",
)
log_check("Evidence Vault Sealing & Chain of Custody", sealed.get("sha256") == real_sha256)

# Full cryptographic audit of the vault
audit = vault.verify_vault_integrity(case_id="CASE-ISO")
log_check("Cryptographic Vault Audit (INTACT)", audit["vault_status"] == "INTACT", f"Valid artifacts: {audit['valid_count']}, Tampered: {audit['tampered_count']}")

# 6. Local JOCKY Execution Still Works
local_script = """CASE "STEP8-LOCAL"
TARGET "LOCAL-HOST"
COLLECT SYSTEM
ANALYZE
VERIFY INTEGRITY
REPORT FORMAT JSON"""

local_exec = client.post("/api/jocky/execute", json={"script": local_script}, headers=auth_headers).json()
log_check("Local JOCKY Execution (Backward Compatibility)", local_exec.get("success") is True and "system" in local_exec.get("collected_data", {}))

# 7. Device Revocation
revoke_res = client.post(f"/api/agents/devices/{dev1_id}/revoke", headers=auth_headers)
log_check("Device Revocation API", revoke_res.status_code == 200 and revoke_res.json().get("success") is True)

# Revoked device cannot heartbeat
revoked_hb = client.post("/api/agents/heartbeat", json={"device_id": dev1_id, "hostname": "Val-Host-1", "platform": "Windows 11", "agent_version": "1.0.0"}, headers=dev1_headers)
log_check("Revoked Device Heartbeat Rejected (HTTP 401)", revoked_hb.status_code == 401)

# Revoked device cannot poll jobs
revoked_poll = client.get("/api/agents/jobs", headers=dev1_headers)
log_check("Revoked Device Job Polling Rejected (HTTP 401)", revoked_poll.status_code == 401)

# 8. Security Audits: Path Traversal & Sanitization
try:
    sanitize_case_id("../../etc/passwd")
    traversal_case_blocked = False
except (ValueError, SecurityValidationError):
    traversal_case_blocked = True
log_check("Security: Path Traversal in Case ID Blocked", traversal_case_blocked)

try:
    sanitize_forensic_path(Path("c:/sandbox"), Path("c:/sandbox/../../windows/system32"))
    traversal_path_blocked = False
except (ValueError, SecurityValidationError):
    traversal_path_blocked = True
log_check("Security: Path Traversal in Forensic Path Blocked", traversal_path_blocked)

# 9. Summary Print
all_passed = all(r["passed"] for r in results.values())
print("\n" + "=" * 70)
print(f"STEP 8 VALIDATION SUMMARY: {'ALL PASSED' if all_passed else 'SOME CHECKS FAILED'}")
print("=" * 70)
for name, data in results.items():
    print(f"{'[X]' if data['passed'] else '[ ]'} {name}")
print("=" * 70)
sys.exit(0 if all_passed else 1)
