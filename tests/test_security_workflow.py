"""
Unit and integration tests for JOCKY Security & Incident Response Subsystem:
- Authentication & Session Verification
- Analyst Availability & Simulation Channel
- AI Fallback Provider (No Groq, Safe Advisory)
- Critical Incident Alert Workflow
- Secure Report Queue (SENT vs QUEUED states)
- Audit Logging & Verification
- Evidence Integrity Invariants
"""

from fastapi.testclient import TestClient
from backend.app.main import app
from backend.app.security import (
    analyst_manager,
    auth_manager,
    report_queue,
    get_audit_events,
)
from backend.app.evidence import _default_vault

client = TestClient(app)


def test_auth_login_success():
    """Verify login with demo credentials returns token and investigator session."""
    payload = {
        "username": "investigator@jocky.local",
        "password": "jocky-forensics-2026",
        "case_id": "TEST-CASE-001",
    }
    resp = client.post("/api/auth/login", json=payload)
    assert resp.status_code == 200
    data = resp.json()
    assert data["success"] is True
    assert "token" in data["session"]
    assert data["session"]["role"] == "Lead Forensic Examiner"
    assert data["session"]["username"] == "investigator@jocky.local"

    # Verify session check
    token = data["session"]["token"]
    me_resp = client.get("/api/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert me_resp.status_code == 200
    assert me_resp.json()["session"]["username"] == "investigator@jocky.local"


def test_auth_login_invalid_password():
    """Verify failed login returns 401 and records audit event."""
    payload = {
        "username": "investigator@jocky.local",
        "password": "wrong-password",
        "case_id": "TEST-CASE-001",
    }
    resp = client.post("/api/auth/login", json=payload)
    assert resp.status_code == 401
    assert resp.json()["success"] is False

    # Check audit log for FAILED_LOGIN
    audits = get_audit_events(limit=5, action="FAILED_LOGIN")
    assert len(audits) > 0
    assert audits[0]["action"] == "FAILED_LOGIN"


def test_auth_logout():
    """Verify logout revokes session and records audit event."""
    login_resp = client.post("/api/auth/login", json={
        "username": "admin",
        "password": "admin-forensics-2026",
        "case_id": "TEST-CASE-LOGOUT",
    })
    token = login_resp.json()["session"]["token"]

    logout_resp = client.post("/api/auth/logout", json={
        "token": token,
        "report_sent_status": "LOGOUT_WITHOUT_SENDING",
        "case_id": "TEST-CASE-LOGOUT",
    })
    assert logout_resp.status_code == 200
    assert logout_resp.json()["success"] is True

    # Token should now be invalid
    me_resp = client.get("/api/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert me_resp.status_code == 401


def test_analyst_status_and_toggle():
    """Verify analyst status endpoint and demo toggle capability."""
    resp = client.get("/api/security/analyst/status")
    assert resp.status_code == 200
    data = resp.json()
    assert "status" in data
    assert data["is_simulation"] is True

    # Toggle to OFFLINE
    t_resp = client.post("/api/security/analyst/toggle", json={"status": "OFFLINE"})
    assert t_resp.status_code == 200
    assert t_resp.json()["status"] == "OFFLINE"

    # Reset to ONLINE
    client.post("/api/security/analyst/toggle", json={"status": "ONLINE"})


def test_security_chat_analyst_online():
    """Verify chatting when analyst is ONLINE routes to human analyst channel."""
    client.post("/api/security/analyst/toggle", json={"status": "ONLINE"})

    chat_resp = client.post("/api/security/chat", json={
        "message": "We have an incident with suspicious temporary folder execution.",
        "mode": "auto",
        "case_id": "CASE-TEST-SOC",
    })
    assert chat_resp.status_code == 200
    data = chat_resp.json()
    assert data["success"] is True
    assert data["channel"] == "analyst"
    assert "Sarah Connor" in data["reply"]["sender_name"]
    assert data["reply"]["role"] == "analyst"


def test_security_chat_ai_fallback_when_offline():
    """Verify chatting when analyst is OFFLINE falls back to AI Forensic Assistant."""
    # Set analyst to OFFLINE
    client.post("/api/security/analyst/toggle", json={"status": "OFFLINE"})

    # Send message in auto mode
    chat_resp = client.post("/api/security/chat", json={
        "message": "What heuristic rules are evaluated?",
        "mode": "auto",
        "case_id": "CASE-TEST-AI",
    })
    assert chat_resp.status_code == 200
    data = chat_resp.json()
    assert data["success"] is True
    assert data["channel"] == "ai"
    assert "AI Forensic Assistant" in data["reply"]

    # Reset analyst to ONLINE
    client.post("/api/security/analyst/toggle", json={"status": "ONLINE"})


def test_critical_incident_alert_endpoint():
    """Verify GET /api/security/incident/current evaluates live rules without mutating evidence."""
    resp = client.get("/api/security/incident/current?case_id=LAB-2026-001&target=LAB-PC")
    assert resp.status_code == 200
    data = resp.json()
    assert data["success"] is True
    incident = data["incident"]
    assert "case_id" in incident
    assert "severity" in incident
    assert "disclaimer" in incident
    assert "evidence_integrity_status" in incident
    assert incident["case_id"] == "LAB-2026-001"


def test_report_send_and_queue_workflow():
    """
    Verify report sending:
    1. When service is reachable -> status: SENT
    2. When service is unreachable -> status: QUEUED
    3. Retry capability
    """
    # 1. Reachable service -> SENT
    report_queue.set_service_reachable(True)
    resp_sent = client.post("/api/security/report/send", json={
        "case_id": "CASE-TEST-RPT",
        "format": "JSON",
        "destination": "CENTRAL-SOC",
    })
    assert resp_sent.status_code == 200
    d_sent = resp_sent.json()["delivery"]
    assert d_sent["status"] == "SENT"
    assert d_sent["delivery_receipt"] is not None
    assert "sha256" in d_sent

    # 2. Unreachable service -> QUEUED
    report_queue.set_service_reachable(False)
    resp_queued = client.post("/api/security/report/send", json={
        "case_id": "CASE-TEST-RPT",
        "format": "JSON",
        "destination": "OFFLINE-SOC",
    })
    assert resp_queued.status_code == 200
    d_queued = resp_queued.json()["delivery"]
    assert d_queued["status"] == "QUEUED"
    assert d_queued["error_reason"] is not None
    assert d_queued["delivery_receipt"] is None
    queued_id = d_queued["report_id"]

    # 3. Check status endpoint
    stat_resp = client.get(f"/api/security/report/status/{queued_id}")
    assert stat_resp.status_code == 200
    assert stat_resp.json()["report"]["status"] == "QUEUED"

    # 4. Retry after service restored -> SENT
    report_queue.set_service_reachable(True)
    retry_resp = client.post(f"/api/security/report/retry/{queued_id}")
    assert retry_resp.status_code == 200
    assert retry_resp.json()["report"]["status"] == "SENT"


def test_audit_log_endpoint():
    """Verify GET /api/security/audit returns chronological audit records without passwords."""
    resp = client.get("/api/security/audit?limit=20")
    assert resp.status_code == 200
    data = resp.json()
    assert data["success"] is True
    assert data["total"] > 0
    events = data["events"]
    for evt in events:
        assert "timestamp" in evt
        assert "action" in evt
        # Ensure raw password values are never leaked in audit logs
        assert "jocky-forensics-2026" not in str(evt)
        assert "admin-forensics-2026" not in str(evt)
        assert "wrong-password" not in str(evt)


def test_evidence_vault_unmodified_by_security_workflow():
    """Verify that all security, chat, and reporting operations leave Evidence Vault intact."""
    vault_audit = _default_vault.verify_vault_integrity()
    assert vault_audit.get("vault_status") in ("INTACT", "VERIFIED")
    assert vault_audit.get("tampered_count", 0) == 0
