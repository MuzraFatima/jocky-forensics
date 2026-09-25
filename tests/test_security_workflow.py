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

import uuid
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


def test_auth_register_and_login_workflow():
    """Verify investigator registration and subsequent authentication."""
    uid = uuid.uuid4().hex[:6]
    test_email = f"field_examiner_{uid}@agency.gov"
    reg_payload = {
        "email": test_email,
        "username": test_email,
        "password": "SecurePassword2026!",
        "role": "Incident Responder",
        "case_id": "CASE-REG-01",
    }
    reg_resp = client.post("/api/auth/register", json=reg_payload)
    assert reg_resp.status_code == 200
    reg_data = reg_resp.json()
    assert reg_data["success"] is True
    assert "token" in reg_data["session"]
    assert reg_data["session"]["username"] == test_email
    assert reg_data["session"]["role"] == "Incident Responder"

    # Verify session check
    token = reg_data["session"]["token"]
    me_resp = client.get("/api/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert me_resp.status_code == 200
    assert me_resp.json()["session"]["username"] == test_email

    # Now verify login with the new account
    login_resp = client.post("/api/auth/login", json={
        "username": test_email,
        "password": "SecurePassword2026!",
        "case_id": "CASE-REG-01",
    })
    assert login_resp.status_code == 200
    login_data = login_resp.json()
    assert login_data["success"] is True
    assert "token" in login_data["session"]


def test_auth_register_duplicate_user_rejected():
    """Verify duplicate registration attempt is rejected with 409 Conflict."""
    uid = uuid.uuid4().hex[:6]
    test_email = f"duplicate_examiner_{uid}@agency.gov"
    reg_payload = {
        "email": test_email,
        "password": "SecurePassword2026!",
    }
    # First registration -> 200
    res1 = client.post("/api/auth/register", json=reg_payload)
    assert res1.status_code == 200

    # Second registration with same email -> 409
    res2 = client.post("/api/auth/register", json=reg_payload)
    assert res2.status_code == 409
    assert res2.json()["success"] is False
    assert "already exists" in res2.json()["error"]


def test_auth_registered_user_wrong_password():
    """Verify login with registered user but invalid password returns 401."""
    uid = uuid.uuid4().hex[:6]
    test_email = f"sec_agent_{uid}@agency.gov"
    reg_payload = {
        "email": test_email,
        "password": "CorrectPassword123!",
    }
    client.post("/api/auth/register", json=reg_payload)

    # Attempt login with wrong password
    login_resp = client.post("/api/auth/login", json={
        "username": test_email,
        "password": "IncorrectPassword999!",
    })
    assert login_resp.status_code == 401
    assert login_resp.json()["success"] is False


def test_auth_demo_and_admin_accounts_still_work():
    """Verify existing demo and admin accounts continue to authenticate seamlessly."""
    # 1. Investigator demo
    resp_inv = client.post("/api/auth/login", json={
        "username": "investigator@jocky.local",
        "password": "jocky-forensics-2026",
    })
    assert resp_inv.status_code == 200
    assert resp_inv.json()["success"] is True

    # 2. Admin demo
    resp_adm = client.post("/api/auth/login", json={
        "username": "admin@jocky.local",
        "password": "admin-forensics-2026",
    })
    assert resp_adm.status_code == 200
    assert resp_adm.json()["success"] is True

    # 3. Short aliases
    resp_short = client.post("/api/auth/login", json={
        "username": "admin",
        "password": "admin-forensics-2026",
    })
    assert resp_short.status_code == 200
    assert resp_short.json()["success"] is True


def test_auth_persistence_across_backend_restart(tmp_path):
    """
    Verify registered accounts are securely hashed with PBKDF2-HMAC-SHA256,
    persisted to disk, and successfully re-loaded across fresh AuthManager re-initializations.
    """
    from backend.app.security.auth import AuthManager

    # Instantiate AuthManager with custom isolated storage
    manager_1 = AuthManager(storage_dir=tmp_path)
    user_email = "persistent_examiner@jocky.local"
    raw_password = "PersistentSecretKey2026!"

    # Register user in manager 1
    session_1 = manager_1.register(
        username=user_email,
        password=raw_password,
        role="Senior Forensic Specialist",
    )
    assert session_1["username"] == user_email

    # Verify password in memory is hashed, NOT plaintext
    record = manager_1.get_user(user_email)
    assert record is not None
    assert record["password"].startswith("pbkdf2_sha256$")
    assert raw_password not in record["password"]

    # Verify persistent file exists and does NOT contain raw password
    users_file = tmp_path / "users.json"
    assert users_file.is_file()
    file_content = users_file.read_text(encoding="utf-8")
    assert raw_password not in file_content
    assert "pbkdf2_sha256$" in file_content

    # Simulate backend / process restart: create fresh AuthManager with same storage_dir
    manager_2 = AuthManager(storage_dir=tmp_path)

    # Verify user was restored
    user_restored = manager_2.get_user(user_email)
    assert user_restored is not None
    assert user_restored["username"] == user_email

    # Authenticate with original password in restarted manager
    auth_result = manager_2.authenticate(user_email, raw_password)
    assert auth_result is not None
    assert auth_result["username"] == user_email

    # Wrong password fails in restarted manager
    assert manager_2.authenticate(user_email, "WrongPassword") is None

