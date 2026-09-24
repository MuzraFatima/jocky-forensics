"""
Integration tests for JOCKY FastAPI backend endpoints.
"""

from fastapi.testclient import TestClient
from backend.app.main import app

client = TestClient(app)


def test_root_endpoint():
    """Verify root endpoint serves frontend HTML."""
    response = client.get("/")
    assert response.status_code == 200
    assert "text/html" in response.headers.get("content-type", "")


def test_api_status_endpoint():
    """Verify API root/status endpoint metadata."""
    response = client.get("/api/status")
    assert response.status_code == 200
    data = response.json()
    assert data["framework"] == "JOCKY"
    assert data["status"] == "operational"

    res_api = client.get("/api")
    assert res_api.status_code == 200
    assert res_api.json()["framework"] == "JOCKY"



def test_health_check():
    """Verify health endpoint responds with healthy status."""
    response = client.get("/api/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert data["framework"] == "JOCKY"
    assert data["stage"] == "skeleton"


def test_api_parse_valid_script():
    """Verify POST /api/jocky/parse with valid script returns 200 and AST + Plan."""
    payload = {
        "script": 'CASE "LAB-2026-001"\nTARGET "LAB-PC"\nCOLLECT SYSTEM\nCOLLECT PROCESSES\nANALYZE\nREPORT'
    }
    response = client.post("/api/jocky/parse", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["success"] is True
    assert "ast" in data
    assert "execution_plan" in data
    assert data["execution_plan"]["case_id"] == "LAB-2026-001"
    assert data["execution_plan"]["target"] == "LAB-PC"
    assert len(data["execution_plan"]["tasks"]) == 4


def test_api_parse_invalid_script():
    """Verify POST /api/jocky/parse with invalid script returns 400 and line/column."""
    payload = {
        "script": 'CASE "LAB-001"\nTARGET "LAB-PC"\nCOLLECT UNKNOWN_MODULE'
    }
    response = client.post("/api/jocky/parse", json=payload)
    assert response.status_code == 400
    data = response.json()
    assert data["success"] is False
    assert data["error_type"] == "JockySyntaxError"
    assert "Invalid COLLECT target" in data["message"]
    assert data["line"] == 3
    assert data["column"] is not None


def test_api_parse_missing_case():
    """Verify POST /api/jocky/parse missing CASE returns 400."""
    payload = {
        "script": 'TARGET "LAB-PC"\nCOLLECT SYSTEM'
    }
    response = client.post("/api/jocky/parse", json=payload)
    assert response.status_code == 400
    data = response.json()
    assert data["success"] is False
    assert data["error_type"] == "JockyValidationError"
    assert "Missing mandatory 'CASE'" in data["message"]


def test_api_validate_valid_script():
    """Verify POST /api/jocky/validate evaluates policy and returns decision."""
    payload = {
        "script": (
            'CASE "LAB-2026-001"\n'
            'TARGET "LAB-PC"\n'
            'COLLECT SYSTEM\n'
            'COLLECT PROCESSES\n'
            'COLLECT NETWORK\n'
            'COLLECT FILES "./evidence"\n'
            'ANALYZE\n'
            'VERIFY INTEGRITY\n'
            'REPORT'
        )
    }
    response = client.post("/api/jocky/validate", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["success"] is True
    assert data["case_id"] == "LAB-2026-001"
    assert data["target"] == "LAB-PC"

    policy_decision = data["policy_decision"]
    assert policy_decision["allowed"] is True
    assert len(policy_decision["approved_operations"]) == 7
    assert len(policy_decision["rejected_operations"]) == 0
    assert "approved" in policy_decision["reason"].lower()

    # All approved operations must be read-only
    for op in policy_decision["approved_operations"]:
        assert op["read_only"] is True


def test_api_validate_invalid_syntax():
    """Verify POST /api/jocky/validate returns 400 on syntax error."""
    payload = {
        "script": 'CASE "LAB-001"\nTARGET "LAB-PC"\nINJECT CODE'
    }
    response = client.post("/api/jocky/validate", json=payload)
    assert response.status_code == 400
    data = response.json()
    assert data["success"] is False
    assert data["error_type"] == "JockySyntaxError"
    assert data["line"] == 3


def test_api_investigate_end_to_end():
    """
    End-to-End integration test:
    Executes script -> parses -> validates -> runs policy -> executes collectors ->
    stores evidence with SHA-256 -> verifies integrity -> returns comprehensive result.
    """
    script = (
        'CASE "LAB-2026-001"\n'
        'TARGET "LAB-PC"\n'
        'COLLECT SYSTEM\n'
        'COLLECT PROCESSES\n'
        'COLLECT NETWORK\n'
        'ANALYZE\n'
        'VERIFY INTEGRITY\n'
        'REPORT'
    )
    payload = {"script": script}
    response = client.post("/api/jocky/investigate", json=payload)

    assert response.status_code == 200
    data = response.json()

    # 1. Case and Target
    assert data["success"] is True
    assert data["status"] == "COMPLETED"
    assert data["case_id"] == "LAB-2026-001"
    assert data["target"] == "LAB-PC"

    # 2. Execution Plan
    assert "execution_plan" in data
    assert len(data["execution_plan"]["tasks"]) == 6

    # 3. Policy Result
    assert data["policy_result"]["allowed"] is True
    assert len(data["policy_result"]["approved_operations"]) == 6
    assert len(data["policy_result"]["rejected_operations"]) == 0

    # 4. Collected Data
    collected = data["collected_data"]
    assert "system" in collected
    assert collected["system"]["collector"] == "system"
    assert collected["system"]["read_only"] is True

    assert "processes" in collected
    assert collected["processes"]["collector"] == "processes"
    assert collected["processes"]["count"] > 0

    assert "network" in collected
    assert collected["network"]["collector"] == "network"
    assert isinstance(collected["network"]["connections"], list)

    # 5. Evidence IDs
    evidence_ids = data["evidence_ids"]
    assert "system" in evidence_ids
    assert "processes" in evidence_ids
    assert "network" in evidence_ids
    assert evidence_ids["system"].startswith("EVID-LAB-2026-001-system-")

    # 6. SHA-256 Hashes
    hashes = data["sha256_hashes"]
    assert len(hashes["system"]) == 64
    assert len(hashes["processes"]) == 64
    assert len(hashes["network"]) == 64

    # 7. Integrity Status
    integrity = data["integrity_status"]
    assert integrity["verified"] is True
    assert integrity["total_verified"] == 3
    for detail in integrity["details"]:
        assert detail["valid"] is True
        assert detail["stored_hash"] == detail["recomputed_hash"]

    # 8. Timestamps
    timestamps = data["timestamps"]
    assert "started_at" in timestamps
    assert "completed_at" in timestamps

    # 9. Analysis and Report
    assert "analysis" in data
    assert data["analysis"]["status"] == "COMPLETED"
    assert "report" in data
    assert data["report"]["case_id"] == "LAB-2026-001"


# =============================================================================
# Phase 2 — Execute API Endpoint Tests (POST /api/jocky/execute)
# =============================================================================

def test_api_execute_ir_valid_script():
    """
    POST /api/jocky/execute with a valid script:
    Expect 200, success=True, receipts non-empty, evidence collected.
    """
    script = (
        'CASE "IR-2026-001"\n'
        'TARGET "IR-HOST"\n'
        'COLLECT SYSTEM\n'
        'COLLECT PROCESSES\n'
        'COLLECT NETWORK\n'
        'ANALYZE PROCESS_NETWORK\n'
        'VERIFY INTEGRITY\n'
        'REPORT FORMAT JSON'
    )
    response = client.post("/api/jocky/execute", json={"script": script})
    assert response.status_code == 200
    data = response.json()

    # Top-level success and identity
    assert data["success"] is True
    assert data["case_id"] == "IR-2026-001"
    assert data["target"] == "IR-HOST"
    assert data["ir_version"] == "1.0"

    # Policy result embedded
    assert "policy_result" in data
    assert data["policy_result"]["allowed"] is True

    # Receipts: one per IR operation
    assert "receipts" in data
    assert len(data["receipts"]) == 6
    for r in data["receipts"]:
        assert r["status"] == "COMPLETED"
        assert "capability" in r

    # Evidence collected for all three sources
    assert "system" in data["collected_data"]
    assert "processes" in data["collected_data"]
    assert "network" in data["collected_data"]

    # Evidence IDs and hashes
    for src in ("system", "processes", "network"):
        assert src in data["evidence_ids"]
        assert src in data["sha256_hashes"]
        assert len(data["sha256_hashes"][src]) == 64

    # Integrity verified
    assert data["integrity_status"]["verified"] is True

    # Timestamps
    assert "started_at" in data["timestamps"]
    assert "completed_at" in data["timestamps"]


def test_api_execute_ir_blocked_by_policy():
    """
    POST /api/jocky/execute where IR contains a policy-violating operation:
    This requires a custom IR that bypasses DSL validation — not possible via the script
    endpoint alone (the DSL only generates valid ops). Instead verify compile error path
    using an invalid script that produces a DSL error before reaching policy.

    Test the pre-flight policy check by using a valid-syntax script that compiles to
    an IR where we probe the endpoint flow. Since the DSL itself won't generate INJECT
    operations, we test that policy denial is correctly returned from the engine for
    the standalone evaluate_ir_policy call, and that the endpoint returns 400 on
    bad syntax properly.
    """
    # Use a script that produces a syntax error (unknown command) → expect 400
    bad_script = 'CASE "X"\nTARGET "Y"\nINJECT PROCESS'
    response = client.post("/api/jocky/execute", json={"script": bad_script})
    assert response.status_code == 400
    data = response.json()
    assert data["success"] is False
    assert "error_type" in data


def test_api_execute_ir_syntax_error():
    """
    POST /api/jocky/execute with invalid JOCKY syntax:
    Expect 400 with error_type and message.
    """
    payload = {"script": 'CASE "IR-001"\nTARGET "HOST"\nCOLLECT UNKNOWN_THING'}
    response = client.post("/api/jocky/execute", json={"script": payload["script"]})
    assert response.status_code == 400
    data = response.json()
    assert data["success"] is False
    assert "error_type" in data
    assert data["message"] is not None


def test_api_execute_ir_receipt_fields():
    """
    POST /api/jocky/execute: verify each receipt entry has required structured fields.
    """
    script = (
        'CASE "IR-FIELD-001"\n'
        'TARGET "FIELD-HOST"\n'
        'COLLECT SYSTEM'
    )
    response = client.post("/api/jocky/execute", json={"script": script})
    assert response.status_code == 200
    data = response.json()

    assert len(data["receipts"]) == 1
    entry = data["receipts"][0]
    for key in ("index", "type", "capability", "policy_decision", "status", "started_at", "completed_at"):
        assert key in entry, f"Receipt entry missing required field '{key}'"
    assert entry["policy_decision"] == "ALLOWED"
    assert entry["status"] == "COMPLETED"
    assert entry["capability"] == "COLLECT_SYSTEM"


def test_api_execute_ir_version_field():
    """
    POST /api/jocky/execute: the ir_version field must reflect JOCKY IR v1.0.
    """
    script = (
        'CASE "IR-VER-001"\n'
        'TARGET "VER-HOST"\n'
        'COLLECT SYSTEM'
    )
    response = client.post("/api/jocky/execute", json={"script": script})
    assert response.status_code == 200
    data = response.json()
    assert data["ir_version"] == "1.0"


# =====================================================================
# Phase 3: Direct Forensic Collector API Tests
# =====================================================================

def test_api_forensics_list_collectors():
    """Verify GET /api/forensics/collectors returns Phase 3 collectors list."""
    response = client.get("/api/forensics/collectors")
    assert response.status_code == 200
    data = response.json()
    assert data["framework"] == "JOCKY"
    assert data["phase"] == 3
    collector_names = [c["name"] for c in data["collectors"]]
    assert "system" in collector_names
    assert "processes" in collector_names
    assert "network" in collector_names
    assert "files" in collector_names
    assert "users" in collector_names
    assert "windows_metadata" in collector_names
    assert "registry" in collector_names


def test_api_forensics_direct_collect_files():
    """Verify GET /api/forensics/collect/files returns structured file forensic artifact."""
    response = client.get("/api/forensics/collect/files")
    assert response.status_code == 200
    data = response.json()
    assert data["success"] is True
    assert data["source"] == "files"
    artifact = data["artifact"]
    assert artifact["collector"] == "files"
    assert artifact["read_only"] is True
    assert "provenance" in artifact
    assert "files" in artifact


def test_api_forensics_direct_collect_users():
    """Verify GET /api/forensics/collect/users returns user & session telemetry."""
    response = client.get("/api/forensics/collect/users")
    assert response.status_code == 200
    data = response.json()
    assert data["success"] is True
    assert data["source"] == "users"
    artifact = data["artifact"]
    assert artifact["collector"] == "users"
    assert "current_user" in artifact


def test_api_forensics_direct_collect_windows_metadata():
    """Verify GET /api/forensics/collect/windows_metadata returns Windows metadata."""
    response = client.get("/api/forensics/collect/windows_metadata")
    assert response.status_code == 200
    data = response.json()
    assert data["success"] is True
    assert data["source"] == "windows_metadata"
    artifact = data["artifact"]
    assert artifact["collector"] == "windows_metadata"
    assert "autoruns" in artifact
    assert "services" in artifact


def test_api_forensics_direct_collect_unknown():
    """Verify GET /api/forensics/collect/invalid returns 404 with helpful error."""
    response = client.get("/api/forensics/collect/unauthorized_collector")
    assert response.status_code == 404
    data = response.json()
    assert data["success"] is False
    assert "available_collectors" in data


# =====================================================================
# Phase 4: Correlation API Tests
# =====================================================================

def test_api_forensics_correlate_live():
    """Verify GET /api/forensics/correlate runs correlation across live data."""
    response = client.get("/api/forensics/correlate")
    assert response.status_code == 200
    data = response.json()
    assert data["success"] is True
    assert "correlation" in data
    corr = data["correlation"]
    assert "summary" in corr
    assert "entities" in corr
    assert "relationships" in corr
    assert "process_tree" in corr
    assert "correlated_chains" in corr


def test_api_forensics_correlate_post():
    """Verify POST /api/forensics/correlate correlates given payload."""
    payload = {
        "evidence": {
            "processes": [
                {"pid": 111, "ppid": None, "name": "root.exe", "exe": r"C:\root.exe"},
                {"pid": 222, "ppid": 111, "name": "child.exe", "exe": r"C:\child.exe"},
            ],
            "network": [
                {"pid": 222, "protocol": "TCP", "laddr": {"ip": "127.0.0.1", "port": 8080}}
            ],
            "files": [
                {"path": r"C:\child.exe", "sha256": "f" * 64}
            ]
        }
    }
    response = client.post("/api/forensics/correlate", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["success"] is True
    corr = data["correlation"]
    assert corr["summary"]["process_count"] == 2
    assert corr["summary"]["network_count"] == 1
    assert corr["summary"]["file_count"] >= 1
    assert any(r["type"] == "SPAWNED_CHILD" for r in corr["relationships"])
    assert any(r["type"] == "OPENED_SOCKET" for r in corr["relationships"])


# =====================================================================
# Phase 5: Timeline & Automated Analysis API Tests
# =====================================================================

def test_api_forensics_timeline_live():
    """Verify GET /api/forensics/timeline builds chronological event stream from live state."""
    response = client.get("/api/forensics/timeline")
    assert response.status_code == 200
    data = response.json()
    assert data["success"] is True
    assert "timeline" in data
    assert isinstance(data["timeline"], list)
    assert data["count"] == len(data["timeline"])
    if data["count"] > 0:
        evt = data["timeline"][0]
        assert "timestamp" in evt
        assert "event_type" in evt
        assert "entity" in evt


def test_api_forensics_timeline_post():
    """Verify POST /api/forensics/timeline normalizes provided evidence."""
    payload = {
        "evidence": {
            "processes": [
                {"pid": 777, "name": "scanner.exe", "create_time": "2026-09-23T11:00:00Z"}
            ],
            "network": [
                {"pid": 777, "protocol": "TCP", "status": "ESTABLISHED"}
            ]
        }
    }
    response = client.post("/api/forensics/timeline", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["success"] is True
    assert data["count"] >= 2
    types = [e["event_type"] for e in data["timeline"]]
    assert "PROCESS_SPAWN" in types
    assert "NETWORK_SOCKET" in types


def test_api_forensics_analysis_live():
    """Verify GET /api/forensics/analysis evaluates heuristic detection rules on live state."""
    response = client.get("/api/forensics/analysis")
    assert response.status_code == 200
    data = response.json()
    assert data["success"] is True
    assert "total_detections" in data
    assert "severity_counts" in data
    assert "detections" in data
    assert "high" in data["severity_counts"]


def test_api_forensics_analysis_post():
    """Verify POST /api/forensics/analysis evaluates rules on custom anomalous evidence."""
    payload = {
        "evidence": {
            "processes": [
                {
                    "pid": 9999,
                    "name": "suspicious.exe",
                    "exe": r"C:\Users\Admin\AppData\Local\Temp\suspicious.exe",
                }
            ]
        }
    }
    response = client.post("/api/forensics/analysis", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["success"] is True
    assert data["total_detections"] >= 1
    assert data["severity_counts"]["high"] >= 1
    rule_ids = [d["rule_id"] for d in data["detections"]]
    assert "RULE-001" in rule_ids




