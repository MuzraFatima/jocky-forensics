"""
Unit tests for JOCKY Policy Engine and Forensic Executor.

Phase 1 legacy tests: PolicyEngine, ForensicExecutor.
Phase 2 IR tests: evaluate_ir_policy, filter helpers, IRExecutor.
"""

from backend.app.engine import ForensicExecutor, PolicyEngine
from backend.app.language import parse_jocky_script


# =============================================================================
# Phase 1 — Legacy Policy Engine + ForensicExecutor Tests
# =============================================================================

def test_valid_execution_plan_is_approved():
    """Verify that a canonical valid execution plan is completely approved."""
    script = """
    CASE "LAB-2026-001"
    TARGET "LAB-PC"
    COLLECT SYSTEM
    COLLECT PROCESSES
    COLLECT NETWORK
    COLLECT FILES "./evidence"
    ANALYZE
    VERIFY INTEGRITY
    REPORT
    """
    parsed = parse_jocky_script(script)
    plan = parsed["execution_plan"]

    policy = PolicyEngine()
    result = policy.evaluate(plan)

    assert result["allowed"] is True
    assert len(result["approved_operations"]) == 7
    assert len(result["rejected_operations"]) == 0
    assert "All 7 operations approved" in result["reason"]

    # Invariant: Every approved operation must be marked read-only
    for op in result["approved_operations"]:
        assert op["read_only"] is True
        assert op["policy_status"] == "APPROVED"
        assert len(op["reason"]) > 0


def test_every_supported_operation_is_allowed():
    """Verify that each authorized operation is permitted by the policy engine."""
    policy = PolicyEngine()

    test_cases = [
        ({"action": "COLLECT", "category": "SYSTEM", "step": 1}, "COLLECT", "SYSTEM"),
        ({"action": "COLLECT", "category": "PROCESSES", "step": 1}, "COLLECT", "PROCESSES"),
        ({"action": "COLLECT", "category": "NETWORK", "step": 1}, "COLLECT", "NETWORK"),
        ({"action": "COLLECT", "category": "FILES", "params": {"path": "./evidence"}, "step": 1}, "COLLECT", "FILES"),
        ({"action": "ANALYZE", "step": 1}, "ANALYZE", None),
        ({"action": "VERIFY", "target": "INTEGRITY", "step": 1}, "VERIFY", "INTEGRITY"),
        ({"action": "REPORT", "step": 1}, "REPORT", None),
    ]

    for task, expected_op, expected_target in test_cases:
        plan = {"case_id": "TEST", "target": "HOST", "tasks": [task]}
        res = policy.evaluate(plan)
        assert res["allowed"] is True, f"Failed for {expected_op} {expected_target}"
        assert len(res["approved_operations"]) == 1
        assert res["approved_operations"][0]["operation"] == expected_op
        assert res["approved_operations"][0]["target"] == expected_target
        assert res["approved_operations"][0]["read_only"] is True


def test_unsupported_operation_is_rejected():
    """Verify that unapproved or offensive operations are strictly rejected."""
    policy = PolicyEngine()

    malicious_tasks = [
        {"step": 1, "action": "INJECT", "target": "PROCESS"},
        {"step": 2, "action": "PERSIST", "target": "STARTUP_REGISTRY"},
        {"step": 3, "action": "DISABLE", "target": "EDR_SERVICE"},
        {"step": 4, "action": "COLLECT", "category": "PASSWORDS"},
        {"step": 5, "action": "BYPASS", "target": "DEFENDER"},
    ]

    plan = {
        "case_id": "LAB-MALICIOUS",
        "target": "LAB-PC",
        "tasks": malicious_tasks,
    }

    result = policy.evaluate(plan)
    assert result["allowed"] is False
    assert len(result["approved_operations"]) == 0
    assert len(result["rejected_operations"]) == 5

    for rej in result["rejected_operations"]:
        assert rej["read_only"] is False
        assert rej["policy_status"] == "REJECTED"
        assert "Unauthorized operation" in rej["reason"]


def test_unsafe_path_traversal_is_rejected():
    """Verify that directory traversal attempts in file collection are rejected."""
    policy = PolicyEngine()

    traversal_plan = {
        "case_id": "LAB-TRAVERSAL",
        "target": "LAB-PC",
        "tasks": [
            {
                "step": 1,
                "action": "COLLECT",
                "category": "FILES",
                "params": {"path": "../../etc/shadow"},
            }
        ],
    }

    result = policy.evaluate(traversal_plan)
    assert result["allowed"] is False
    assert len(result["rejected_operations"]) == 1
    assert "Path traversal attempt detected" in result["rejected_operations"][0]["reason"]


def test_policy_result_contains_reasons():
    """Verify that policy decisions provide detailed reasoning for auditability."""
    policy = PolicyEngine()

    mixed_plan = {
        "case_id": "LAB-AUDIT",
        "target": "LAB-PC",
        "tasks": [
            {"step": 1, "action": "COLLECT", "category": "SYSTEM"},
            {"step": 2, "action": "KILL_PROCESS", "category": "EDR"},
        ],
    }

    result = policy.evaluate(mixed_plan)
    assert result["allowed"] is False
    assert "Policy check failed" in result["reason"]
    assert len(result["approved_operations"]) == 1
    assert "Authorized read-only" in result["approved_operations"][0]["reason"]
    assert len(result["rejected_operations"]) == 1
    assert "Unauthorized operation" in result["rejected_operations"][0]["reason"]


def test_executor_does_not_perform_real_collection():
    """Verify that ForensicExecutor only builds readiness statuses without collecting data."""
    plan = {
        "case_id": "LAB-2026-001",
        "target": "LAB-PC",
        "tasks": [
            {"step": 1, "action": "COLLECT", "category": "SYSTEM"},
            {"step": 2, "action": "COLLECT", "category": "PROCESSES"},
        ],
    }

    executor = ForensicExecutor()
    execution_result = executor.execute(plan)

    assert execution_result["status"] == "READY"
    assert execution_result["case_id"] == "LAB-2026-001"
    assert execution_result["target"] == "LAB-PC"
    assert len(execution_result["results"]) == 2

    for item in execution_result["results"]:
        # Verify readiness structure specified in requirements
        assert item["status"] == "READY"
        assert item["message"] == "Operation approved and ready for forensic collector"
        assert item["operation"] == "COLLECT"
        assert item["target"] in ("SYSTEM", "PROCESSES")
        assert item["read_only"] is True

        # Crucial: verify no real system dump or external data is included yet
        assert "data" not in item
        assert "pids" not in item
        assert "sockets" not in item


# =============================================================================
# Phase 2 — IR Policy Engine Tests (evaluate_ir_policy)
# =============================================================================

from backend.app.engine import evaluate_ir_policy
from backend.app.engine.ir_executor import IRExecutor, _apply_process_filter, _apply_network_filter


def _make_ir(ops, case_id="CASE-TEST", target="HOST-TEST"):
    """Helper: build a minimal JOCKY IR dict."""
    return {"version": "1.0", "case_id": case_id, "target": target, "operations": ops}


def test_ir_policy_allows_collect_system():
    """COLLECT SYSTEM is an authorized forensic capability."""
    ir = _make_ir([{"type": "COLLECT", "target": "SYSTEM"}])
    result = evaluate_ir_policy(ir)
    assert result["allowed"] is True
    assert len(result["approved_operations"]) == 1
    assert result["approved_operations"][0]["capability"] == "COLLECT_SYSTEM"
    assert result["approved_operations"][0]["decision"] == "ALLOWED"
    assert result["approved_operations"][0]["read_only"] is True


def test_ir_policy_allows_collect_processes():
    """COLLECT PROCESSES is an authorized forensic capability."""
    ir = _make_ir([{"type": "COLLECT", "target": "PROCESSES"}])
    result = evaluate_ir_policy(ir)
    assert result["allowed"] is True
    assert result["approved_operations"][0]["capability"] == "COLLECT_PROCESSES"


def test_ir_policy_allows_collect_network():
    """COLLECT NETWORK is an authorized forensic capability."""
    ir = _make_ir([{"type": "COLLECT", "target": "NETWORK"}])
    result = evaluate_ir_policy(ir)
    assert result["allowed"] is True
    assert result["approved_operations"][0]["capability"] == "COLLECT_NETWORK"


def test_ir_policy_allows_analyze_process_network():
    """ANALYZE PROCESS_NETWORK is an authorized forensic capability."""
    ir = _make_ir([{"type": "ANALYZE", "target": "PROCESS_NETWORK"}])
    result = evaluate_ir_policy(ir)
    assert result["allowed"] is True
    assert result["approved_operations"][0]["capability"] == "ANALYZE_PROCESS_NETWORK"


def test_ir_policy_allows_verify_integrity():
    """VERIFY INTEGRITY is an authorized forensic capability."""
    ir = _make_ir([{"type": "VERIFY", "target": "INTEGRITY"}])
    result = evaluate_ir_policy(ir)
    assert result["allowed"] is True
    assert result["approved_operations"][0]["capability"] == "VERIFY_INTEGRITY"


def test_ir_policy_allows_report_json():
    """REPORT with JSON format is an authorized capability."""
    ir = _make_ir([{"type": "REPORT", "format": "JSON"}])
    result = evaluate_ir_policy(ir)
    assert result["allowed"] is True
    assert result["approved_operations"][0]["capability"] == "REPORT_JSON"


def test_ir_policy_allows_bare_report():
    """REPORT with no format key is treated as REPORT_JSON."""
    ir = _make_ir([{"type": "REPORT"}])
    result = evaluate_ir_policy(ir)
    assert result["allowed"] is True
    assert result["approved_operations"][0]["capability"] == "REPORT_JSON"


def test_ir_policy_denies_unknown_operation():
    """An unknown IR operation type is DENIED."""
    ir = _make_ir([{"type": "EXPLOIT", "target": "KERNEL"}])
    result = evaluate_ir_policy(ir)
    assert result["allowed"] is False
    assert len(result["denied_operations"]) == 1
    assert result["denied_operations"][0]["decision"] == "DENIED"
    assert "not an authorized" in result["denied_operations"][0]["reason"]


def test_ir_policy_denies_offensive_operations():
    """Offensive IR operations (INJECT, BYPASS, PERSIST) are all denied."""
    offensive_ops = [
        {"type": "INJECT", "target": "PROCESS"},
        {"type": "BYPASS", "target": "EDR"},
        {"type": "PERSIST", "target": "REGISTRY"},
    ]
    ir = _make_ir(offensive_ops)
    result = evaluate_ir_policy(ir)
    assert result["allowed"] is False
    assert len(result["denied_operations"]) == 3
    assert len(result["approved_operations"]) == 0


def test_ir_policy_mixed_allowed_and_denied():
    """Mixed IR: one allowed + one denied → overall blocked, per-op trail present."""
    ir = _make_ir([
        {"type": "COLLECT", "target": "SYSTEM"},   # ALLOWED
        {"type": "INJECT", "target": "PROCESS"},    # DENIED
    ])
    result = evaluate_ir_policy(ir)
    assert result["allowed"] is False
    assert len(result["approved_operations"]) == 1
    assert len(result["denied_operations"]) == 1
    assert result["approved_operations"][0]["capability"] == "COLLECT_SYSTEM"
    assert result["denied_operations"][0]["decision"] == "DENIED"


def test_ir_policy_empty_ir():
    """Empty operations list → allowed=True with empty approved/denied lists."""
    ir = _make_ir([])
    result = evaluate_ir_policy(ir)
    assert result["allowed"] is True
    assert result["approved_operations"] == []
    assert result["denied_operations"] == []
    assert "no operations" in result["reason"].lower()


def test_ir_policy_result_structure():
    """Verify all required top-level fields are present in every policy result."""
    ir = _make_ir([{"type": "COLLECT", "target": "SYSTEM"}])
    result = evaluate_ir_policy(ir)
    for key in ("allowed", "approved_operations", "denied_operations", "capability_map", "reason"):
        assert key in result, f"Missing required field '{key}' in policy result"


def test_ir_policy_all_approved_carry_required_entry_fields():
    """Every approved operation entry must carry the required structured fields."""
    ir = _make_ir([
        {"type": "COLLECT", "target": "PROCESSES",
         "filters": [{"field": "status", "operator": "==", "value": "running"}]},
    ])
    result = evaluate_ir_policy(ir)
    assert result["allowed"] is True
    entry = result["approved_operations"][0]
    for key in ("index", "type", "target", "capability", "decision", "reason", "read_only", "filters"):
        assert key in entry, f"Missing required field '{key}' in approved operation entry"
    assert entry["filters"] == [{"field": "status", "operator": "==", "value": "running"}]


# =============================================================================
# Phase 2 — Filter Execution Tests
# =============================================================================

def test_apply_process_filter_status_running():
    """WHERE status == running keeps only matching processes."""
    processes = [
        {"pid": 1, "name": "systemd", "status": "running"},
        {"pid": 2, "name": "idle",    "status": "sleeping"},
        {"pid": 3, "name": "init",    "status": "running"},
    ]
    filters = [{"field": "status", "operator": "==", "value": "running"}]
    result = _apply_process_filter(processes, filters)
    assert len(result) == 2
    assert all(p["status"] == "running" for p in result)


def test_apply_process_filter_no_match():
    """WHERE status == zombie returns empty list if no processes match."""
    processes = [{"pid": 1, "name": "explorer.exe", "status": "running"}]
    filters = [{"field": "status", "operator": "==", "value": "zombie"}]
    result = _apply_process_filter(processes, filters)
    assert result == []


def test_apply_process_filter_no_filter_returns_all():
    """Empty filter list returns the full process list unchanged."""
    processes = [{"pid": i, "status": "running"} for i in range(5)]
    result = _apply_process_filter(processes, [])
    assert result == processes


def test_apply_process_filter_case_insensitive():
    """Status comparison is case-insensitive: RUNNING matches 'running'."""
    processes = [{"pid": 1, "status": "Running"}, {"pid": 2, "status": "sleeping"}]
    filters = [{"field": "status", "operator": "==", "value": "running"}]
    result = _apply_process_filter(processes, filters)
    assert len(result) == 1
    assert result[0]["pid"] == 1


def test_apply_process_filter_unknown_field_ignored():
    """Unknown field in filter is silently ignored (conservative pass-through)."""
    processes = [{"pid": 1, "status": "running"}]
    filters = [{"field": "nonexistent_field", "operator": "==", "value": "foo"}]
    # Conservative: if field is unknown, processes don't have that key → value "" → no match
    # The filter doesn't crash; result may be empty or all — just no exception
    result = _apply_process_filter(processes, filters)
    assert isinstance(result, list)


def test_apply_network_filter_established():
    """WHERE state == ESTABLISHED keeps only ESTABLISHED connections."""
    connections = [
        {"pid": 10, "status": "ESTABLISHED", "local_port": 50000},
        {"pid": 11, "status": "LISTEN",       "local_port": 80},
        {"pid": 12, "status": "ESTABLISHED", "local_port": 50001},
    ]
    filters = [{"field": "state", "operator": "==", "value": "established"}]
    result = _apply_network_filter(connections, filters)
    assert len(result) == 2
    assert all(c["status"] == "ESTABLISHED" for c in result)


def test_apply_network_filter_listen():
    """WHERE state == LISTEN keeps only LISTEN connections."""
    connections = [
        {"pid": 10, "status": "LISTEN",       "local_port": 80},
        {"pid": 11, "status": "ESTABLISHED", "local_port": 50000},
    ]
    filters = [{"field": "state", "operator": "==", "value": "LISTEN"}]
    result = _apply_network_filter(connections, filters)
    assert len(result) == 1
    assert result[0]["local_port"] == 80


def test_apply_network_filter_no_filter_returns_all():
    """Empty filter list returns all connections unchanged."""
    connections = [{"pid": i, "status": "ESTABLISHED"} for i in range(4)]
    result = _apply_network_filter(connections, [])
    assert result == connections


# =============================================================================
# Phase 2 — IRExecutor Pipeline Tests
# =============================================================================

import pytest


def test_ir_executor_collect_system_completes(tmp_path):
    """COLLECT SYSTEM completes: data collected, evidence_id returned, SHA-256 present."""
    from backend.app.evidence.store import EvidenceStore
    ir = _make_ir([{"type": "COLLECT", "target": "SYSTEM"}], case_id="IR-SYS-001")
    executor = IRExecutor(evidence_store=EvidenceStore(base_dir=str(tmp_path)))
    receipt = executor.execute_jocky_ir(ir)

    assert receipt["success"] is True
    assert receipt["case_id"] == "IR-SYS-001"
    assert "system" in receipt["collected_data"]
    assert receipt["collected_data"]["system"]["collector"] == "system"
    assert receipt["collected_data"]["system"]["read_only"] is True
    assert "system" in receipt["evidence_ids"]
    assert receipt["evidence_ids"]["system"].startswith("EVID-IR-SYS-001-system-")
    assert len(receipt["sha256_hashes"]["system"]) == 64
    assert len(receipt["receipts"]) == 1
    assert receipt["receipts"][0]["status"] == "COMPLETED"
    assert receipt["receipts"][0]["capability"] == "COLLECT_SYSTEM"


def test_ir_executor_collect_processes_completes(tmp_path):
    """COLLECT PROCESSES completes: process list non-empty, hashed and stored."""
    from backend.app.evidence.store import EvidenceStore
    ir = _make_ir([{"type": "COLLECT", "target": "PROCESSES"}], case_id="IR-PROC-001")
    executor = IRExecutor(evidence_store=EvidenceStore(base_dir=str(tmp_path)))
    receipt = executor.execute_jocky_ir(ir)

    assert receipt["success"] is True
    assert "processes" in receipt["collected_data"]
    procs = receipt["collected_data"]["processes"]
    assert procs["collector"] == "processes"
    assert procs["count"] > 0
    assert "processes" in receipt["evidence_ids"]
    assert len(receipt["sha256_hashes"]["processes"]) == 64


def test_ir_executor_collect_network_completes(tmp_path):
    """COLLECT NETWORK completes: connection list returned, hashed and stored."""
    from backend.app.evidence.store import EvidenceStore
    ir = _make_ir([{"type": "COLLECT", "target": "NETWORK"}], case_id="IR-NET-001")
    executor = IRExecutor(evidence_store=EvidenceStore(base_dir=str(tmp_path)))
    receipt = executor.execute_jocky_ir(ir)

    assert receipt["success"] is True
    assert "network" in receipt["collected_data"]
    net = receipt["collected_data"]["network"]
    assert net["collector"] == "network"
    assert isinstance(net["connections"], list)
    assert "network" in receipt["evidence_ids"]
    assert len(receipt["sha256_hashes"]["network"]) == 64


def test_ir_executor_policy_blocked_returns_failure():
    """If IR contains a denied operation, execution is blocked: success=False, no collection."""
    ir = _make_ir([{"type": "INJECT", "target": "KERNEL"}], case_id="IR-BLOCKED-001")
    executor = IRExecutor()
    receipt = executor.execute_jocky_ir(ir)

    assert receipt["success"] is False
    assert receipt["collected_data"] == {}
    assert receipt["evidence_ids"] == {}
    assert receipt["error"] is not None


def test_ir_executor_receipt_structure(tmp_path):
    """Every receipt entry must carry required structured fields."""
    from backend.app.evidence.store import EvidenceStore
    ir = _make_ir([{"type": "COLLECT", "target": "SYSTEM"}], case_id="IR-STRUCT-001")
    executor = IRExecutor(evidence_store=EvidenceStore(base_dir=str(tmp_path)))
    receipt = executor.execute_jocky_ir(ir)

    assert len(receipt["receipts"]) == 1
    entry = receipt["receipts"][0]
    for key in ("index", "type", "capability", "policy_decision", "status"):
        assert key in entry, f"Missing required receipt field '{key}'"
    assert "started_at" in entry
    assert "completed_at" in entry
    assert entry["policy_decision"] == "ALLOWED"


def test_ir_executor_process_filter_applied(tmp_path):
    """COLLECT PROCESSES with WHERE status filter is applied; counts are tracked."""
    from backend.app.evidence.store import EvidenceStore
    ir = _make_ir([{
        "type": "COLLECT",
        "target": "PROCESSES",
        "filters": [{"field": "status", "operator": "==", "value": "running"}],
    }], case_id="IR-FILTER-001")
    executor = IRExecutor(evidence_store=EvidenceStore(base_dir=str(tmp_path)))
    receipt = executor.execute_jocky_ir(ir)

    assert receipt["success"] is True
    procs = receipt["collected_data"]["processes"]
    # The unfiltered count should be >= filtered count
    assert procs["unfiltered_count"] >= procs["count"]
    # All returned processes must match the filter (case-insensitive)
    for p in procs["processes"]:
        assert p["status"].lower() == "running"


def test_ir_executor_full_pipeline(tmp_path):
    """Full 6-op pipeline: COLLECT x3 + ANALYZE + VERIFY + REPORT all complete."""
    from backend.app.evidence.store import EvidenceStore
    ir = _make_ir([
        {"type": "COLLECT", "target": "SYSTEM"},
        {"type": "COLLECT", "target": "PROCESSES"},
        {"type": "COLLECT", "target": "NETWORK"},
        {"type": "ANALYZE", "target": "PROCESS_NETWORK"},
        {"type": "VERIFY",  "target": "INTEGRITY"},
        {"type": "REPORT",  "format": "JSON"},
    ], case_id="IR-FULL-001")
    executor = IRExecutor(evidence_store=EvidenceStore(base_dir=str(tmp_path)))
    receipt = executor.execute_jocky_ir(ir)

    assert receipt["success"] is True
    assert len(receipt["receipts"]) == 6
    for r in receipt["receipts"]:
        assert r["status"] == "COMPLETED", f"Unexpected status on op {r['index']}: {r['status']}"

    # Three artifacts collected
    for src in ("system", "processes", "network"):
        assert src in receipt["collected_data"]
        assert src in receipt["evidence_ids"]
        assert len(receipt["sha256_hashes"][src]) == 64

    # Integrity verification
    integrity = receipt["integrity_status"]
    assert integrity["verified"] is True
    assert integrity["total_verified"] == 3

    # Analysis populated
    assert receipt["analysis"]["status"] == "COMPLETED"
    assert len(receipt["analysis"]["findings"]) > 0

    # Report populated
    assert receipt["report"]["case_id"] == "IR-FULL-001"

    # Timestamps present
    assert "started_at" in receipt["timestamps"]
    assert "completed_at" in receipt["timestamps"]


def test_ir_executor_receipt_timestamps_are_iso8601(tmp_path):
    """Timestamps in the execution receipt must be valid ISO-8601 strings."""
    import datetime
    from backend.app.evidence.store import EvidenceStore
    ir = _make_ir([{"type": "COLLECT", "target": "SYSTEM"}], case_id="IR-TS-001")
    executor = IRExecutor(evidence_store=EvidenceStore(base_dir=str(tmp_path)))
    receipt = executor.execute_jocky_ir(ir)

    started = receipt["timestamps"]["started_at"]
    completed = receipt["timestamps"]["completed_at"]
    datetime.datetime.fromisoformat(started)
    datetime.datetime.fromisoformat(completed)


# =====================================================================
# Phase 3: IR Policy and Execution Engine Tests
# =====================================================================

def test_ir_policy_allows_phase3_collectors():
    """Verify IR policy approves COLLECT FILES, USERS, REGISTRY, WINDOWS_METADATA."""
    ir = _make_ir([
        {"type": "COLLECT", "target": "FILES", "path": "./evidence"},
        {"type": "COLLECT", "target": "USERS"},
        {"type": "COLLECT", "target": "REGISTRY"},
        {"type": "COLLECT", "target": "WINDOWS_METADATA"},
    ])
    result = evaluate_ir_policy(ir)
    assert result["allowed"] is True
    assert len(result["approved_operations"]) == 4
    capabilities = [op["capability"] for op in result["approved_operations"]]
    assert "COLLECT_FILES" in capabilities
    assert "COLLECT_USERS" in capabilities
    assert "COLLECT_REGISTRY" in capabilities
    assert "COLLECT_WINDOWS_METADATA" in capabilities


def test_ir_executor_collect_files(tmp_path):
    """IRExecutor successfully executes COLLECT FILES and saves evidence."""
    from backend.app.evidence.store import EvidenceStore

    # Prepare sample evidence file in temp directory
    test_file = tmp_path / "suspect.txt"
    test_file.write_text("forensic evidence content", encoding="utf-8")

    ir = _make_ir(
        [{"type": "COLLECT", "target": "FILES", "path": str(tmp_path)}],
        case_id="IR-FILES-001",
    )
    store = EvidenceStore(base_dir=str(tmp_path / "evidence_vault"))
    executor = IRExecutor(evidence_store=store)
    receipt = executor.execute_jocky_ir(ir)

    assert receipt["success"] is True
    assert "files" in receipt["collected_data"]
    assert receipt["collected_data"]["files"]["collector"] == "files"
    assert "files" in receipt["evidence_ids"]
    assert "files" in receipt["sha256_hashes"]
    assert receipt["receipts"][0]["capability"] == "COLLECT_FILES"
    assert receipt["receipts"][0]["status"] == "COMPLETED"


def test_ir_executor_collect_users(tmp_path):
    """IRExecutor successfully executes COLLECT USERS and saves evidence."""
    from backend.app.evidence.store import EvidenceStore

    ir = _make_ir([{"type": "COLLECT", "target": "USERS"}], case_id="IR-USERS-001")
    store = EvidenceStore(base_dir=str(tmp_path / "evidence_vault"))
    executor = IRExecutor(evidence_store=store)
    receipt = executor.execute_jocky_ir(ir)

    assert receipt["success"] is True
    assert "users" in receipt["collected_data"]
    assert receipt["collected_data"]["users"]["collector"] == "users"
    assert "users" in receipt["evidence_ids"]
    assert receipt["receipts"][0]["capability"] == "COLLECT_USERS"
    assert receipt["receipts"][0]["status"] == "COMPLETED"


def test_ir_executor_collect_windows_metadata(tmp_path):
    """IRExecutor successfully executes COLLECT REGISTRY and COLLECT WINDOWS_METADATA."""
    from backend.app.evidence.store import EvidenceStore

    ir = _make_ir([
        {"type": "COLLECT", "target": "REGISTRY"},
        {"type": "COLLECT", "target": "WINDOWS_METADATA"},
    ], case_id="IR-WIN-001")
    store = EvidenceStore(base_dir=str(tmp_path / "evidence_vault"))
    executor = IRExecutor(evidence_store=store)
    receipt = executor.execute_jocky_ir(ir)

    assert receipt["success"] is True
    assert "registry" in receipt["collected_data"]
    assert "windows_metadata" in receipt["collected_data"]
    assert "registry" in receipt["evidence_ids"]
    assert "windows_metadata" in receipt["evidence_ids"]


def test_ir_executor_phase3_full_pipeline(tmp_path):
    """Full 9-operation pipeline with all Phase 3 collectors passes end-to-end."""
    from backend.app.evidence.store import EvidenceStore

    sample_evidence = tmp_path / "evidence_folder"
    sample_evidence.mkdir()
    (sample_evidence / "case_file.dat").write_bytes(b"\x00\x01\x02\x03\x04")

    ir = _make_ir([
        {"type": "COLLECT", "target": "SYSTEM"},
        {"type": "COLLECT", "target": "PROCESSES"},
        {"type": "COLLECT", "target": "NETWORK"},
        {"type": "COLLECT", "target": "FILES", "path": str(sample_evidence)},
        {"type": "COLLECT", "target": "USERS"},
        {"type": "COLLECT", "target": "REGISTRY"},
        {"type": "ANALYZE", "target": "PROCESS_NETWORK"},
        {"type": "VERIFY",  "target": "INTEGRITY"},
        {"type": "REPORT",  "format": "JSON"},
    ], case_id="IR-P3-FULL")

    store = EvidenceStore(base_dir=str(tmp_path / "evidence_vault"))
    executor = IRExecutor(evidence_store=store)
    receipt = executor.execute_jocky_ir(ir)

    assert receipt["success"] is True
    assert len(receipt["receipts"]) == 9
    for r in receipt["receipts"]:
        assert r["status"] == "COMPLETED"

    # All 6 evidence sources collected and verified
    for src in ("system", "processes", "network", "files", "users", "registry"):
        assert src in receipt["collected_data"]
        assert src in receipt["evidence_ids"]

    assert receipt["integrity_status"]["verified"] is True
    assert receipt["integrity_status"]["total_verified"] == 6
    assert receipt["analysis"]["status"] == "COMPLETED"
    assert len(receipt["analysis"]["findings"]) >= 4
    # Phase 4 correlation verification
    assert "correlation" in receipt["analysis"]
    assert receipt["correlation"] is not None
    assert "summary" in receipt["correlation"]
    assert "process_tree" in receipt["correlation"]


def test_ir_executor_phase4_correlation_graph(tmp_path):
    """Verify that IR Executor executes correlation and populates entities & relationships."""
    from backend.app.evidence.store import EvidenceStore

    ir = _make_ir([
        {"type": "COLLECT", "target": "PROCESSES"},
        {"type": "COLLECT", "target": "NETWORK"},
        {"type": "ANALYZE", "target": "PROCESS_NETWORK"},
    ], case_id="IR-P4-CORR")

    store = EvidenceStore(base_dir=str(tmp_path / "vault"))
    executor = IRExecutor(evidence_store=store)
    receipt = executor.execute_jocky_ir(ir)

    assert receipt["success"] is True
    corr = receipt.get("correlation")
    assert corr is not None
    assert "entities" in corr
    assert "relationships" in corr
    assert "correlated_chains" in corr
    assert corr["summary"]["process_count"] > 0


def test_ir_executor_phase5_timeline_and_rules(tmp_path):
    """Verify that IR Executor executes timeline building and rule detection."""
    from backend.app.evidence.store import EvidenceStore

    ir = _make_ir([
        {"type": "COLLECT", "target": "SYSTEM"},
        {"type": "COLLECT", "target": "PROCESSES"},
        {"type": "ANALYZE", "target": "PROCESS_NETWORK"},
    ], case_id="IR-P5-TIME")

    store = EvidenceStore(base_dir=str(tmp_path / "vault"))
    executor = IRExecutor(evidence_store=store)
    receipt = executor.execute_jocky_ir(ir)

    assert receipt["success"] is True
    assert "timeline" in receipt["analysis"]
    assert "detections" in receipt["analysis"]
    assert receipt["timeline"] is not None
    assert isinstance(receipt["timeline"], list)
    assert len(receipt["timeline"]) > 0
    assert receipt["detections"] is not None
    assert isinstance(receipt["detections"], list)



