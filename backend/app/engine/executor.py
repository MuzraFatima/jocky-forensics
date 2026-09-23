"""
JOCKY Forensic Execution Engine & Pipeline Runner

Orchestrates the dispatch of policy-approved operations:
- Pre-execution policy enforcement
- Read-only forensic collectors invocation (SYSTEM, PROCESSES, NETWORK)
- Immutable Evidence Store recording & SHA-256 calculation
- Cryptographic integrity verification & Chain of Custody logging
- Heuristic analysis and report summary generation
"""

import datetime
from typing import Any, Dict, List, Optional

from backend.app.collectors.files import collect_files_info
from backend.app.collectors.network import collect_network_info
from backend.app.collectors.processes import collect_process_info
from backend.app.collectors.system import collect_system_info
from backend.app.collectors.users import collect_users_info
from backend.app.collectors.windows_metadata import (
    collect_registry_info,
    collect_windows_metadata,
)
from backend.app.evidence.store import EvidenceStore
from .policy import PolicyEngine


class ForensicExecutor:
    """Orchestrates forensic tasks approved by the policy engine."""

    def __init__(self, policy_engine: Optional[PolicyEngine] = None, evidence_store: Optional[EvidenceStore] = None):
        self.policy_engine = policy_engine or PolicyEngine()
        self.evidence_store = evidence_store or EvidenceStore()

    def execute(self, execution_plan: Dict[str, Any]) -> Dict[str, Any]:
        """
        Validates the execution plan through the policy engine and simulates
        orchestration readiness without performing real data collection.
        Maintains backward compatibility with Phase 2/3 test contracts.
        """
        # 1. Run policy evaluation
        policy_result = self.policy_engine.evaluate(execution_plan)

        if not policy_result["allowed"]:
            return {
                "status": "BLOCKED",
                "case_id": execution_plan.get("case_id"),
                "target": execution_plan.get("target"),
                "message": "Execution halted: plan contains policy violations.",
                "policy_result": policy_result,
                "results": [],
            }

        # 2. Build structured readiness results for all approved operations
        results: List[Dict[str, Any]] = []

        for op in policy_result["approved_operations"]:
            res_item: Dict[str, Any] = {
                "step": op.get("step"),
                "status": "READY",
                "message": "Operation approved and ready for forensic collector",
                "operation": op.get("operation"),
                "target": op.get("target"),
                "read_only": op.get("read_only", True),
            }
            if op.get("params"):
                res_item["params"] = op["params"]
            results.append(res_item)

        return {
            "status": "READY",
            "case_id": execution_plan.get("case_id"),
            "target": execution_plan.get("target"),
            "message": "All operations approved by policy engine. Ready for collector dispatch.",
            "policy_result": policy_result,
            "results": results,
            "total_operations": len(results),
        }

    def run_investigation(
        self,
        execution_plan: Dict[str, Any],
        store: Optional[EvidenceStore] = None,
    ) -> Dict[str, Any]:
        """
        Executes an end-to-end investigation pipeline for an approved execution plan:
        1. Enforces policy authorization
        2. Executes read-only collectors (SYSTEM, PROCESSES, NETWORK)
        3. Persists each artifact to EvidenceStore with SHA-256 hash & custody log
        4. Performs read-only heuristic analysis
        5. Verifies cryptographic integrity across stored evidence
        6. Generates report summary
        """
        started_at = datetime.datetime.now(datetime.timezone.utc).isoformat()
        evidence_store = store or self.evidence_store

        # 1. Evaluate policy
        policy_result = self.policy_engine.evaluate(execution_plan)
        if not policy_result["allowed"]:
            return {
                "success": False,
                "status": "BLOCKED",
                "case_id": execution_plan.get("case_id"),
                "target": execution_plan.get("target"),
                "message": "Investigation blocked by policy engine.",
                "policy_result": policy_result,
                "execution_plan": execution_plan,
                "collected_data": {},
                "evidence_ids": {},
                "sha256_hashes": {},
                "integrity_status": {"verified": False, "details": []},
                "timestamps": {"started_at": started_at, "completed_at": started_at},
            }

        case_id = execution_plan.get("case_id", "DEFAULT-CASE")
        target = execution_plan.get("target", "LOCAL-HOST")

        collected_data: Dict[str, Any] = {}
        evidence_ids: Dict[str, str] = {}
        sha256_hashes: Dict[str, str] = {}
        integrity_details: List[Dict[str, Any]] = []
        analysis_result: Dict[str, Any] = {}
        report_summary: Dict[str, Any] = {}

        tasks = execution_plan.get("tasks", [])

        for task in tasks:
            action = task.get("action", "").upper()
            category = (task.get("category") or "").upper()

            # A. Forensic Collectors
            if action == "COLLECT":
                if category == "SYSTEM":
                    data = collect_system_info()
                    collected_data["system"] = data
                    record = evidence_store.save_evidence(
                        case_id=case_id,
                        source="system",
                        data=data,
                        who="JOCKY Forensic Engine",
                        why=f"Automated system forensic acquisition for {case_id}",
                    )
                    evidence_ids["system"] = record["evidence_id"]
                    sha256_hashes["system"] = record["sha256"]

                elif category == "PROCESSES":
                    data = collect_process_info()
                    collected_data["processes"] = data
                    record = evidence_store.save_evidence(
                        case_id=case_id,
                        source="processes",
                        data=data,
                        who="JOCKY Forensic Engine",
                        why=f"Automated process forensic acquisition for {case_id}",
                    )
                    evidence_ids["processes"] = record["evidence_id"]
                    sha256_hashes["processes"] = record["sha256"]

                elif category == "NETWORK":
                    data = collect_network_info()
                    collected_data["network"] = data
                    record = evidence_store.save_evidence(
                        case_id=case_id,
                        source="network",
                        data=data,
                        who="JOCKY Forensic Engine",
                        why=f"Automated network forensic acquisition for {case_id}",
                    )
                    evidence_ids["network"] = record["evidence_id"]
                    sha256_hashes["network"] = record["sha256"]

                elif category == "FILES":
                    target_path = task.get("target_path") or task.get("path")
                    data = collect_files_info(target_path=target_path)
                    collected_data["files"] = data
                    record = evidence_store.save_evidence(
                        case_id=case_id,
                        source="files",
                        data=data,
                        who="JOCKY Forensic Engine",
                        why=f"Automated files forensic acquisition for {case_id}",
                    )
                    evidence_ids["files"] = record["evidence_id"]
                    sha256_hashes["files"] = record["sha256"]

                elif category == "USERS":
                    data = collect_users_info()
                    collected_data["users"] = data
                    record = evidence_store.save_evidence(
                        case_id=case_id,
                        source="users",
                        data=data,
                        who="JOCKY Forensic Engine",
                        why=f"Automated users forensic acquisition for {case_id}",
                    )
                    evidence_ids["users"] = record["evidence_id"]
                    sha256_hashes["users"] = record["sha256"]

                elif category in ("REGISTRY", "WINDOWS_METADATA"):
                    is_reg = category == "REGISTRY"
                    source_name = "registry" if is_reg else "windows_metadata"
                    data = collect_registry_info() if is_reg else collect_windows_metadata()
                    collected_data[source_name] = data
                    record = evidence_store.save_evidence(
                        case_id=case_id,
                        source=source_name,
                        data=data,
                        who="JOCKY Forensic Engine",
                        why=f"Automated Windows metadata acquisition for {case_id}",
                    )
                    evidence_ids[source_name] = record["evidence_id"]
                    sha256_hashes[source_name] = record["sha256"]

            # B. Forensic Analysis Engine
            elif action == "ANALYZE":
                findings: List[str] = []
                if "system" in collected_data:
                    sys_info = collected_data["system"]
                    findings.append(f"Operating System identified as {sys_info.get('os')} ({sys_info.get('os_version')}) on {sys_info.get('hostname')}.")
                if "processes" in collected_data:
                    proc_info = collected_data["processes"]
                    findings.append(f"Enumerated {proc_info.get('count', 0)} active processes under inspection.")
                if "network" in collected_data:
                    net_info = collected_data["network"]
                    listen_count = sum(1 for c in net_info.get("connections", []) if c.get("status") == "LISTEN")
                    est_count = sum(1 for c in net_info.get("connections", []) if c.get("status") == "ESTABLISHED")
                    findings.append(f"Network discovery observed {net_info.get('count', 0)} total sockets ({listen_count} listening, {est_count} established).")

                analysis_result = {
                    "status": "COMPLETED",
                    "triage_verdict": "BENIGN / BASELINE_COLLECTED",
                    "findings": findings,
                    "artifacts_analyzed": list(collected_data.keys()),
                }

            # C. Cryptographic Integrity Verification
            elif action == "VERIFY":
                for source_name, evid_id in list(evidence_ids.items()):
                    verification_res = evidence_store.verify_evidence(
                        evidence_id=evid_id,
                        who="JOCKY Integrity Engine",
                        why=f"Automated script-directed integrity verification for {case_id}",
                    )
                    integrity_details.append({
                        "source": source_name,
                        "evidence_id": evid_id,
                        "valid": verification_res["valid"],
                        "stored_hash": verification_res["stored_hash"],
                        "recomputed_hash": verification_res["recomputed_hash"],
                    })

            # D. Forensic Report Generation
            elif action == "REPORT":
                report_summary = {
                    "case_id": case_id,
                    "target": target,
                    "generated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                    "artifacts_collected": len(evidence_ids),
                    "integrity_verified": all(d["valid"] for d in integrity_details) if integrity_details else True,
                    "summary": f"Forensic collection completed for case {case_id} on target {target}.",
                }

        completed_at = datetime.datetime.now(datetime.timezone.utc).isoformat()
        overall_integrity = (
            all(d["valid"] for d in integrity_details) if integrity_details else (True if evidence_ids else None)
        )

        return {
            "success": True,
            "status": "COMPLETED",
            "case_id": case_id,
            "target": target,
            "execution_plan": execution_plan,
            "policy_result": policy_result,
            "collected_data": collected_data,
            "evidence_ids": evidence_ids,
            "sha256_hashes": sha256_hashes,
            "integrity_status": {
                "verified": overall_integrity,
                "total_verified": len(integrity_details),
                "details": integrity_details,
            },
            "analysis": analysis_result,
            "report": report_summary,
            "timestamps": {
                "started_at": started_at,
                "completed_at": completed_at,
            },
        }
