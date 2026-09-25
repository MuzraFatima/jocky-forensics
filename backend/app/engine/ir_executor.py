"""
JOCKY Phase-2 IR Execution Engine

Executes a validated JOCKY IR through the Phase-2 pipeline:

    JOCKY IR
       ↓
    IR Policy Check  (ir_policy.evaluate_ir_policy)
       ↓
    Execution Plan   (per-operation readiness + filter metadata)
       ↓
    Existing Collectors  (system / process / network)
       ↓
    Post-collection Filter Application
       ↓
    Evidence Store  (SHA-256 + chain of custody)
       ↓
    Execution Receipt

The engine is deliberately READ-ONLY and FORENSIC:
  - It invokes only the three existing read-only collectors.
  - It applies WHERE filters post-collection (no selective fetching).
  - It stores every collected artifact in the evidence store.
  - It never modifies, deletes, kills, or alters any system resource.

Phase 3+ (report rendering, cross-case correlation) is out of scope here.
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
from backend.app.analysis import (
    build_forensic_timeline,
    correlate_evidence,
    evaluate_forensic_rules,
)
from backend.app.evidence.store import EvidenceStore
from backend.app.reporting import ForensicReportBuilder

from .ir_policy import evaluate_ir_policy


# ---------------------------------------------------------------------------
# Filter helpers — apply WHERE clauses post-collection
# ---------------------------------------------------------------------------

def _apply_process_filter(
    processes: List[Dict[str, Any]],
    filters: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """
    Filter a process list using WHERE predicates.

    Supported fields:  status
    Supported operators: ==

    Comparison is case-insensitive on both sides.
    Unknown fields or operators are silently ignored (conservative).
    """
    if not filters:
        return processes

    result = processes
    for flt in filters:
        field = flt.get("field", "").lower()
        operator = flt.get("operator", "")
        value = flt.get("value", "").lower()

        if operator != "==" or not field or not value:
            continue

        result = [
            p for p in result
            if str(p.get(field, "")).lower() == value
        ]
    return result


def _apply_network_filter(
    connections: List[Dict[str, Any]],
    filters: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """
    Filter a network connection list using WHERE predicates.

    Supported fields:  state (maps to the 'status' key in collector output)
    Supported operators: ==
    """
    if not filters:
        return connections

    result = connections
    for flt in filters:
        field = flt.get("field", "").lower()
        operator = flt.get("operator", "")
        value = flt.get("value", "").upper()

        if operator != "==" or not field or not value:
            continue

        # 'state' in JOCKY DSL maps to 'status' in the network collector output
        collector_field = "status" if field == "state" else field

        result = [
            c for c in result
            if str(c.get(collector_field, "")).upper() == value
        ]
    return result


# ---------------------------------------------------------------------------
# Operation receipt builder
# ---------------------------------------------------------------------------

def _receipt_entry(
    index: int,
    op_type: str,
    capability: str,
    decision: str,
    status: str,
    record_count: Optional[int] = None,
    evidence_id: Optional[str] = None,
    sha256: Optional[str] = None,
    filters_applied: Optional[List[Dict[str, Any]]] = None,
    filter_matched_count: Optional[int] = None,
    error: Optional[str] = None,
    started_at: Optional[str] = None,
    completed_at: Optional[str] = None,
) -> Dict[str, Any]:
    """Build a standardized per-operation receipt entry."""
    entry: Dict[str, Any] = {
        "index": index,
        "type": op_type,
        "capability": capability,
        "policy_decision": decision,
        "status": status,
    }
    if record_count is not None:
        entry["record_count"] = record_count
    if evidence_id is not None:
        entry["evidence_id"] = evidence_id
    if sha256 is not None:
        entry["sha256"] = sha256
    if filters_applied:
        entry["filters_applied"] = filters_applied
    if filter_matched_count is not None:
        entry["filter_matched_count"] = filter_matched_count
    if error is not None:
        entry["error"] = error
    if started_at is not None:
        entry["started_at"] = started_at
    if completed_at is not None:
        entry["completed_at"] = completed_at
    return entry


# ---------------------------------------------------------------------------
# Main IR executor
# ---------------------------------------------------------------------------

class IRExecutor:
    """
    Phase-2 execution engine that runs a JOCKY IR through the forensic pipeline.

    Usage::

        executor = IRExecutor()
        receipt = executor.execute_jocky_ir(ir)
    """

    def __init__(self, evidence_store: Optional[EvidenceStore] = None):
        self.evidence_store = evidence_store or EvidenceStore()

    def execute_jocky_ir(self, ir: Dict[str, Any]) -> Dict[str, Any]:
        """
        Execute a JOCKY IR dict through the Phase-2 pipeline.

        Args:
            ir: A JOCKY IR dict as produced by :func:`backend.app.language.ir.build_ir`.

        Returns:
            An Execution Receipt dict::

                {
                    "success": bool,
                    "case_id": str,
                    "target": str,
                    "ir_version": str,
                    "policy_result": {...},
                    "receipts": [{...}, ...],
                    "collected_data": {category: data_dict, ...},
                    "evidence_ids": {category: evidence_id, ...},
                    "sha256_hashes": {category: digest, ...},
                    "integrity_status": {...},
                    "analysis": {...},
                    "report": {...},
                    "timestamps": {"started_at": ..., "completed_at": ...},
                    "error": str | None
                }
        """
        started_at = datetime.datetime.now(datetime.timezone.utc).isoformat()

        case_id: str = ir.get("case_id", "UNKNOWN-CASE")
        target: str  = ir.get("target",  "UNKNOWN-TARGET")
        ir_version: str = ir.get("version", "1.0")

        # ── Step 1: IR Policy Check ─────────────────────────────────────────
        policy_result = evaluate_ir_policy(ir)

        if not policy_result["allowed"]:
            return {
                "success": False,
                "case_id": case_id,
                "target": target,
                "ir_version": ir_version,
                "policy_result": policy_result,
                "receipts": [],
                "collected_data": {},
                "evidence_ids": {},
                "sha256_hashes": {},
                "integrity_status": {"verified": False, "details": []},
                "analysis": {},
                "report": {},
                "timestamps": {
                    "started_at": started_at,
                    "completed_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                },
                "error": f"Execution blocked by policy: {policy_result['reason']}",
            }

        # Build a quick lookup: index → approved operation entry
        approved_by_index: Dict[int, Dict[str, Any]] = {
            op["index"]: op for op in policy_result["approved_operations"]
        }

        # ── Step 2: Execute each IR operation in order ─────────────────────
        receipts: List[Dict[str, Any]] = []
        collected_data: Dict[str, Any] = {}
        evidence_ids: Dict[str, str] = {}
        sha256_hashes: Dict[str, str] = {}
        integrity_details: List[Dict[str, Any]] = []
        analysis_result: Dict[str, Any] = {}
        report_summary: Dict[str, Any] = {}

        for idx, op in enumerate(ir.get("operations", [])):
            op_type = op.get("type", "").upper()
            op_target = (op.get("target") or "").upper()
            op_filters = op.get("filters", [])
            op_format  = op.get("format", "JSON")

            approved_entry = approved_by_index.get(idx)
            if approved_entry is None:
                # Denied operation — record and skip
                receipts.append(_receipt_entry(
                    index=idx,
                    op_type=op_type,
                    capability=f"UNKNOWN_{op_type}",
                    decision="DENIED",
                    status="SKIPPED",
                    error="Operation denied by policy engine.",
                ))
                continue

            capability = approved_entry["capability"]
            op_start = datetime.datetime.now(datetime.timezone.utc).isoformat()

            # ── COLLECT SYSTEM ──────────────────────────────────────────────
            if capability == "COLLECT_SYSTEM":
                try:
                    data = collect_system_info()
                    collected_data["system"] = data
                    record = self.evidence_store.save_evidence(
                        case_id=case_id,
                        source="system",
                        data=data,
                        who="JOCKY Phase-2 IR Executor",
                        why=f"IR-directed system forensic acquisition for case {case_id}",
                    )
                    evidence_ids["system"] = record["evidence_id"]
                    sha256_hashes["system"] = record["sha256"]
                    receipts.append(_receipt_entry(
                        index=idx,
                        op_type=op_type,
                        capability=capability,
                        decision="ALLOWED",
                        status="COMPLETED",
                        record_count=1,
                        evidence_id=record["evidence_id"],
                        sha256=record["sha256"],
                        started_at=op_start,
                        completed_at=datetime.datetime.now(datetime.timezone.utc).isoformat(),
                    ))
                except Exception as exc:
                    receipts.append(_receipt_entry(
                        index=idx,
                        op_type=op_type,
                        capability=capability,
                        decision="ALLOWED",
                        status="ERROR",
                        error=str(exc),
                        started_at=op_start,
                        completed_at=datetime.datetime.now(datetime.timezone.utc).isoformat(),
                    ))

            # ── COLLECT PROCESSES ────────────────────────────────────────────
            elif capability == "COLLECT_PROCESSES":
                try:
                    raw = collect_process_info()
                    all_procs = raw.get("processes", [])
                    filtered_procs = _apply_process_filter(all_procs, op_filters)

                    # Build the stored artifact with filtered processes
                    data: Dict[str, Any] = {
                        **raw,
                        "processes": filtered_procs,
                        "count": len(filtered_procs),
                        "unfiltered_count": len(all_procs),
                        "filters_applied": op_filters,
                    }
                    collected_data["processes"] = data
                    record = self.evidence_store.save_evidence(
                        case_id=case_id,
                        source="processes",
                        data=data,
                        who="JOCKY Phase-2 IR Executor",
                        why=f"IR-directed process forensic acquisition for case {case_id}",
                    )
                    evidence_ids["processes"] = record["evidence_id"]
                    sha256_hashes["processes"] = record["sha256"]
                    receipts.append(_receipt_entry(
                        index=idx,
                        op_type=op_type,
                        capability=capability,
                        decision="ALLOWED",
                        status="COMPLETED",
                        record_count=len(filtered_procs),
                        evidence_id=record["evidence_id"],
                        sha256=record["sha256"],
                        filters_applied=op_filters or None,
                        filter_matched_count=len(filtered_procs) if op_filters else None,
                        started_at=op_start,
                        completed_at=datetime.datetime.now(datetime.timezone.utc).isoformat(),
                    ))
                except Exception as exc:
                    receipts.append(_receipt_entry(
                        index=idx,
                        op_type=op_type,
                        capability=capability,
                        decision="ALLOWED",
                        status="ERROR",
                        error=str(exc),
                        started_at=op_start,
                        completed_at=datetime.datetime.now(datetime.timezone.utc).isoformat(),
                    ))

            # ── COLLECT NETWORK ──────────────────────────────────────────────
            elif capability == "COLLECT_NETWORK":
                try:
                    raw = collect_network_info()
                    all_conns = raw.get("connections", [])
                    filtered_conns = _apply_network_filter(all_conns, op_filters)

                    data = {
                        **raw,
                        "connections": filtered_conns,
                        "count": len(filtered_conns),
                        "unfiltered_count": len(all_conns),
                        "filters_applied": op_filters,
                    }
                    collected_data["network"] = data
                    record = self.evidence_store.save_evidence(
                        case_id=case_id,
                        source="network",
                        data=data,
                        who="JOCKY Phase-2 IR Executor",
                        why=f"IR-directed network forensic acquisition for case {case_id}",
                    )
                    evidence_ids["network"] = record["evidence_id"]
                    sha256_hashes["network"] = record["sha256"]
                    receipts.append(_receipt_entry(
                        index=idx,
                        op_type=op_type,
                        capability=capability,
                        decision="ALLOWED",
                        status="COMPLETED",
                        record_count=len(filtered_conns),
                        evidence_id=record["evidence_id"],
                        sha256=record["sha256"],
                        filters_applied=op_filters or None,
                        filter_matched_count=len(filtered_conns) if op_filters else None,
                        started_at=op_start,
                        completed_at=datetime.datetime.now(datetime.timezone.utc).isoformat(),
                    ))
                except Exception as exc:
                    receipts.append(_receipt_entry(
                        index=idx,
                        op_type=op_type,
                        capability=capability,
                        decision="ALLOWED",
                        status="ERROR",
                        error=str(exc),
                        started_at=op_start,
                        completed_at=datetime.datetime.now(datetime.timezone.utc).isoformat(),
                    ))

            # ── COLLECT FILES ────────────────────────────────────────────────
            elif capability == "COLLECT_FILES":
                try:
                    target_path = op.get("path")
                    data = collect_files_info(target_path=target_path)
                    collected_data["files"] = data
                    record = self.evidence_store.save_evidence(
                        case_id=case_id,
                        source="files",
                        data=data,
                        who="JOCKY Phase-3 IR Executor",
                        why=f"IR-directed file forensic acquisition for case {case_id}",
                    )
                    evidence_ids["files"] = record["evidence_id"]
                    sha256_hashes["files"] = record["sha256"]
                    receipts.append(_receipt_entry(
                        index=idx,
                        op_type=op_type,
                        capability=capability,
                        decision="ALLOWED",
                        status="COMPLETED",
                        record_count=data.get("count", 0),
                        evidence_id=record["evidence_id"],
                        sha256=record["sha256"],
                        started_at=op_start,
                        completed_at=datetime.datetime.now(datetime.timezone.utc).isoformat(),
                    ))
                except Exception as exc:
                    receipts.append(_receipt_entry(
                        index=idx,
                        op_type=op_type,
                        capability=capability,
                        decision="ALLOWED",
                        status="ERROR",
                        error=str(exc),
                        started_at=op_start,
                        completed_at=datetime.datetime.now(datetime.timezone.utc).isoformat(),
                    ))

            # ── COLLECT USERS ────────────────────────────────────────────────
            elif capability == "COLLECT_USERS":
                try:
                    data = collect_users_info()
                    collected_data["users"] = data
                    record = self.evidence_store.save_evidence(
                        case_id=case_id,
                        source="users",
                        data=data,
                        who="JOCKY Phase-3 IR Executor",
                        why=f"IR-directed users/sessions forensic acquisition for case {case_id}",
                    )
                    evidence_ids["users"] = record["evidence_id"]
                    sha256_hashes["users"] = record["sha256"]
                    receipts.append(_receipt_entry(
                        index=idx,
                        op_type=op_type,
                        capability=capability,
                        decision="ALLOWED",
                        status="COMPLETED",
                        record_count=data.get("count", 0),
                        evidence_id=record["evidence_id"],
                        sha256=record["sha256"],
                        started_at=op_start,
                        completed_at=datetime.datetime.now(datetime.timezone.utc).isoformat(),
                    ))
                except Exception as exc:
                    receipts.append(_receipt_entry(
                        index=idx,
                        op_type=op_type,
                        capability=capability,
                        decision="ALLOWED",
                        status="ERROR",
                        error=str(exc),
                        started_at=op_start,
                        completed_at=datetime.datetime.now(datetime.timezone.utc).isoformat(),
                    ))

            # ── COLLECT REGISTRY / WINDOWS_METADATA ──────────────────────────
            elif capability in ("COLLECT_REGISTRY", "COLLECT_WINDOWS_METADATA"):
                try:
                    is_reg = capability == "COLLECT_REGISTRY"
                    source_name = "registry" if is_reg else "windows_metadata"
                    data = collect_registry_info() if is_reg else collect_windows_metadata()
                    collected_data[source_name] = data
                    record = self.evidence_store.save_evidence(
                        case_id=case_id,
                        source=source_name,
                        data=data,
                        who="JOCKY Phase-3 IR Executor",
                        why=f"IR-directed Windows forensic metadata acquisition for case {case_id}",
                    )
                    evidence_ids[source_name] = record["evidence_id"]
                    sha256_hashes[source_name] = record["sha256"]
                    receipts.append(_receipt_entry(
                        index=idx,
                        op_type=op_type,
                        capability=capability,
                        decision="ALLOWED",
                        status="COMPLETED",
                        record_count=data.get("count", 0),
                        evidence_id=record["evidence_id"],
                        sha256=record["sha256"],
                        started_at=op_start,
                        completed_at=datetime.datetime.now(datetime.timezone.utc).isoformat(),
                    ))
                except Exception as exc:
                    receipts.append(_receipt_entry(
                        index=idx,
                        op_type=op_type,
                        capability=capability,
                        decision="ALLOWED",
                        status="ERROR",
                        error=str(exc),
                        started_at=op_start,
                        completed_at=datetime.datetime.now(datetime.timezone.utc).isoformat(),
                    ))

            # ── ANALYZE PROCESS_NETWORK ──────────────────────────────────────
            elif capability == "ANALYZE_PROCESS_NETWORK":
                findings: List[str] = []
                if "system" in collected_data:
                    sys = collected_data["system"]
                    findings.append(
                        f"Host: {sys.get('hostname')} | OS: {sys.get('os')} {sys.get('os_version')} | "
                        f"Arch: {sys.get('architecture')}"
                    )
                if "processes" in collected_data:
                    p = collected_data["processes"]
                    findings.append(
                        f"Process inventory: {p.get('count', 0)} processes"
                        + (f" (filtered from {p.get('unfiltered_count', p.get('count', 0))} total)"
                           if p.get("unfiltered_count") is not None and p.get("unfiltered_count") != p.get("count") else "")
                        + " — read-only enumeration, no injection or modification."
                    )
                if "network" in collected_data:
                    n = collected_data["network"]
                    all_conns_in_data = n.get("connections", [])
                    listen = sum(1 for c in all_conns_in_data if c.get("status") == "LISTEN")
                    est    = sum(1 for c in all_conns_in_data if c.get("status") == "ESTABLISHED")
                    findings.append(
                        f"Network sockets: {n.get('count', 0)} connections"
                        + (f" (filtered from {n.get('unfiltered_count', n.get('count', 0))} total)"
                           if n.get("unfiltered_count") is not None and n.get("unfiltered_count") != n.get("count") else "")
                        + f" — {listen} LISTEN, {est} ESTABLISHED."
                    )

                # Simple cross-artifact correlation
                if "processes" in collected_data and "network" in collected_data:
                    proc_pids = {p["pid"] for p in collected_data["processes"].get("processes", []) if p.get("pid")}
                    net_pids  = {c["pid"] for c in collected_data["network"].get("connections", []) if c.get("pid")}
                    overlapping = proc_pids & net_pids
                    findings.append(
                        f"Process-Network correlation: {len(overlapping)} process(es) have active network sockets."
                    )

                if "files" in collected_data:
                    f_data = collected_data["files"]
                    summary = f_data.get("summary", {})
                    findings.append(
                        f"Filesystem forensics: {f_data.get('count', 0)} files inspected "
                        f"({summary.get('executables_count', 0)} executable(s), "
                        f"{f_data.get('process_binaries_count', 0)} process binary signatures verified)."
                    )

                if "users" in collected_data:
                    u_data = collected_data["users"]
                    cu = u_data.get("current_user", {})
                    findings.append(
                        f"User identity: {cu.get('username')} on {cu.get('domain')} "
                        f"(Admin: {cu.get('is_admin')}) | "
                        f"{u_data.get('active_sessions_count', len(u_data.get('active_sessions', [])))} active session(s)."
                    )

                if "windows_metadata" in collected_data or "registry" in collected_data:
                    wm_data = collected_data.get("windows_metadata") or collected_data.get("registry", {})
                    autoruns_cnt = wm_data.get("autoruns_count", len(wm_data.get("autoruns", [])))
                    findings.append(
                        f"Windows persistence: {autoruns_cnt} autorun registry key(s) verified."
                    )

                # Phase 4 Forensic Correlation
                correlation_result = None
                try:
                    correlation_result = correlate_evidence(collected_data)
                    summary = correlation_result.get("summary", {})
                    findings.append(
                        f"Forensic Correlation Graph: {summary.get('total_entities', 0)} entities "
                        f"({summary.get('process_count', 0)} procs, {summary.get('network_count', 0)} sockets, "
                        f"{summary.get('file_count', 0)} files, {summary.get('user_count', 0)} users) "
                        f"with {summary.get('total_relationships', 0)} relationships and "
                        f"{summary.get('correlated_chains_count', 0)} process chains."
                    )
                except Exception as corr_exc:
                    correlation_result = {"error": str(corr_exc)}

                # Phase 5 Forensic Timeline & Heuristic Analysis
                timeline_result = None
                detections_result = None
                try:
                    # Enrich with evidence IDs if available
                    data_with_ids = {**collected_data, "evidence_ids": evidence_ids}
                    timeline_result = build_forensic_timeline(data_with_ids)
                    findings.append(
                        f"Forensic Timeline: {len(timeline_result)} chronological events normalized and ordered."
                    )
                except Exception as tl_exc:
                    timeline_result = {"error": str(tl_exc)}

                try:
                    detections_result = evaluate_forensic_rules(collected_data)
                    high_cnt = sum(1 for d in detections_result if d.get("severity") == "HIGH")
                    med_cnt  = sum(1 for d in detections_result if d.get("severity") == "MEDIUM")
                    findings.append(
                        f"Heuristic Rule Analysis: {len(detections_result)} anomaly detection(s) "
                        f"({high_cnt} HIGH, {med_cnt} MEDIUM)."
                    )
                except Exception as rule_exc:
                    detections_result = {"error": str(rule_exc)}

                analysis_result = {
                    "status": "COMPLETED",
                    "capability": "ANALYZE_PROCESS_NETWORK",
                    "triage_verdict": "BASELINE_COLLECTED",
                    "findings": findings,
                    "artifacts_analyzed": list(collected_data.keys()),
                    "correlation": correlation_result,
                    "timeline": timeline_result,
                    "detections": detections_result,
                }
                receipts.append(_receipt_entry(
                    index=idx,
                    op_type=op_type,
                    capability=capability,
                    decision="ALLOWED",
                    status="COMPLETED",
                    record_count=len(findings),
                    started_at=op_start,
                    completed_at=datetime.datetime.now(datetime.timezone.utc).isoformat(),
                ))

            # ── VERIFY INTEGRITY ─────────────────────────────────────────────
            elif capability == "VERIFY_INTEGRITY":
                verify_start = op_start
                for source_name, evid_id in list(evidence_ids.items()):
                    try:
                        vr = self.evidence_store.verify_evidence(
                            evidence_id=evid_id,
                            who="JOCKY Phase-2 Integrity Verifier",
                            why=f"IR-directed integrity verification for case {case_id}",
                        )
                        integrity_details.append({
                            "source": source_name,
                            "evidence_id": evid_id,
                            "valid": vr["valid"],
                            "stored_hash": vr["stored_hash"],
                            "recomputed_hash": vr["recomputed_hash"],
                        })
                    except Exception as exc:
                        integrity_details.append({
                            "source": source_name,
                            "evidence_id": evid_id,
                            "valid": False,
                            "error": str(exc),
                        })

                all_valid = all(d.get("valid", False) for d in integrity_details)
                receipts.append(_receipt_entry(
                    index=idx,
                    op_type=op_type,
                    capability=capability,
                    decision="ALLOWED",
                    status="COMPLETED",
                    record_count=len(integrity_details),
                    started_at=verify_start,
                    completed_at=datetime.datetime.now(datetime.timezone.utc).isoformat(),
                ))

            # ── REPORT (JSON / HTML / MD) ────────────────────────────────────
            elif capability in ("REPORT_JSON", "REPORT_HTML", "REPORT_MD"):
                fmt = (op_format or "JSON").upper()
                if capability == "REPORT_HTML":
                    fmt = "HTML"
                elif capability == "REPORT_MD":
                    fmt = "MD"

                builder = ForensicReportBuilder(
                    case_id=case_id,
                    target=target,
                    execution_id=ir.get("execution_id"),
                )
                rep_data = builder.build_report_data(
                    collected_data=collected_data,
                    correlation=analysis_result.get("correlation"),
                    timeline=analysis_result.get("timeline"),
                    detections=analysis_result.get("detections"),
                    evidence_ids=evidence_ids,
                    sha256_hashes=sha256_hashes,
                )

                if fmt == "HTML":
                    rendered_content = builder.generate_html(rep_data)
                elif fmt in ("MD", "MARKDOWN"):
                    rendered_content = builder.generate_markdown(rep_data)
                else:
                    rendered_content = builder.generate_json(rep_data)

                saved_path = builder.save_report(rendered_content, fmt)

                report_summary = {
                    "case_id": case_id,
                    "target": target,
                    "format": fmt,
                    "generated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                    "artifacts_collected": len(evidence_ids),
                    "integrity_verified": all(d.get("valid", False) for d in integrity_details) if integrity_details else True,
                    "summary": f"Forensic investigation completed for case {case_id} on target {target}.",
                    "evidence_ids": evidence_ids,
                    "sha256_hashes": sha256_hashes,
                    "report_data": rep_data,
                    "content": rendered_content,
                    "saved_path": str(saved_path),
                    "attestation": rep_data.get("attestation"),
                }
                receipts.append(_receipt_entry(
                    index=idx,
                    op_type=op_type,
                    capability=capability,
                    decision="ALLOWED",
                    status="COMPLETED",
                    started_at=op_start,
                    completed_at=datetime.datetime.now(datetime.timezone.utc).isoformat(),
                ))

        # ── Step 3: Assemble final execution receipt ────────────────────────
        completed_at = datetime.datetime.now(datetime.timezone.utc).isoformat()
        overall_integrity = (
            all(d.get("valid", False) for d in integrity_details)
            if integrity_details
            else (True if evidence_ids else None)
        )

        all_completed = all(r["status"] in ("COMPLETED", "SKIPPED") for r in receipts)

        return {
            "success": all_completed,
            "case_id": case_id,
            "target": target,
            "ir_version": ir_version,
            "policy_result": policy_result,
            "receipts": receipts,
            "collected_data": collected_data,
            "evidence_ids": evidence_ids,
            "sha256_hashes": sha256_hashes,
            "integrity_status": {
                "verified": overall_integrity,
                "total_verified": len(integrity_details),
                "details": integrity_details,
            },
            "analysis": analysis_result,
            "correlation": analysis_result.get("correlation") if analysis_result else None,
            "timeline": analysis_result.get("timeline") if analysis_result else None,
            "detections": analysis_result.get("detections") if analysis_result else None,
            "report": report_summary,
            "timestamps": {
                "started_at": started_at,
                "completed_at": completed_at,
            },
            "error": None,
        }
