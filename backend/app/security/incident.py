"""
JOCKY Forensic Framework — Incident Triage & Critical Alert Manager

Extracts current threat indicators from active forensic heuristic rules
and Evidence Vault integrity status.

Safety Invariants:
- Uses configured deterministic forensic heuristics (rules.py).
- Explicit compliance wording: "Potential security incident detected based on configured forensic rules."
- Does NOT claim definitive host compromise.
- Emits CRITICAL_INCIDENT_VIEWED audit events.
"""

from datetime import datetime, timezone
import time
from typing import Any, Dict, List, Optional

from backend.app.analysis.rules import evaluate_forensic_rules
from backend.app.collectors.files import collect_files_info
from backend.app.collectors.network import collect_network_info
from backend.app.collectors.processes import collect_process_info
from backend.app.collectors.windows_metadata import collect_windows_metadata
from backend.app.evidence import _default_vault
from .audit import record_audit_event


def get_current_incident(
    case_id: str = "LAB-2026-001",
    target: str = "LAB-PC",
    evidence: Optional[Dict[str, Any]] = None,
    user: str = "INVESTIGATOR",
    record_audit: bool = True,
) -> Dict[str, Any]:
    """
    Evaluates live or cached forensic artifacts for HIGH or CRITICAL severity alerts.
    Returns structured incident triage metadata.
    """
    if not evidence:
        raw_evidence = {
            "processes": collect_process_info(),
            "network": collect_network_info(),
            "files": collect_files_info(max_files=30),
            "windows_metadata": collect_windows_metadata(),
        }
    else:
        raw_evidence = evidence

    # Run deterministic heuristic detections
    detections: List[Dict[str, Any]] = evaluate_forensic_rules(raw_evidence)

    # Filter for high or critical priority alerts
    high_critical = [d for d in detections if d.get("severity") in ("HIGH", "CRITICAL")]

    # Check evidence integrity
    vault_status = _default_vault.verify_vault_integrity(case_id=case_id)
    integrity_verified = vault_status.get("status") == "VERIFIED" or vault_status.get("tampered_count", 0) == 0

    has_critical = len(high_critical) > 0
    top_detection = high_critical[0] if has_critical else (detections[0] if detections else None)

    # Assemble incident package
    incident_id = f"INC-{case_id}-{int(time.time())}" if has_critical else None

    incident_data = {
        "has_incident": has_critical,
        "incident_id": incident_id or "INC-NONE-000",
        "case_id": case_id,
        "target": target,
        "severity": top_detection.get("severity", "LOW") if top_detection else "NORMAL",
        "title": "Potential Critical Security Incident Detected" if has_critical else "Standard Baseline Telemetry",
        "disclaimer": "Potential security incident detected based on configured forensic rules. Does not claim definitive machine compromise.",
        "detection_reason": (
            top_detection.get("description", "Automated heuristic pattern identified.")
            if top_detection
            else "No high-severity anomalous execution patterns identified in active telemetry."
        ),
        "rule_id": top_detection.get("rule_id", "NONE") if top_detection else "NONE",
        "detection_name": top_detection.get("name", "Baseline Execution") if top_detection else "Baseline Execution",
        "detection_time": datetime.now(timezone.utc).isoformat(),
        "related_evidence_count": len(detections),
        "high_severity_count": len(high_critical),
        "evidence_integrity_status": "VERIFIED (SHA-256 Intact)" if integrity_verified else "TAMPERING_FLAGGED",
        "integrity_verified": integrity_verified,
        "detections": detections,
    }

    if has_critical and record_audit:
        record_audit_event(
            action="CRITICAL_INCIDENT_VIEWED",
            user=user,
            case_id=case_id,
            result="DETECTED",
            details={
                "incident_id": incident_id,
                "rule_id": top_detection.get("rule_id"),
                "severity": incident_data["severity"],
            },
            target_id=incident_id,
        )

    return incident_data
