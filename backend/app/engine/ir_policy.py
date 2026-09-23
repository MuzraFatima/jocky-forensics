"""
JOCKY Phase-2 IR Policy Evaluator

Evaluates a JOCKY IR dict (produced by Phase-1 compiler) against the
authorization policy before any collectors are dispatched.

The IR uses a different schema from the legacy execution_plan (tasks list),
so this module provides an adapter that translates IR operations into the
policy engine's expected task format and maps the allowed capability names.

Supported IR capabilities:
  COLLECT  SYSTEM            → COLLECT_SYSTEM
  COLLECT  PROCESSES         → COLLECT_PROCESSES
  COLLECT  NETWORK           → COLLECT_NETWORK
  ANALYZE  PROCESS_NETWORK   → ANALYZE_PROCESS_NETWORK
  VERIFY   INTEGRITY         → VERIFY_INTEGRITY
  REPORT   (any format)      → REPORT_JSON  (only JSON is supported in Phase 2)

Security invariants:
  - Every capability must be explicitly authorized.
  - Unknown / offensive operations are always DENIED.
  - The result carries the full per-operation decision trail.
"""

from typing import Any, Dict, List, Optional, Tuple

# ---------------------------------------------------------------------------
# Capability allow-list
# Each entry: (ir_type, ir_target_or_None) → capability_label
# ---------------------------------------------------------------------------
_CAPABILITY_MAP: Dict[Tuple[str, Optional[str]], str] = {
    ("COLLECT",  "SYSTEM"):           "COLLECT_SYSTEM",
    ("COLLECT",  "PROCESSES"):        "COLLECT_PROCESSES",
    ("COLLECT",  "NETWORK"):          "COLLECT_NETWORK",
    ("COLLECT",  "FILES"):            "COLLECT_FILES",
    ("COLLECT",  "USERS"):            "COLLECT_USERS",
    ("COLLECT",  "REGISTRY"):         "COLLECT_REGISTRY",
    ("COLLECT",  "WINDOWS_METADATA"): "COLLECT_WINDOWS_METADATA",
    ("ANALYZE",  "PROCESS_NETWORK"):  "ANALYZE_PROCESS_NETWORK",
    ("ANALYZE",  None):               "ANALYZE_PROCESS_NETWORK",   # bare ANALYZE
    ("VERIFY",   "INTEGRITY"):        "VERIFY_INTEGRITY",
    ("REPORT",   None):               "REPORT_JSON",
    ("REPORT",   "JSON"):             "REPORT_JSON",               # explicit format
    ("REPORT",   "HTML"):             "REPORT_HTML",
    ("REPORT",   "MD"):               "REPORT_MD",
    ("REPORT",   "MARKDOWN"):         "REPORT_MD",
}


def _op_key(op: Dict[str, Any]) -> Tuple[str, Optional[str]]:
    """Derive the lookup key for an IR operation."""
    op_type = op.get("type", "").upper()
    op_target = op.get("target") or op.get("format")
    if op_target:
        op_target = op_target.upper()
    return (op_type, op_target)


def evaluate_ir_policy(ir: Dict[str, Any]) -> Dict[str, Any]:
    """
    Evaluate a JOCKY IR dict against the forensic authorization policy.

    Returns a policy result dict:
    {
        "allowed": bool,
        "approved_operations": [...],
        "denied_operations":   [...],
        "capability_map":      {i: capability_label, ...},
        "reason": str
    }

    Each operation entry carries:
    {
        "index":       int,
        "type":        str,
        "target":      str|None,
        "capability":  str,
        "decision":    "ALLOWED" | "DENIED",
        "reason":      str,
        "read_only":   bool,
        "filters":     [...] | [],
        "format":      str|None
    }
    """
    operations: List[Dict[str, Any]] = ir.get("operations", [])

    if not operations:
        return {
            "allowed": True,
            "approved_operations": [],
            "denied_operations": [],
            "capability_map": {},
            "reason": "IR contains no operations.",
        }

    approved: List[Dict[str, Any]] = []
    denied: List[Dict[str, Any]] = []
    capability_map: Dict[int, str] = {}

    for idx, op in enumerate(operations):
        key = _op_key(op)
        op_type = key[0]
        op_target = key[1]
        capability = _CAPABILITY_MAP.get(key)

        # Also check with None target for flexible matching (e.g., REPORT with format key)
        if capability is None:
            format_val = op.get("format")
            if format_val:
                alt_key = (op_type, format_val.upper())
                capability = _CAPABILITY_MAP.get(alt_key)

        base_entry: Dict[str, Any] = {
            "index": idx,
            "type": op_type,
            "target": op_target,
            "filters": op.get("filters", []),
            "format": op.get("format"),
        }

        if capability is None:
            label = f"{op_type} {op_target or ''}".strip()
            entry = {
                **base_entry,
                "capability": f"UNKNOWN_{op_type}",
                "decision": "DENIED",
                "reason": (
                    f"Operation '{label}' is not an authorized forensic capability. "
                    "Only COLLECT_SYSTEM, COLLECT_PROCESSES, COLLECT_NETWORK, "
                    "ANALYZE_PROCESS_NETWORK, VERIFY_INTEGRITY, and REPORT_JSON are permitted."
                ),
                "read_only": False,
            }
            denied.append(entry)
        else:
            capability_map[idx] = capability
            entry = {
                **base_entry,
                "capability": capability,
                "decision": "ALLOWED",
                "reason": f"Authorized read-only forensic capability '{capability}' approved.",
                "read_only": True,
            }
            approved.append(entry)

    is_allowed = len(denied) == 0

    if is_allowed:
        reason = (
            f"All {len(approved)} IR operations authorized under the read-only forensic policy."
        )
    else:
        reason = (
            f"Policy DENIED: {len(denied)} unauthorized operation(s). "
            f"{len(approved)} operation(s) approved."
        )

    return {
        "allowed": is_allowed,
        "approved_operations": approved,
        "denied_operations": denied,
        "capability_map": capability_map,
        "reason": reason,
    }
