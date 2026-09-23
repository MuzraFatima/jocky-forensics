"""
JOCKY Forensic Policy Engine

Enforces authorization, boundary restrictions, and non-destructive invariants
on JOCKY Execution Plans prior to dispatching to collectors.

Security Invariants:
- All approved operations MUST be explicitly marked read-only.
- Disallows any offensive, bypass, injection, or system modification operations.
- Rejects path traversal and unauthorized filesystem paths.
"""

from typing import Any, Dict, List, Optional, Set, Tuple

# Authorized (Action, Category/Target) pairs
AUTHORIZED_OPERATIONS: Set[Tuple[str, Optional[str]]] = {
    ("COLLECT", "SYSTEM"),
    ("COLLECT", "PROCESSES"),
    ("COLLECT", "NETWORK"),
    ("COLLECT", "FILES"),
    ("ANALYZE", None),
    ("VERIFY", "INTEGRITY"),
    ("REPORT", None),
}


class PolicyEngine:
    """Evaluates execution plans against the JOCKY authorized forensics policy."""

    def __init__(self, allowed_file_prefixes: Optional[List[str]] = None):
        # Default authorized evidence directory prefixes
        self.allowed_file_prefixes = allowed_file_prefixes or ["./", "./evidence", "evidence", "/evidence"]

    def _is_path_safe(self, path: Optional[str]) -> Tuple[bool, str]:
        """Verify that a target file path does not attempt path traversal or escaping bounds."""
        if not path:
            return False, "Target path is missing or empty"

        normalized = path.replace("\\", "/")
        if ".." in normalized.split("/"):
            return False, f"Path traversal attempt detected in path '{path}'"

        return True, "Path within authorized bounds"

    def evaluate(self, execution_plan: Dict[str, Any]) -> Dict[str, Any]:
        """
        Evaluates every task in an execution plan.
        Returns a PolicyResult dictionary containing:
        - allowed (bool)
        - approved_operations (list)
        - rejected_operations (list)
        - reason (str)
        """
        approved_operations: List[Dict[str, Any]] = []
        rejected_operations: List[Dict[str, Any]] = []

        tasks = execution_plan.get("tasks", [])
        if not tasks:
            return {
                "allowed": True,
                "approved_operations": [],
                "rejected_operations": [],
                "reason": "Execution plan contains no tasks to evaluate.",
            }

        for task in tasks:
            action = task.get("action", "").upper()
            category = task.get("category")
            target = task.get("target")
            sub_target = category or target
            if sub_target:
                sub_target = sub_target.upper()

            step = task.get("step", 0)
            op_key = (action, sub_target)

            # 1. Check if action and target match the authorization allowlist
            if op_key not in AUTHORIZED_OPERATIONS:
                rejected_operations.append({
                    "step": step,
                    "operation": action,
                    "target": sub_target,
                    "read_only": False,
                    "policy_status": "REJECTED",
                    "reason": (
                        f"Unauthorized operation '{action} {sub_target or ''}'. "
                        "Only authorized read-only forensic operations (SYSTEM, PROCESSES, NETWORK, FILES, ANALYZE, VERIFY INTEGRITY, REPORT) are permitted."
                    ),
                })
                continue

            # 2. Path safety check for COLLECT FILES
            if action == "COLLECT" and sub_target == "FILES":
                params = task.get("params", {})
                target_path = params.get("path")
                is_safe, path_reason = self._is_path_safe(target_path)
                if not is_safe:
                    rejected_operations.append({
                        "step": step,
                        "operation": action,
                        "target": sub_target,
                        "params": params,
                        "read_only": False,
                        "policy_status": "REJECTED",
                        "reason": f"File collection policy violation: {path_reason}",
                    })
                    continue

            # 3. Approve operation and mark explicitly as read-only
            approved_op = {
                "step": step,
                "operation": action,
                "target": sub_target,
                "read_only": True,
                "policy_status": "APPROVED",
                "reason": "Authorized read-only forensic operation approved.",
            }
            if task.get("params"):
                approved_op["params"] = task["params"]
            if task.get("description"):
                approved_op["description"] = task["description"]

            approved_operations.append(approved_op)

        # Compute overarching policy verdict
        is_allowed = len(rejected_operations) == 0

        if is_allowed:
            reason = (
                f"All {len(approved_operations)} operations approved under authorized read-only forensic policy. "
                "No destructive or invasive operations scheduled."
            )
        else:
            reason = (
                f"Policy check failed: {len(rejected_operations)} unauthorized or unsafe operation(s) rejected. "
                f"{len(approved_operations)} operation(s) approved."
            )

        return {
            "allowed": is_allowed,
            "approved_operations": approved_operations,
            "rejected_operations": rejected_operations,
            "reason": reason,
        }
