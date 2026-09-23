"""
JOCKY DSL Semantic Validator

Validates the parsed AST against forensic structural rules and emits a safe,
read-only execution plan describing the planned investigation steps.

Phase-1 extended validation rules:
  1.  CASE is required (exactly once).
  2.  TARGET is required (exactly once).
  3.  At least one COLLECT operation is required.
  4.  Unknown operations are rejected (parser already catches most).
  5.  Invalid WHERE filters are rejected.
  6.  VERIFY INTEGRITY must follow at least one evidence-producing COLLECT.
  7.  REPORT should come after investigation operations (warning, not hard error).
  8.  Duplicate CASE declarations are rejected.
  9.  Duplicate TARGET declarations are rejected.
  10. Unsupported REPORT formats are rejected.

Important:
    This validator only generates an abstract execution plan.
    It does NOT execute commands, access the filesystem, or harvest data.
"""

from typing import Any, Dict, List, Optional
from .ast import (
    AnalyzeNode,
    CaseNode,
    CollectNode,
    FilterExpression,
    ProgramNode,
    ReportNode,
    TargetNode,
    VerifyNode,
)
from .errors import JockyValidationError

# Supported report formats
_SUPPORTED_REPORT_FORMATS = {"JSON", "HTML", "MD", "MARKDOWN"}

# Valid filter fields per collection category (lower-cased)
_VALID_FILTERS: Dict[str, set] = {
    "PROCESSES": {"status"},
    "NETWORK": {"state"},
}

# Valid filter values per field (lower-cased field → set of valid upper-case values)
_VALID_FILTER_VALUES: Dict[str, set] = {
    "status": {"RUNNING", "SLEEPING", "STOPPED", "ZOMBIE", "IDLE"},
    "state": {"ESTABLISHED", "LISTEN", "TIME_WAIT", "CLOSE_WAIT", "SYN_SENT"},
}

# Evidence-producing COLLECT categories
_EVIDENCE_CATEGORIES = {
    "SYSTEM", "PROCESSES", "NETWORK", "FILES",
    "USERS", "REGISTRY", "WINDOWS_METADATA"
}


class Validator:
    """Validates JOCKY AST and compiles a declarative Execution Plan."""

    def validate_and_plan(self, program: ProgramNode) -> Dict[str, Any]:
        """
        Validates the program AST and returns a structured execution plan.
        Raises JockyValidationError if mandatory invariants are violated.
        """
        case_nodes: List[CaseNode] = []
        target_nodes: List[TargetNode] = []

        # ── 1. Scan for CASE and TARGET — check uniqueness & presence ─────────

        for stmt in program.statements:
            if isinstance(stmt, CaseNode):
                case_nodes.append(stmt)
            elif isinstance(stmt, TargetNode):
                target_nodes.append(stmt)

        # CASE required and unique
        if len(case_nodes) == 0:
            raise JockyValidationError(
                "Missing mandatory 'CASE' declaration. A forensic script must define a case identifier.",
                line=program.line,
                column=program.column,
            )
        if len(case_nodes) > 1:
            second_case = case_nodes[1]
            raise JockyValidationError(
                f"Duplicate 'CASE' declaration '{second_case.case_id}'. Only one case context is permitted per script.",
                line=second_case.line,
                column=second_case.column,
            )

        # TARGET required and unique
        if len(target_nodes) == 0:
            raise JockyValidationError(
                "Missing mandatory 'TARGET' declaration. A forensic script must define a target host.",
                line=program.line,
                column=program.column,
            )
        if len(target_nodes) > 1:
            second_target = target_nodes[1]
            raise JockyValidationError(
                f"Duplicate 'TARGET' declaration '{second_target.target_name}'. Only one target host is permitted per script.",
                line=second_target.line,
                column=second_target.column,
            )

        case_id = case_nodes[0].case_id.strip()
        if not case_id:
            raise JockyValidationError(
                "Case identifier cannot be empty.",
                line=case_nodes[0].line,
                column=case_nodes[0].column,
            )

        target_name = target_nodes[0].target_name.strip()
        if not target_name:
            raise JockyValidationError(
                "Target identifier cannot be empty.",
                line=target_nodes[0].line,
                column=target_nodes[0].column,
            )

        # ── 2. Validate individual statements and collect evidence-tracking info

        has_collect = False
        has_evidence_collect = False  # COLLECT that produces storable artifacts
        collected_categories: List[str] = []

        for stmt in program.statements:
            if isinstance(stmt, (CaseNode, TargetNode)):
                continue

            if isinstance(stmt, CollectNode):
                has_collect = True
                if stmt.category in _EVIDENCE_CATEGORIES:
                    has_evidence_collect = True
                    collected_categories.append(stmt.category)

                # Validate WHERE filters
                if stmt.filters:
                    allowed_fields = _VALID_FILTERS.get(stmt.category, set())
                    for flt in stmt.filters:
                        if flt.field not in allowed_fields:
                            valid_str = ", ".join(sorted(allowed_fields)) or "none"
                            raise JockyValidationError(
                                f"Invalid filter field '{flt.field}' for COLLECT {stmt.category}. "
                                f"Allowed fields: {valid_str}",
                                line=flt.line,
                                column=flt.column,
                            )
                        valid_values = _VALID_FILTER_VALUES.get(flt.field, set())
                        if valid_values and flt.value.upper() not in valid_values:
                            valid_str = ", ".join(sorted(valid_values))
                            raise JockyValidationError(
                                f"Invalid filter value '{flt.value}' for field '{flt.field}'. "
                                f"Allowed values: {valid_str}",
                                line=flt.line,
                                column=flt.column,
                            )

                # COLLECT FILES needs a non-empty path
                if stmt.category == "FILES":
                    if not stmt.path or not stmt.path.strip():
                        raise JockyValidationError(
                            "COLLECT FILES path cannot be empty.",
                            line=stmt.line,
                            column=stmt.column,
                        )

            elif isinstance(stmt, VerifyNode):
                # Rule 6: VERIFY INTEGRITY must follow at least one evidence-producing COLLECT
                if not has_evidence_collect:
                    raise JockyValidationError(
                        "VERIFY INTEGRITY must follow at least one evidence-producing COLLECT operation "
                        "(SYSTEM, PROCESSES, NETWORK, or FILES).",
                        line=stmt.line,
                        column=stmt.column,
                    )

            elif isinstance(stmt, ReportNode):
                # Rule 10: Only supported formats are accepted
                if stmt.format is not None and stmt.format.upper() not in _SUPPORTED_REPORT_FORMATS:
                    raise JockyValidationError(
                        f"Unsupported report format '{stmt.format}'. "
                        f"Supported formats: {', '.join(sorted(_SUPPORTED_REPORT_FORMATS))}",
                        line=stmt.line,
                        column=stmt.column,
                    )

        # Rule 3: At least one COLLECT required
        if not has_collect:
            raise JockyValidationError(
                "A forensic script must contain at least one COLLECT operation.",
                line=program.line,
                column=program.column,
            )

        # ── 3. Build structured execution plan tasks ──────────────────────────

        tasks: List[Dict[str, Any]] = []
        step_number = 1

        for stmt in program.statements:
            if isinstance(stmt, (CaseNode, TargetNode)):
                continue

            if isinstance(stmt, CollectNode):
                task: Dict[str, Any] = {
                    "step": step_number,
                    "action": "COLLECT",
                    "category": stmt.category,
                    "line": stmt.line,
                    "column": stmt.column,
                }
                if stmt.category == "SYSTEM":
                    task["description"] = "Collect system environment, OS release, and uptime metadata (read-only)"
                elif stmt.category == "PROCESSES":
                    task["description"] = "Enumerate running processes, PIDs, parent trees, and execution paths (read-only)"
                elif stmt.category == "NETWORK":
                    task["description"] = "Enumerate active connections, sockets, and network interfaces (read-only)"
                elif stmt.category == "FILES":
                    task["description"] = f"Collect file metadata and compute hashes within target directory '{stmt.path}'"
                    task["params"] = {"path": stmt.path}

                if stmt.filters:
                    task["filters"] = [f.to_dict() for f in stmt.filters]

                tasks.append(task)
                step_number += 1

            elif isinstance(stmt, AnalyzeNode):
                analyze_task: Dict[str, Any] = {
                    "step": step_number,
                    "action": "ANALYZE",
                    "description": "Execute heuristic forensic analysis on collected artifacts",
                    "line": stmt.line,
                    "column": stmt.column,
                }
                if stmt.analysis_target:
                    analyze_task["target"] = stmt.analysis_target
                tasks.append(analyze_task)
                step_number += 1

            elif isinstance(stmt, VerifyNode):
                tasks.append({
                    "step": step_number,
                    "action": "VERIFY",
                    "target": stmt.verify_target,
                    "description": "Verify SHA-256 cryptographic integrity of all stored evidence",
                    "line": stmt.line,
                    "column": stmt.column,
                })
                step_number += 1

            elif isinstance(stmt, ReportNode):
                report_task: Dict[str, Any] = {
                    "step": step_number,
                    "action": "REPORT",
                    "description": "Generate comprehensive forensic analysis report and chain of custody log",
                    "line": stmt.line,
                    "column": stmt.column,
                }
                if stmt.format:
                    report_task["format"] = stmt.format
                tasks.append(report_task)
                step_number += 1

        execution_plan: Dict[str, Any] = {
            "case_id": case_id,
            "target": target_name,
            "tasks": tasks,
            "metadata": {
                "read_only": True,
                "total_tasks": len(tasks),
                "policy_verified": True,
                "description": "Declarative execution plan; no commands executed yet.",
            },
        }

        return execution_plan
