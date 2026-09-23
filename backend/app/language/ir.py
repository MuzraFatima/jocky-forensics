"""
JOCKY DSL Intermediate Representation (IR)

Transforms a validated ProgramNode AST into a compact, version-stamped
JOCKY IR dictionary.  The IR is the final artefact of Phase 1.

The IR does NOT execute any operations.  That is Phase 2 (Execution Engine).

IR Schema (version 1.0):
{
    "version": "1.0",
    "case_id": "<string>",
    "target":  "<string>",
    "operations": [
        {
            "type":    "COLLECT" | "ANALYZE" | "VERIFY" | "REPORT",
            "target":  "<string>",           # present on COLLECT, ANALYZE, VERIFY
            "filters": [ {...} ],            # optional, present on COLLECT when WHERE used
            "format":  "<string>",           # optional, present on REPORT FORMAT
        },
        ...
    ]
}
"""

from typing import Any, Dict, List

from .ast import (
    AnalyzeNode,
    CaseNode,
    CollectNode,
    ProgramNode,
    ReportNode,
    TargetNode,
    VerifyNode,
)

IR_VERSION = "1.0"


def build_ir(program: ProgramNode) -> Dict[str, Any]:
    """
    Walk a validated ProgramNode and produce the JOCKY IR dictionary.

    Prerequisites:
        The program must already be semantically validated (via Validator).
        This function trusts that the AST is well-formed.

    Args:
        program: A validated ProgramNode instance.

    Returns:
        A JSON-serialisable dict representing the JOCKY IR.
    """
    case_id: str = ""
    target: str = ""
    operations: List[Dict[str, Any]] = []

    for stmt in program.statements:

        # ── Declaration nodes set global context, not discrete operations ──

        if isinstance(stmt, CaseNode):
            case_id = stmt.case_id
            continue

        if isinstance(stmt, TargetNode):
            target = stmt.target_name
            continue

        # ── Operational nodes → IR operations ──────────────────────────────

        if isinstance(stmt, CollectNode):
            op: Dict[str, Any] = {
                "type": "COLLECT",
                "target": stmt.category,
            }
            if stmt.path is not None:
                op["path"] = stmt.path
            if stmt.filters:
                op["filters"] = [
                    {
                        "field": f.field,
                        "operator": f.operator,
                        "value": f.value,
                    }
                    for f in stmt.filters
                ]
            operations.append(op)

        elif isinstance(stmt, AnalyzeNode):
            op = {"type": "ANALYZE"}
            if stmt.analysis_target:
                op["target"] = stmt.analysis_target
            operations.append(op)

        elif isinstance(stmt, VerifyNode):
            operations.append({
                "type": "VERIFY",
                "target": stmt.verify_target,
            })

        elif isinstance(stmt, ReportNode):
            op = {"type": "REPORT"}
            if stmt.format:
                op["format"] = stmt.format
            operations.append(op)

    return {
        "version": IR_VERSION,
        "case_id": case_id,
        "target": target,
        "operations": operations,
    }
