"""
JOCKY DSL Intermediate Representation (IR)

Transforms a validated ProgramNode AST into a version-stamped JOCKY IR
dictionary. The IR describes investigation intent; it does not execute
anything.

IR schema (version 2.0):
{
    "version": "2.0",
    "case_id": "<string>",
    "target":  "<string>",
    "platform": "AUTO" | "WINDOWS" | "LINUX" | "MACOS",
    "required_capabilities": ["COLLECT_SYSTEM", ...],
    "operations": [
        {
            "id":            "op-1",
            "type":          "COLLECT" | "ANALYZE" | "VERIFY" | "REPORT",
            "target":        "<string>",   # COLLECT, ANALYZE, VERIFY
            "path":          "<string>",   # COLLECT FILES only
            "filters":       [ {...} ],    # COLLECT with WHERE
            "format":        "<string>",   # REPORT FORMAT
            "capability":    "<label>" | null,
            "output_schema": "<schema id>" | null,
            "platforms":     ["LINUX", ...],
            "source":        {"line": int, "column": int}
        },
        ...
    ]
}

Version 2.0 only adds keys to 1.0, so anything that read 1.0 operations
(type / target / path / filters / format) keeps working.
"""

from typing import Any, Dict, List

from .ast import (
    AnalyzeNode,
    CaseNode,
    CollectNode,
    PlatformNode,
    ProgramNode,
    ReportNode,
    TargetNode,
    VerifyNode,
)
from .capabilities import lookup

IR_VERSION = "2.0"


def _annotate(op: Dict[str, Any], index: int, line: int, column: int) -> Dict[str, Any]:
    """Attach id, declared capability, output schema, platforms and source position."""
    spec = lookup(op["type"], op.get("target") or op.get("format"))
    op["id"] = f"op-{index}"
    op["capability"] = spec.capability if spec else None
    op["output_schema"] = spec.output_schema if spec else None
    op["platforms"] = sorted(spec.platforms) if spec else []
    op["source"] = {"line": line, "column": column}
    return op


def build_ir(program: ProgramNode) -> Dict[str, Any]:
    """
    Walk a validated ProgramNode and produce the JOCKY IR dictionary.

    The program must already be semantically validated (via Validator);
    this function trusts that the AST is well-formed.
    """
    case_id: str = ""
    target: str = ""
    platform: str = "AUTO"
    operations: List[Dict[str, Any]] = []

    for stmt in program.statements:
        # Declarations set global context rather than producing operations
        if isinstance(stmt, CaseNode):
            case_id = stmt.case_id
            continue
        if isinstance(stmt, TargetNode):
            target = stmt.target_name
            continue
        if isinstance(stmt, PlatformNode):
            platform = stmt.platform
            continue

        op: Dict[str, Any]
        if isinstance(stmt, CollectNode):
            op = {"type": "COLLECT", "target": stmt.category}
            if stmt.path is not None:
                op["path"] = stmt.path
            if stmt.filters:
                op["filters"] = [{"field": f.field, "operator": f.operator, "value": f.value} for f in stmt.filters]
        elif isinstance(stmt, AnalyzeNode):
            op = {"type": "ANALYZE"}
            if stmt.analysis_target:
                op["target"] = stmt.analysis_target
        elif isinstance(stmt, VerifyNode):
            op = {"type": "VERIFY", "target": stmt.verify_target}
        elif isinstance(stmt, ReportNode):
            op = {"type": "REPORT"}
            if stmt.format:
                op["format"] = stmt.format
        else:
            continue

        operations.append(_annotate(op, len(operations) + 1, stmt.line, stmt.column))

    required = sorted({op["capability"] for op in operations if op["capability"]})

    return {
        "version": IR_VERSION,
        "case_id": case_id,
        "target": target,
        "platform": platform,
        "required_capabilities": required,
        "operations": operations,
    }
