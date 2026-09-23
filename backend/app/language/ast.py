"""
JOCKY DSL Abstract Syntax Tree (AST) Nodes

Defines the structured nodes representing a parsed JOCKY forensic script.
Each node includes source coordinates (line and column) and serialization helpers.

Phase-1 additions:
  - FilterExpression  — represents a WHERE field == value clause
  - CollectNode gains an optional List[FilterExpression] field
  - AnalyzeNode gains an optional analysis_target field (e.g., PROCESS_NETWORK)
  - ReportNode gains an optional format field (e.g., JSON)
"""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


# ---------------------------------------------------------------------------
# Base
# ---------------------------------------------------------------------------

@dataclass
class ASTNode:
    """Base class for all AST nodes."""
    line: int
    column: int

    def to_dict(self) -> Dict[str, Any]:
        """Convert AST node to a JSON-serializable dictionary."""
        raise NotImplementedError


# ---------------------------------------------------------------------------
# FilterExpression — WHERE <field> == <value>
# ---------------------------------------------------------------------------

@dataclass
class FilterExpression:
    """
    Represents a single filter predicate in a WHERE clause.

    Example:
        WHERE status == RUNNING
        → FilterExpression(field="status", operator="==", value="RUNNING")
    """
    field: str
    operator: str   # currently only "==" is supported
    value: str
    line: int
    column: int

    def to_dict(self) -> Dict[str, Any]:
        return {
            "field": self.field,
            "operator": self.operator,
            "value": self.value,
            "line": self.line,
            "column": self.column,
        }


# ---------------------------------------------------------------------------
# Declaration nodes
# ---------------------------------------------------------------------------

@dataclass
class CaseNode(ASTNode):
    """Represents: CASE \"LAB-2026-001\" """
    case_id: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "type": "CaseNode",
            "case_id": self.case_id,
            "line": self.line,
            "column": self.column,
        }


@dataclass
class TargetNode(ASTNode):
    """Represents: TARGET \"LAB-PC\" """
    target_name: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "type": "TargetNode",
            "target": self.target_name,
            "line": self.line,
            "column": self.column,
        }


# ---------------------------------------------------------------------------
# Operational nodes
# ---------------------------------------------------------------------------

@dataclass
class CollectNode(ASTNode):
    """
    Represents: COLLECT SYSTEM | PROCESSES | NETWORK | FILES \"<path>\"

    Phase-1: also accepts an optional WHERE filter clause.

    Example:
        COLLECT PROCESSES
            WHERE status == RUNNING
        → CollectNode(category="PROCESSES", filters=[FilterExpression(...)])
    """
    category: str
    path: Optional[str] = None
    filters: List[FilterExpression] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        result: Dict[str, Any] = {
            "type": "CollectNode",
            "category": self.category,
            "line": self.line,
            "column": self.column,
        }
        if self.path is not None:
            result["path"] = self.path
        if self.filters:
            result["filters"] = [f.to_dict() for f in self.filters]
        return result


@dataclass
class AnalyzeNode(ASTNode):
    """
    Represents: ANALYZE [<target>]

    Phase-1: optional analysis_target (e.g., PROCESS_NETWORK).

    Example:
        ANALYZE PROCESS_NETWORK
        → AnalyzeNode(analysis_target="PROCESS_NETWORK")
    """
    analysis_target: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        result: Dict[str, Any] = {
            "type": "AnalyzeNode",
            "line": self.line,
            "column": self.column,
        }
        if self.analysis_target is not None:
            result["analysis_target"] = self.analysis_target
        return result


@dataclass
class VerifyNode(ASTNode):
    """Represents: VERIFY INTEGRITY"""
    verify_target: str = "INTEGRITY"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "type": "VerifyNode",
            "verify_target": self.verify_target,
            "line": self.line,
            "column": self.column,
        }


@dataclass
class ReportNode(ASTNode):
    """
    Represents: REPORT [FORMAT <format>]

    Phase-1: optional format qualifier.

    Example:
        REPORT FORMAT JSON
        → ReportNode(format="JSON")
    """
    format: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        result: Dict[str, Any] = {
            "type": "ReportNode",
            "line": self.line,
            "column": self.column,
        }
        if self.format is not None:
            result["format"] = self.format
        return result


# ---------------------------------------------------------------------------
# Top-level program node
# ---------------------------------------------------------------------------

@dataclass
class ProgramNode(ASTNode):
    """Top-level AST node containing all statements in a JOCKY script."""
    statements: List[ASTNode] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "type": "ProgramNode",
            "statements": [stmt.to_dict() for stmt in self.statements],
            "line": self.line,
            "column": self.column,
        }
