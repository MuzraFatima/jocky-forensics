"""
JOCKY DSL Token Definitions

Defines token types and Token data structure for lexical analysis.
Extended in Phase 1 to support:
  - WHERE / filter clauses
  - FORMAT / JSON report qualifiers
  - STATUS / RUNNING / STATE / ESTABLISHED filter values
  - PROCESS_NETWORK analysis target
  - == operator
"""

from enum import Enum
from typing import Any, NamedTuple


class TokenType(str, Enum):
    # ── Commands & Primary Keywords ──────────────────────────────────────────
    CASE = "CASE"
    TARGET = "TARGET"
    COLLECT = "COLLECT"
    SYSTEM = "SYSTEM"
    PROCESSES = "PROCESSES"
    NETWORK = "NETWORK"
    FILES = "FILES"
    USERS = "USERS"
    REGISTRY = "REGISTRY"
    WINDOWS_METADATA = "WINDOWS_METADATA"
    ANALYZE = "ANALYZE"
    VERIFY = "VERIFY"
    INTEGRITY = "INTEGRITY"
    REPORT = "REPORT"

    # ── Phase-1 additions ────────────────────────────────────────────────────
    # Filter clause keyword
    WHERE = "WHERE"

    # Report qualifier keywords
    FORMAT = "FORMAT"
    JSON = "JSON"

    # Filter field names
    STATUS = "STATUS"
    STATE = "STATE"

    # Filter value keywords
    RUNNING = "RUNNING"
    ESTABLISHED = "ESTABLISHED"

    # Analysis target
    PROCESS_NETWORK = "PROCESS_NETWORK"

    # ── Operators ─────────────────────────────────────────────────────────────
    EQ = "=="          # equality operator used in filter expressions

    # ── Literals & Identifiers ────────────────────────────────────────────────
    STRING = "STRING"
    IDENTIFIER = "IDENTIFIER"
    INTEGER = "INTEGER"

    # ── Delimiters / Control ──────────────────────────────────────────────────
    NEWLINE = "NEWLINE"
    EOF = "EOF"


# ---------------------------------------------------------------------------
# Keyword map — all recognised keyword strings → TokenType
# ---------------------------------------------------------------------------
KEYWORDS: dict[str, TokenType] = {
    "CASE": TokenType.CASE,
    "TARGET": TokenType.TARGET,
    "COLLECT": TokenType.COLLECT,
    "SYSTEM": TokenType.SYSTEM,
    "PROCESSES": TokenType.PROCESSES,
    "NETWORK": TokenType.NETWORK,
    "FILES": TokenType.FILES,
    "ANALYZE": TokenType.ANALYZE,
    "VERIFY": TokenType.VERIFY,
    "INTEGRITY": TokenType.INTEGRITY,
    "REPORT": TokenType.REPORT,
    # Phase-1 additions
    "WHERE": TokenType.WHERE,
    "FORMAT": TokenType.FORMAT,
    "JSON": TokenType.JSON,
    "STATUS": TokenType.STATUS,
    "STATE": TokenType.STATE,
    "RUNNING": TokenType.RUNNING,
    "ESTABLISHED": TokenType.ESTABLISHED,
    "PROCESS_NETWORK": TokenType.PROCESS_NETWORK,
    # Phase-3 additions
    "USERS": TokenType.USERS,
    "REGISTRY": TokenType.REGISTRY,
    "WINDOWS_METADATA": TokenType.WINDOWS_METADATA,
}


class Token(NamedTuple):
    type: TokenType
    value: Any
    line: int
    column: int

    def __repr__(self) -> str:
        return f"Token({self.type.value}, {self.value!r}, line={self.line}, col={self.column})"
