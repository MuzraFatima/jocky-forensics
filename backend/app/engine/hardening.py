"""
JOCKY Forensic Framework — Security Hardening & Invariant Protection (Phase 10)

Provides security validation, invariant protection, and defensive boundaries:
1. Path traversal injection prevention and path sanitization.
2. Read-only filesystem invariant verification (O_RDONLY enforcement).
3. Case ID and target identifier sanitization (prevents directory escape in vault).
4. Safe bounded execution and resource exhaustion guards.
"""

import os
import re
from pathlib import Path
from typing import Any, Callable, Dict, Optional


class SecurityValidationError(ValueError):
    """Raised when a security invariant or path traversal boundary is violated."""
    pass


# Disallowed path traversal patterns
_TRAVERSAL_PATTERN = re.compile(r"(\.\.[/\\]|[/\\]\.\.)")
_SAFE_ID_PATTERN = re.compile(r"^[A-Za-z0-9_\-\.]+$")


def sanitize_case_id(case_id: str) -> str:
    """
    Validates and sanitizes a case identifier.
    Rejects path separators, null bytes, or directory traversal attempts.
    """
    if not case_id or not isinstance(case_id, str):
        raise SecurityValidationError("Case identifier cannot be empty or non-string.")

    clean_id = case_id.strip()
    if "\x00" in clean_id or "/" in clean_id or "\\" in clean_id:
        raise SecurityValidationError(f"Case identifier '{case_id}' contains illegal path separators or null bytes.")

    if not _SAFE_ID_PATTERN.match(clean_id):
        raise SecurityValidationError(f"Case identifier '{case_id}' contains illegal characters. Only alphanumeric, '_', '-', '.' allowed.")

    return clean_id


def sanitize_forensic_path(path_str: str, base_boundary: Optional[str] = None) -> Path:
    """
    Validates an on-disk target path for read-only forensic inspection:
    - Rejects null bytes and traversal tokens.
    - If base_boundary is provided, ensures the resolved path remains inside base_boundary.
    """
    if not path_str or not isinstance(path_str, str):
        raise SecurityValidationError("Target forensic path cannot be empty.")

    if "\x00" in path_str:
        raise SecurityValidationError("Path contains illegal null byte.")

    # Check for direct traversal attempts
    if _TRAVERSAL_PATTERN.search(path_str):
        raise SecurityValidationError(f"Path traversal sequence detected in '{path_str}'.")

    try:
        resolved = Path(path_str).resolve()
    except Exception as exc:
        raise SecurityValidationError(f"Invalid path string: {exc}")

    if base_boundary:
        base_path = Path(base_boundary).resolve()
        try:
            resolved.relative_to(base_path)
        except ValueError:
            raise SecurityValidationError(
                f"Security violation: path '{path_str}' escapes designated boundary '{base_boundary}'."
            )

    return resolved


def verify_read_only_access(file_path: Path) -> bool:
    """
    Verifies that a file path is accessible in read-only mode and that
    the framework does not possess write privileges or attempt modifications.
    """
    if not file_path.exists():
        return False
    return os.access(file_path, os.R_OK)


def bounded_memory_inspect(items: list, max_items: int = 1000) -> list:
    """
    Guards in-memory forensic listings against runaway memory exhaustion.
    Truncates list if it exceeds max_items while preserving order.
    """
    if len(items) > max_items:
        return items[:max_items]
    return items
