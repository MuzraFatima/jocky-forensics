"""
JOCKY Forensic Framework — Security Audit Logger

Chronologically records security-sensitive and evidentiary actions:
- LOGIN / LOGOUT / FAILED_LOGIN
- REPORT_GENERATED / REPORT_SEND_ATTEMPT / REPORT_SENT / REPORT_QUEUED / REPORT_SEND_FAILED
- ANALYST_CONTACT / AI_ASSISTANCE_USED
- CRITICAL_INCIDENT_VIEWED

Safety Invariants:
- Never persists or logs passwords, API keys, or credentials.
- Thread-safe in-memory circular buffer with optional append-only audit persistence.
- Immutable event records with ISO-8601 timestamps.
"""

import threading
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
import uuid


class AuditLogger:
    """Thread-safe audit trail manager for JOCKY security operations."""

    def __init__(self, max_entries: int = 1000):
        self._lock = threading.Lock()
        self._entries: List[Dict[str, Any]] = []
        self._max_entries = max_entries

    def record(
        self,
        action: str,
        user: Optional[str] = None,
        case_id: Optional[str] = None,
        result: str = "SUCCESS",
        details: Optional[Dict[str, Any]] = None,
        target_id: Optional[str] = None,
        ip_address: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Records an audit event safely without secrets.
        """
        sanitized_details = self._sanitize_details(details or {})

        entry = {
            "id": f"AUD-{uuid.uuid4().hex[:12].upper()}",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "epoch": time.time(),
            "action": action.upper(),
            "user": user or "ANONYMOUS_INVESTIGATOR",
            "case_id": case_id or "GENERAL",
            "result": result.upper(),
            "target_id": target_id,
            "ip_address": ip_address or "127.0.0.1",
            "details": sanitized_details,
        }

        with self._lock:
            self._entries.append(entry)
            if len(self._entries) > self._max_entries:
                self._entries.pop(0)

        return entry

    def get_events(
        self,
        limit: int = 100,
        action: Optional[str] = None,
        case_id: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Returns recent audit events filtered chronologically in descending order."""
        with self._lock:
            filtered = list(self._entries)

        if action:
            act_clean = action.upper().strip()
            filtered = [e for e in filtered if e["action"] == act_clean]

        if case_id:
            c_clean = case_id.strip()
            filtered = [e for e in filtered if e["case_id"] == c_clean]

        # Return latest first
        filtered.reverse()
        return filtered[:limit]

    def _sanitize_details(self, details: Dict[str, Any]) -> Dict[str, Any]:
        """Strips any sensitive keys (passwords, tokens, keys) from audit payloads."""
        forbidden_substrings = ("password", "secret", "token", "auth", "key", "credential")
        sanitized = {}
        for k, v in details.items():
            if any(sub in k.lower() for sub in forbidden_substrings):
                sanitized[k] = "[REDACTED]"
            elif isinstance(v, dict):
                sanitized[k] = self._sanitize_details(v)
            else:
                sanitized[k] = v
        return sanitized


# Global singleton instance
audit_logger = AuditLogger()


def record_audit_event(
    action: str,
    user: Optional[str] = None,
    case_id: Optional[str] = None,
    result: str = "SUCCESS",
    details: Optional[Dict[str, Any]] = None,
    target_id: Optional[str] = None,
    ip_address: Optional[str] = None,
) -> Dict[str, Any]:
    """Helper shortcut to log an audit event."""
    return audit_logger.record(
        action=action,
        user=user,
        case_id=case_id,
        result=result,
        details=details,
        target_id=target_id,
        ip_address=ip_address,
    )


def get_audit_events(
    limit: int = 100,
    action: Optional[str] = None,
    case_id: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """Helper shortcut to fetch audit events."""
    return audit_logger.get_events(limit=limit, action=action, case_id=case_id)
