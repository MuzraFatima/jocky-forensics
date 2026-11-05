"""
JOCKY Forensic Framework — Security Audit Logger

Chronologically records security-sensitive and evidentiary actions:
- LOGIN / LOGOUT / FAILED_LOGIN
- REPORT_GENERATED / REPORT_SEND_ATTEMPT / REPORT_SENT / REPORT_QUEUED / REPORT_SEND_FAILED
- ANALYST_CONTACT / AI_ASSISTANCE_USED
- CRITICAL_INCIDENT_VIEWED

Tamper evidence (blueprint §3.4, §8):
    Every entry carries a sequence number, the hash of the previous entry
    and its own SHA-256 over a canonical encoding. Changing, deleting or
    reordering any entry breaks the chain, which verify_chain() reports
    with the first sequence number that no longer matches.

    When the in-memory buffer drops its oldest entry, the dropped entry's
    hash becomes the "anchor" the remaining chain must start from. If a
    persistence path is set, every entry is also appended to a JSONL file
    that keeps the full chain from genesis.

Safety invariants:
- Never persists or logs passwords, API keys, or credentials.
- Thread-safe.
"""

import hashlib
import json
import os
import threading
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

GENESIS_HASH = "0" * 64


def _entry_digest(entry: Dict[str, Any]) -> str:
    body = {k: v for k, v in entry.items() if k != "entry_hash"}
    canonical = json.dumps(body, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def verify_chain(entries: Iterable[Dict[str, Any]], anchor: str = GENESIS_HASH) -> Dict[str, Any]:
    """
    Check that entries form an unbroken hash chain starting from anchor.

    Returns {"valid": bool, "checked": int, "first_bad_seq": int | None, "reason": str}.
    """
    expected_prev = anchor
    expected_seq: Optional[int] = None
    checked = 0
    for entry in entries:
        seq = entry.get("seq")
        if expected_seq is not None and seq != expected_seq:
            return {"valid": False, "checked": checked, "first_bad_seq": seq,
                    "reason": f"sequence jumps from {expected_seq - 1} to {seq} (entry removed or reordered)"}
        if entry.get("prev_hash") != expected_prev:
            return {"valid": False, "checked": checked, "first_bad_seq": seq,
                    "reason": f"entry {seq} does not link to the previous entry's hash"}
        if entry.get("entry_hash") != _entry_digest(entry):
            return {"valid": False, "checked": checked, "first_bad_seq": seq,
                    "reason": f"entry {seq} was modified after it was recorded"}
        expected_prev = entry["entry_hash"]
        expected_seq = (seq or 0) + 1
        checked += 1
    return {"valid": True, "checked": checked, "first_bad_seq": None, "reason": "chain intact"}


def verify_log_file(path: Path) -> Dict[str, Any]:
    """Verify a persisted JSONL audit log from genesis."""
    entries = []
    with open(path, encoding="utf-8") as handle:
        for line in handle:
            if line.strip():
                entries.append(json.loads(line))
    return verify_chain(entries, GENESIS_HASH)


class AuditLogger:
    """Thread-safe, hash-chained audit trail for JOCKY security operations."""

    def __init__(self, max_entries: int = 1000, persist_path: Optional[Path] = None):
        self._lock = threading.Lock()
        self._entries: List[Dict[str, Any]] = []
        self._max_entries = max_entries
        self._anchor = GENESIS_HASH
        self._last_hash = GENESIS_HASH
        self._next_seq = 1
        self._persist_path = Path(persist_path) if persist_path else None
        if self._persist_path:
            self._resume_from_file()

    def _resume_from_file(self) -> None:
        """Continue the chain from an existing log file instead of restarting at genesis."""
        if not self._persist_path or not self._persist_path.is_file():
            return
        last = None
        with open(self._persist_path, encoding="utf-8") as handle:
            for line in handle:
                if line.strip():
                    last = json.loads(line)
        if last:
            self._anchor = last["entry_hash"]
            self._last_hash = last["entry_hash"]
            self._next_seq = int(last["seq"]) + 1

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
        """Records an audit event safely without secrets and links it into the chain."""
        sanitized_details = self._sanitize_details(details or {})
        with self._lock:
            entry = {
                "seq": self._next_seq,
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
                "prev_hash": self._last_hash,
            }
            entry["entry_hash"] = _entry_digest(entry)
            self._last_hash = entry["entry_hash"]
            self._next_seq += 1
            self._entries.append(entry)
            if len(self._entries) > self._max_entries:
                dropped = self._entries.pop(0)
                self._anchor = dropped["entry_hash"]
            if self._persist_path:
                self._persist_path.parent.mkdir(parents=True, exist_ok=True)
                with open(self._persist_path, "a", encoding="utf-8") as handle:
                    handle.write(json.dumps(entry, sort_keys=True, default=str) + "\n")
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

        filtered.reverse()
        return filtered[:limit]

    def verify(self) -> Dict[str, Any]:
        """Verify the in-memory chain and, if persisted, the full log file."""
        with self._lock:
            entries = [dict(e) for e in self._entries]
            anchor = self._anchor
        result = verify_chain(entries, anchor)
        result["head_hash"] = entries[-1]["entry_hash"] if entries else anchor
        if self._persist_path and self._persist_path.is_file():
            result["persisted"] = verify_log_file(self._persist_path)
        return result

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


def _default_persist_path() -> Optional[Path]:
    """JOCKY_AUDIT_LOG overrides; otherwise <JOCKY_STORAGE_DIR or data/>/audit-log.jsonl (git-ignored)."""
    explicit = os.getenv("JOCKY_AUDIT_LOG")
    if explicit:
        return None if explicit.lower() in ("off", "none", "0") else Path(explicit)
    base = os.getenv("JOCKY_STORAGE_DIR")
    root = Path(base) if base else Path(__file__).resolve().parent.parent.parent.parent / "data"
    return root / "audit-log.jsonl"


# Global singleton instance
audit_logger = AuditLogger(persist_path=_default_persist_path())


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


def verify_audit_chain() -> Dict[str, Any]:
    """Helper shortcut to verify the audit hash chain."""
    return audit_logger.verify()
