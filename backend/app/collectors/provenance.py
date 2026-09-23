"""
JOCKY Forensic Collector Provenance Module

Generates auditable provenance records for forensic collections, capturing
originating host, collection method, operator identity, timestamp, and read-only flags.
"""

import datetime
import getpass
import os
import platform
import uuid
from typing import Any, Dict


def get_current_operator() -> str:
    """Safely obtain the current operator / user identity."""
    try:
        return getpass.getuser()
    except Exception:
        return os.environ.get("USERNAME") or os.environ.get("USER") or "unknown_operator"


def create_provenance(collector_name: str, method: str) -> Dict[str, Any]:
    """
    Creates a standardized collector provenance dictionary.

    Args:
        collector_name: Logical name of the collector (e.g. 'files', 'users', 'system').
        method: The underlying collection method (e.g. 'filesystem_scan_stat', 'psutil_users').

    Returns:
        Structured provenance dictionary adhering to JOCKY forensic standards.
    """
    now_utc = datetime.datetime.now(datetime.timezone.utc).isoformat()
    return {
        "collector": collector_name,
        "version": "1.0.0",
        "read_only": True,
        "host": platform.node() or "unknown_host",
        "os": platform.system() or "unknown_os",
        "os_release": platform.release() or "unknown_release",
        "collected_by": get_current_operator(),
        "method": method,
        "timestamp_utc": now_utc,
    }


def generate_collector_evidence_id(collector_name: str, case_id: str = "CASE-LIVE") -> str:
    """
    Generates a deterministic-format evidence ID for collector payloads.
    Format: EVID-<case_id>-<collector>-<timestamp>-<rand>
    """
    ts = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%d-%H%M%S")
    rand_hex = uuid.uuid4().hex[:6]
    safe_name = collector_name.lower().replace(" ", "_")
    return f"EVID-{case_id}-{safe_name}-{ts}-{rand_hex}"
