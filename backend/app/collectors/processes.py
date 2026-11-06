"""
JOCKY Safe Process Forensic Collector

Authorized read-only digital forensic collector for active process enumeration,
gathering PID, process name, executable path, security context (username),
resource utilization (CPU/memory), status, and creation timestamps.

Safety Invariants:
- Strictly read-only: does not kill, suspend, modify, or inject into any process.
- No memory dumping or code inspection.
- Gracefully handles inaccessible, restricted, or ephemeral processes without crashing.
- No security evasion, bypass, or privilege tampering.
"""

import datetime
from typing import Any, Dict, List, Optional

import psutil


def _safe_format_timestamp(raw_ts: Optional[float]) -> Optional[str]:
    """Convert raw epoch timestamp to ISO 8601 UTC string safely."""
    if not raw_ts or raw_ts <= 0:
        return None
    try:
        return datetime.datetime.fromtimestamp(
            raw_ts, tz=datetime.timezone.utc
        ).isoformat()
    except (ValueError, OSError, OverflowError):
        return None


def collect_process_info() -> Dict[str, Any]:
    """
    Safely enumerates running processes and gathers read-only forensic metadata.

    Handles psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess,
    and missing attributes gracefully so that individual inaccessible processes
    do not terminate the collection run.

    Returns:
        JSON-serializable dictionary adhering to the JOCKY collector schema.
    """
    process_records: List[Dict[str, Any]] = []

    # One parent-PID table for the whole snapshot. On Windows psutil rebuilds
    # the full process table for every Process.ppid() call, which made this
    # collector take seconds (one table scan per process).
    ppid_map: Dict[int, int] = {}
    platform_ppid_map = getattr(psutil._psplatform, "ppid_map", None)
    if callable(platform_ppid_map):
        try:
            ppid_map = platform_ppid_map()
        except Exception:
            ppid_map = {}

    attrs = ["pid", "name", "cmdline", "username", "exe", "cpu_percent", "memory_percent", "status", "create_time"]
    if not ppid_map:
        attrs.append("ppid")

    try:
        # ad_value=None turns AccessDenied on any single attribute into None.
        # Those fields are not re-read: asking again is denied again and only
        # doubles the cost for every protected process.
        proc_iter = psutil.process_iter(attrs=attrs, ad_value=None)
    except Exception:
        proc_iter = []

    for proc in proc_iter:
        info = getattr(proc, "info", None) or {}
        try:
            pid = info.get("pid", proc.pid)
            ppid = ppid_map.get(pid) if ppid_map else info.get("ppid")
            cmdline = info.get("cmdline")
            cmdline = [str(arg) for arg in cmdline] if isinstance(cmdline, list) else None
            cpu_percent = info.get("cpu_percent")
            mem_percent = info.get("memory_percent")
            process_records.append({
                "pid": pid,
                "ppid": ppid,
                "name": info.get("name") or "unknown",
                "cmdline": cmdline,
                "username": info.get("username") or None,
                "exe": info.get("exe") or None,
                "cpu_percent": round(cpu_percent, 2) if isinstance(cpu_percent, (int, float)) else None,
                "memory_percent": round(mem_percent, 2) if isinstance(mem_percent, (int, float)) else None,
                "status": info.get("status") or "unknown",
                "create_time": _safe_format_timestamp(info.get("create_time")),
            })
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            # The process exited or is fully protected; skip it
            continue
        except Exception:
            continue

    return {
        "collector": "processes",
        "read_only": True,
        "timestamp_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "processes": process_records,
        "count": len(process_records),
    }
