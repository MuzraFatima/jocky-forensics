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

    # Required process attributes
    attrs = [
        "pid",
        "ppid",
        "name",
        "cmdline",
        "username",
        "exe",
        "cpu_percent",
        "memory_percent",
        "status",
        "create_time",
    ]

    try:
        # ad_value=None ensures AccessDenied during individual attribute reads
        # populates the dictionary with None rather than raising an immediate exception
        proc_iter = psutil.process_iter(attrs=attrs, ad_value=None)
    except Exception:
        # Fallback in the unlikely event process_iter itself cannot initialize
        proc_iter = []

    for proc in proc_iter:
        try:
            info = proc.info if hasattr(proc, "info") and proc.info else {}

            pid = info.get("pid")
            if pid is None and hasattr(proc, "pid"):
                try:
                    pid = proc.pid
                except Exception:
                    pid = None

            # Parent PID fallback
            ppid = info.get("ppid")
            if ppid is None and hasattr(proc, "ppid"):
                try:
                    ppid = proc.ppid()
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    ppid = None
                except Exception:
                    ppid = None

            # Name fallback
            name = info.get("name")
            if not name:
                try:
                    name = proc.name()
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    name = "unknown"
                except Exception:
                    name = "unknown"

            # Command line fallback
            cmdline = info.get("cmdline")
            if cmdline is None and hasattr(proc, "cmdline"):
                try:
                    cmdline = proc.cmdline()
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    cmdline = None
                except Exception:
                    cmdline = None
            if isinstance(cmdline, list):
                cmdline = [str(arg) for arg in cmdline]
            else:
                cmdline = None

            # Username
            username = info.get("username")
            if not username:
                try:
                    username = proc.username()
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    username = None
                except Exception:
                    username = None

            # Executable path
            exe = info.get("exe")
            if not exe:
                try:
                    exe = proc.exe()
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    exe = None
                except Exception:
                    exe = None

            # CPU utilization (non-blocking snapshot)
            cpu_percent = info.get("cpu_percent")
            if cpu_percent is None:
                try:
                    cpu_percent = proc.cpu_percent(interval=None)
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    cpu_percent = None
                except Exception:
                    cpu_percent = None
            if isinstance(cpu_percent, (int, float)):
                cpu_percent = round(cpu_percent, 2)

            # Memory utilization percentage
            mem_percent = info.get("memory_percent")
            if mem_percent is None:
                try:
                    mem_percent = proc.memory_percent()
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    mem_percent = None
                except Exception:
                    mem_percent = None
            if isinstance(mem_percent, (int, float)):
                mem_percent = round(mem_percent, 2)

            # Status
            status = info.get("status")
            if not status:
                try:
                    status = proc.status()
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    status = "unknown"
                except Exception:
                    status = "unknown"

            # Creation time
            create_time_raw = info.get("create_time")
            if create_time_raw is None:
                try:
                    create_time_raw = proc.create_time()
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    create_time_raw = None
                except Exception:
                    create_time_raw = None
            create_time_iso = _safe_format_timestamp(create_time_raw)

            process_records.append({
                "pid": pid,
                "ppid": ppid,
                "name": name or "unknown",
                "cmdline": cmdline,
                "username": username or None,
                "exe": exe or None,
                "cpu_percent": cpu_percent,
                "memory_percent": mem_percent,
                "status": status or "unknown",
                "create_time": create_time_iso,
            })

        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            # Gracefully ignore individual process termination or access restrictions
            continue
        except Exception:
            # Shield collector from any unforeseen per-process error
            continue

    return {
        "collector": "processes",
        "read_only": True,
        "timestamp_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "processes": process_records,
        "count": len(process_records),
    }
