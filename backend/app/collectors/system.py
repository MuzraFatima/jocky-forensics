"""
JOCKY Safe System Metadata Collector

Authorized read-only digital forensic collector for system environment,
hardware parameters, kernel/OS release, memory metrics, and boot time.

Safety Invariants:
- Strictly read-only: does not modify any system state, registry, or filesystem.
- No shell execution: uses Python standard library and psutil C-bindings.
- No evasion, stealth, bypass, or hooking.
"""

import datetime
import getpass
import os
import platform
import time
from typing import Any, Dict

import psutil


def _get_current_username() -> str:
    """Safely obtain current username across platforms."""
    try:
        return getpass.getuser()
    except Exception:
        return os.environ.get("USERNAME") or os.environ.get("USER") or "unknown"


def collect_system_info() -> Dict[str, Any]:
    """
    Collects safe, read-only system metadata.

    Returns a clean, JSON-serializable dictionary.
    """
    # 1. Virtual memory metrics
    vm = psutil.virtual_memory()

    # 2. Boot time & uptime
    boot_timestamp = psutil.boot_time()
    boot_time_iso = datetime.datetime.fromtimestamp(
        boot_timestamp, tz=datetime.timezone.utc
    ).isoformat()
    uptime_seconds = round(time.time() - boot_timestamp, 2)

    # 3. CPU hardware metrics
    cpu_freq = psutil.cpu_freq()
    cpu_info: Dict[str, Any] = {
        "count_logical": psutil.cpu_count(logical=True),
        "count_physical": psutil.cpu_count(logical=False),
        "processor": platform.processor() or "unknown",
    }
    if cpu_freq:
        cpu_info["frequency_current_mhz"] = round(cpu_freq.current, 2)
        if cpu_freq.max:
            cpu_info["frequency_max_mhz"] = round(cpu_freq.max, 2)

    # 4. Memory metrics
    memory_info: Dict[str, Any] = {
        "total_bytes": vm.total,
        "available_bytes": vm.available,
        "used_bytes": vm.used,
        "percent_used": vm.percent,
        "total_human": f"{round(vm.total / (1024 ** 3), 2)} GB",
        "available_human": f"{round(vm.available / (1024 ** 3), 2)} GB",
    }

    # 5. Aggregate standardized system forensic artifact
    system_artifact: Dict[str, Any] = {
        "collector": "system",
        "read_only": True,
        "hostname": platform.node() or "unknown",
        "os": platform.system() or "unknown",
        "os_version": f"{platform.release()} ({platform.version()})",
        "architecture": platform.machine() or "unknown",
        "username": _get_current_username(),
        "cpu": cpu_info,
        "memory": memory_info,
        "boot_time": boot_time_iso,
        "uptime_seconds": uptime_seconds,
        "timestamp_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
    }

    return system_artifact
