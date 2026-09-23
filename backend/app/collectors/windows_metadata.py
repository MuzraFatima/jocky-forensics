"""
JOCKY Safe Windows Forensic Metadata & Registry Collector

Authorized read-only digital forensic collector for Windows autoruns/persistence,
system services, OS build metadata, and forensic environment variables.

Safety Invariants:
- Strictly read-only: uses winreg in KEY_READ mode only. Never creates or alters keys.
- Does not start, stop, pause, or reconfigure any Windows service.
- Gracefully handles non-Windows platforms and missing hives without crashing.
"""

import datetime
import os
import platform
from typing import Any, Dict, List, Optional
import psutil

from .provenance import create_provenance, generate_collector_evidence_id


def _safe_epoch_to_iso(epoch_ts: Optional[int]) -> Optional[str]:
    """Safely convert epoch timestamp integer to ISO 8601 UTC string."""
    if not epoch_ts or epoch_ts <= 0:
        return None
    try:
        return datetime.datetime.fromtimestamp(epoch_ts, tz=datetime.timezone.utc).isoformat()
    except Exception:
        return None


def _read_registry_run_keys() -> List[Dict[str, Any]]:
    """
    Safely reads autorun / persistence values from standard Windows registry locations.
    Uses winreg with KEY_READ only.
    """
    entries: List[Dict[str, Any]] = []
    if platform.system() != "Windows":
        return entries

    try:
        import winreg

        targets = [
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "HKLM_Run"),
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", "HKLM_RunOnce"),
            (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "HKCU_Run"),
            (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", "HKCU_RunOnce"),
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run", "HKLM_WoW64_Run"),
        ]

        for hkey, subkey_path, hive_label in targets:
            try:
                with winreg.OpenKey(hkey, subkey_path, 0, winreg.KEY_READ) as key:
                    values_count, _, _ = winreg.QueryInfoKey(key)
                    for i in range(values_count):
                        try:
                            name, val, val_type = winreg.EnumValue(key, i)
                            entries.append({
                                "hive": hive_label,
                                "path": subkey_path,
                                "entry_name": name,
                                "command": str(val),
                                "type": val_type,
                            })
                        except Exception:
                            continue
            except (FileNotFoundError, PermissionError):
                continue
            except Exception:
                continue

    except Exception:
        pass

    return entries


def _read_windows_os_registry_metadata() -> Dict[str, Any]:
    """
    Safely reads Windows NT CurrentVersion registry metadata.
    """
    metadata: Dict[str, Any] = {
        "platform": platform.platform(),
        "release": platform.release(),
        "version": platform.version(),
    }
    if platform.system() != "Windows":
        return metadata

    try:
        import winreg
        key_path = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion"
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path, 0, winreg.KEY_READ) as key:
            fields = [
                ("ProductName", "product_name"),
                ("DisplayVersion", "display_version"),
                ("CurrentBuildNumber", "build_number"),
                ("UBR", "ubr"),
                ("EditionID", "edition_id"),
                ("InstallDate", "install_date_raw"),
                ("RegisteredOwner", "registered_owner"),
            ]
            for reg_name, out_name in fields:
                try:
                    val, _ = winreg.QueryValueEx(key, reg_name)
                    metadata[out_name] = val
                except FileNotFoundError:
                    metadata[out_name] = None
                except Exception:
                    metadata[out_name] = None

            # Convert raw install date if present
            raw_install = metadata.get("install_date_raw")
            if isinstance(raw_install, int):
                metadata["install_date"] = _safe_epoch_to_iso(raw_install)

    except Exception:
        pass

    return metadata


def _collect_windows_services(max_services: int = 150) -> List[Dict[str, Any]]:
    """
    Safely enumerates Windows services using psutil.win_service_iter().
    Non-destructive, read-only status querying.
    """
    service_records: List[Dict[str, Any]] = []
    if platform.system() != "Windows" or not hasattr(psutil, "win_service_iter"):
        return service_records

    try:
        for s in psutil.win_service_iter():
            if len(service_records) >= max_services:
                break
            try:
                info = s.as_dict()
                service_records.append({
                    "name": info.get("name"),
                    "display_name": info.get("display_name"),
                    "status": info.get("status"),
                    "start_type": info.get("start_type"),
                    "binpath": info.get("binpath"),
                    "username": info.get("username"),
                    "pid": info.get("pid"),
                })
            except Exception:
                continue
    except Exception:
        pass

    return service_records


def _collect_forensic_environment() -> Dict[str, Optional[str]]:
    """Gathers key environment variables of forensic interest."""
    env_keys = [
        "COMPUTERNAME", "USERDOMAIN", "OS", "PROCESSOR_ARCHITECTURE",
        "NUMBER_OF_PROCESSORS", "COMSPEC", "SYSTEMROOT", "WINDIR",
        "PROGRAMFILES", "PROGRAMDATA", "TEMP", "TMP", "PATH"
    ]
    return {k: os.environ.get(k) for k in env_keys}


def collect_windows_metadata() -> Dict[str, Any]:
    """
    Safely collects Windows forensic metadata, including registry autorun entries,
    services, OS build telemetry, and environmental configuration.

    Returns:
        Structured JSON-serializable dictionary adhering to JOCKY collector schema.
    """
    autoruns = _read_registry_run_keys()
    os_meta = _read_windows_os_registry_metadata()
    services = _collect_windows_services(max_services=150)
    env_vars = _collect_forensic_environment()

    provenance = create_provenance(
        collector_name="windows_metadata",
        method="winreg_autorun_and_psutil_services",
    )

    total_count = len(autoruns) + len(services)

    return {
        "collector": "windows_metadata",
        "collector_version": "1.0.0",
        "read_only": True,
        "evidence_id": generate_collector_evidence_id("windows_metadata"),
        "timestamp_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "provenance": provenance,
        "os_metadata": os_meta,
        "autoruns": autoruns,
        "autoruns_count": len(autoruns),
        "services": services,
        "services_count": len(services),
        "environment": env_vars,
        "count": total_count,
    }


def collect_registry_info() -> Dict[str, Any]:
    """
    Convenience alias focusing explicitly on registry persistence and run keys.
    """
    meta = collect_windows_metadata()
    return {
        "collector": "registry",
        "collector_version": "1.0.0",
        "read_only": True,
        "evidence_id": generate_collector_evidence_id("registry"),
        "timestamp_utc": meta["timestamp_utc"],
        "provenance": create_provenance("registry", "winreg_read_only_persistence_query"),
        "autoruns": meta["autoruns"],
        "count": meta["autoruns_count"],
        "os_metadata": meta["os_metadata"],
    }
