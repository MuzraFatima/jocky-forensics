"""
JOCKY Safe Users & Sessions Forensic Collector

Authorized read-only digital forensic collector for user identity, active logon
sessions, terminal descriptors, user profile lists, and security context.

Safety Invariants:
- Strictly read-only: does not modify accounts, reset passwords, or alter privileges.
- No privilege escalation or elevation attempts.
- Gracefully handles non-Windows platforms and missing registry keys without crashing.
"""

import ctypes
import datetime
import getpass
import os
import platform
from typing import Any, Dict, List, Optional
import psutil

from .provenance import create_provenance, generate_collector_evidence_id


def _safe_format_ts(epoch_ts: Optional[float]) -> Optional[str]:
    """Safely format epoch timestamp to ISO 8601 UTC string."""
    if not epoch_ts or epoch_ts <= 0:
        return None
    try:
        return datetime.datetime.fromtimestamp(epoch_ts, tz=datetime.timezone.utc).isoformat()
    except (ValueError, OSError, OverflowError):
        return None


def _check_admin_status() -> bool:
    """Safely determine if current execution context has administrative / root rights."""
    try:
        if platform.system() == "Windows":
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        return os.getuid() == 0  # type: ignore[attr-defined]
    except Exception:
        return False


def _collect_windows_profile_list() -> List[Dict[str, Any]]:
    """
    Safely reads user profiles registered in Windows Registry ProfileList.
    Path: HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList
    This registry path is publicly readable without administrative elevation.
    """
    profiles: List[Dict[str, Any]] = []
    if platform.system() != "Windows":
        return profiles

    try:
        import winreg
        key_path = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList"
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path, 0, winreg.KEY_READ) as key:
            subkeys_count, _, _ = winreg.QueryInfoKey(key)
            for i in range(subkeys_count):
                try:
                    sid = winreg.EnumKey(key, i)
                    with winreg.OpenKey(key, sid, 0, winreg.KEY_READ) as subkey:
                        profile_path = None
                        try:
                            profile_path, _ = winreg.QueryValueEx(subkey, "ProfileImagePath")
                        except FileNotFoundError:
                            pass

                        # Determine friendly username from profile path
                        username_hint = os.path.basename(profile_path) if profile_path else sid

                        profiles.append({
                            "sid": sid,
                            "profile_image_path": str(profile_path) if profile_path else None,
                            "account_name": username_hint,
                            "is_system_sid": sid.startswith("S-1-5-18") or sid.startswith("S-1-5-19") or sid.startswith("S-1-5-20"),
                        })
                except Exception:
                    continue
    except Exception:
        pass

    return profiles


def _enumerate_home_directories() -> List[str]:
    """Inspects C:\\Users (Windows), /Users (macOS), or /home (Linux) for user account directories."""
    discovered: List[str] = []
    if platform.system() == "Windows":
        base_dir = r"C:\Users"
    elif platform.system() in ("Darwin", "macOS"):
        base_dir = "/Users"
    else:
        base_dir = "/home"
    if os.path.exists(base_dir):
        try:
            with os.scandir(base_dir) as it:
                for entry in it:
                    if entry.is_dir(follow_symlinks=False):
                        if entry.name not in ("All Users", "Default", "Default User", "Public", "Shared"):
                            discovered.append(entry.name)
        except Exception:
            pass
    return discovered


def collect_users_info() -> Dict[str, Any]:
    """
    Safely enumerates active user sessions, security context, and registered user profiles.

    Returns:
        JSON-serializable dictionary conforming to the JOCKY collector schema.
    """
    # 1. Active sessions via psutil
    active_sessions: List[Dict[str, Any]] = []
    try:
        raw_users = psutil.users()
        for u in raw_users:
            started_iso = _safe_format_ts(getattr(u, "started", None))
            active_sessions.append({
                "username": getattr(u, "name", "unknown"),
                "terminal": getattr(u, "terminal", None) or "console",
                "host": getattr(u, "host", None) or "localhost",
                "started_time": started_iso,
                "pid": getattr(u, "pid", None),
            })
    except Exception:
        active_sessions = []

    # 2. Current operator context
    current_username = "unknown"
    try:
        current_username = getpass.getuser()
    except Exception:
        current_username = os.environ.get("USERNAME") or os.environ.get("USER") or "unknown"

    current_user_context: Dict[str, Any] = {
        "username": current_username,
        "is_admin": _check_admin_status(),
        "domain": os.environ.get("USERDOMAIN") or platform.node() or "WORKGROUP",
        "logon_server": os.environ.get("LOGONSERVER"),
        "session_name": os.environ.get("SESSIONNAME") or "Console",
        "home_path": os.environ.get("USERPROFILE") or os.environ.get("HOME") or "unknown",
        "client_name": os.environ.get("CLIENTNAME"),  # Present in RDP sessions
    }

    # 3. User profiles and discovered account paths
    registered_profiles = _collect_windows_profile_list()
    discovered_homes = _enumerate_home_directories()

    provenance = create_provenance(
        collector_name="users",
        method="psutil_users_and_registry_profilelist",
    )

    total_count = len(active_sessions) + len(registered_profiles)

    return {
        "collector": "users",
        "collector_version": "1.0.0",
        "read_only": True,
        "evidence_id": generate_collector_evidence_id("users"),
        "timestamp_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "provenance": provenance,
        "active_sessions": active_sessions,
        "active_sessions_count": len(active_sessions),
        "current_user": current_user_context,
        "user_profiles": registered_profiles,
        "discovered_user_homes": discovered_homes,
        "count": total_count,
    }
