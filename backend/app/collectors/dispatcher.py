"""
JOCKY Forensic Collector Dispatcher

Provides transparent cross-platform dispatching between Windows and Linux/POSIX
forensic collector implementations while maintaining 100% schema parity:
- On Windows: routes to Win32/NTFS/Registry collectors.
- On Linux/POSIX: routes to /proc, /etc, crontab, and systemd collectors.
- Automatically normalizes differences so the correlation and timeline engines
  operate uniformly regardless of host OS.
"""

import platform
from typing import Any, Callable, Dict, Optional

# Windows collectors
from .files import collect_files_info as win_collect_files
from .network import collect_network_info as win_collect_network
from .processes import collect_process_info as win_collect_processes
from .system import collect_system_info as win_collect_system
from .users import collect_users_info as win_collect_users
from .windows_metadata import (
    collect_registry_info as win_collect_registry,
    collect_windows_metadata as win_collect_persistence,
)

# Linux collectors
from .linux_collectors import (
    collect_linux_files_info,
    collect_linux_network_info,
    collect_linux_persistence_info,
    collect_linux_process_info,
    collect_linux_system_info,
    collect_linux_users_info,
)


def get_current_platform() -> str:
    """Returns 'Windows', 'Linux', or the OS name detected by platform.system()."""
    return platform.system()


def is_windows() -> bool:
    return get_current_platform() == "Windows"


def is_linux() -> bool:
    return get_current_platform() == "Linux"


# ---------------------------------------------------------------------------
# Cross-Platform Dispatchers
# ---------------------------------------------------------------------------

def dispatch_system_info(root_dir: str = "/", force_platform: Optional[str] = None) -> Dict[str, Any]:
    """Collects system telemetry from the active host or forced platform."""
    plat = force_platform or get_current_platform()
    if plat == "Linux":
        return collect_linux_system_info(root_dir=root_dir)
    return win_collect_system()


def dispatch_process_info(root_dir: str = "/", force_platform: Optional[str] = None) -> Dict[str, Any]:
    """Collects running processes from the active host or forced platform."""
    plat = force_platform or get_current_platform()
    if plat == "Linux":
        return collect_linux_process_info(root_dir=root_dir)
    return win_collect_processes()


def dispatch_network_info(root_dir: str = "/", force_platform: Optional[str] = None) -> Dict[str, Any]:
    """Collects network socket telemetry from the active host or forced platform."""
    plat = force_platform or get_current_platform()
    if plat == "Linux":
        return collect_linux_network_info(root_dir=root_dir)
    return win_collect_network()


def dispatch_files_info(
    target_path: Optional[str] = None,
    root_dir: str = "/",
    max_files: int = 50,
    force_platform: Optional[str] = None,
) -> Dict[str, Any]:
    """Collects filesystem metadata and binary hashes."""
    plat = force_platform or get_current_platform()
    if plat == "Linux":
        return collect_linux_files_info(root_dir=root_dir, target_dir=target_path, max_files=max_files)
    return win_collect_files(target_path=target_path, max_files=max_files)


def dispatch_users_info(root_dir: str = "/", force_platform: Optional[str] = None) -> Dict[str, Any]:
    """Collects user identity and session telemetry."""
    plat = force_platform or get_current_platform()
    if plat == "Linux":
        return collect_linux_users_info(root_dir=root_dir)
    return win_collect_users()


def dispatch_persistence_info(root_dir: str = "/", force_platform: Optional[str] = None) -> Dict[str, Any]:
    """
    Collects persistence mechanisms:
    - On Windows: Run keys, Scheduled Tasks, Win32 Services.
    - On Linux: /etc/crontab, /etc/cron.d, systemd service units.
    """
    plat = force_platform or get_current_platform()
    if plat == "Linux":
        return collect_linux_persistence_info(root_dir=root_dir)
    return win_collect_persistence()


def get_platform_collectors(force_platform: Optional[str] = None) -> Dict[str, Callable]:
    """
    Returns a unified mapping of canonical collector names to their platform-aware
    collector functions.
    """
    plat = force_platform or get_current_platform()
    if plat == "Linux":
        return {
            "system": lambda **kw: collect_linux_system_info(**kw),
            "processes": lambda **kw: collect_linux_process_info(**kw),
            "network": lambda **kw: collect_linux_network_info(**kw),
            "files": lambda **kw: collect_linux_files_info(**kw),
            "users": lambda **kw: collect_linux_users_info(**kw),
            "persistence": lambda **kw: collect_linux_persistence_info(**kw),
            "cron": lambda **kw: collect_linux_persistence_info(**kw),
            "systemd": lambda **kw: collect_linux_persistence_info(**kw),
        }
    else:
        return {
            "system": win_collect_system,
            "processes": win_collect_processes,
            "network": win_collect_network,
            "files": win_collect_files,
            "users": win_collect_users,
            "windows_metadata": win_collect_persistence,
            "registry": win_collect_registry,
            "persistence": win_collect_persistence,
        }
