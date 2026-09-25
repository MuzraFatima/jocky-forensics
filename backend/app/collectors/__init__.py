"""
JOCKY Safe Forensic Collectors Module

Houses authorized, read-only collectors designed for forensic evidence acquisition.
Cross-Platform support for Windows, Linux/Ubuntu, and macOS (Darwin) with identical normalized schema.
"""

from typing import Any, Callable, Dict

from .files import collect_files_info
from .network import collect_network_info
from .processes import collect_process_info
from .system import collect_system_info
from .users import collect_users_info
from .windows_metadata import collect_registry_info, collect_windows_metadata
from .provenance import create_provenance, generate_collector_evidence_id
from .linux_collectors import (
    collect_linux_system_info,
    collect_linux_process_info,
    collect_linux_network_info,
    collect_linux_files_info,
    collect_linux_users_info,
    collect_linux_persistence_info,
)
from .macos_collectors import (
    collect_macos_system_info,
    collect_macos_process_info,
    collect_macos_network_info,
    collect_macos_files_info,
    collect_macos_users_info,
    collect_macos_persistence_info,
)
from .dispatcher import (
    get_current_platform,
    get_platform_collectors,
    dispatch_system_info,
    dispatch_process_info,
    dispatch_network_info,
    dispatch_files_info,
    dispatch_users_info,
    dispatch_persistence_info,
    is_windows,
    is_linux,
    is_macos,
    is_darwin,
)


def get_collectors() -> Dict[str, Callable[..., Dict[str, Any]]]:
    """
    Returns available forensic collector implementations for the active host platform.
    Ensures backward compatibility with Phase 3 tests while supporting cross-platform (Windows, Linux, macOS).
    """
    current_os = get_current_platform()
    if current_os in ("Darwin", "macOS"):
        return {
            "system": collect_macos_system_info,
            "processes": collect_macos_process_info,
            "network": collect_macos_network_info,
            "files": collect_macos_files_info,
            "users": collect_macos_users_info,
            "persistence": collect_macos_persistence_info,
            "launch_daemons": collect_macos_persistence_info,
            "launch_agents": collect_macos_persistence_info,
            "windows_metadata": collect_macos_persistence_info,
            "registry": collect_macos_persistence_info,
        }
    elif current_os == "Linux":
        return {
            "system": collect_linux_system_info,
            "processes": collect_linux_process_info,
            "network": collect_linux_network_info,
            "files": collect_linux_files_info,
            "users": collect_linux_users_info,
            "persistence": collect_linux_persistence_info,
            "cron": collect_linux_persistence_info,
            "systemd": collect_linux_persistence_info,
            "windows_metadata": collect_linux_persistence_info,
            "registry": collect_linux_persistence_info,
        }

    return {
        "system": collect_system_info,
        "processes": collect_process_info,
        "network": collect_network_info,
        "files": collect_files_info,
        "users": collect_users_info,
        "windows_metadata": collect_windows_metadata,
        "registry": collect_registry_info,
        "persistence": collect_windows_metadata,
    }


__all__ = [
    "collect_system_info",
    "collect_process_info",
    "collect_network_info",
    "collect_files_info",
    "collect_users_info",
    "collect_windows_metadata",
    "collect_registry_info",
    "collect_linux_system_info",
    "collect_linux_process_info",
    "collect_linux_network_info",
    "collect_linux_files_info",
    "collect_linux_users_info",
    "collect_linux_persistence_info",
    "collect_macos_system_info",
    "collect_macos_process_info",
    "collect_macos_network_info",
    "collect_macos_files_info",
    "collect_macos_users_info",
    "collect_macos_persistence_info",
    "get_current_platform",
    "get_platform_collectors",
    "dispatch_system_info",
    "dispatch_process_info",
    "dispatch_network_info",
    "dispatch_files_info",
    "dispatch_users_info",
    "dispatch_persistence_info",
    "is_windows",
    "is_linux",
    "is_macos",
    "is_darwin",
    "create_provenance",
    "generate_collector_evidence_id",
    "get_collectors",
]
