"""
JOCKY Endpoint Agent — Collector Adapter

Bridges the Endpoint Agent to the existing cross-platform forensic collectors
in `backend/app/collectors/` with ZERO code duplication.

Safety Invariants:
- Strictly read-only forensic inspection.
- Enforces collector allowlist.
- Rejects dangerous commands, scripts, or path traversal directives.
"""

from typing import Any, Dict, Optional, Set

from backend.app.collectors.dispatcher import (
    dispatch_files_info,
    dispatch_network_info,
    dispatch_persistence_info,
    dispatch_process_info,
    dispatch_system_info,
    dispatch_users_info,
    is_windows,
    win_collect_registry,
)

# Strict allowlist of authorized collector names
ALLOWED_COLLECTOR_NAMES: Set[str] = {
    "system",
    "processes",
    "network",
    "files",
    "users",
    "registry",
    "windows_metadata",
}


class CollectorAdapter:
    """
    Adapter that executes authorized forensic collections on the active endpoint
    by routing directly to the battle-tested implementations in `backend/app/collectors/`.
    """

    @classmethod
    def get_allowed_collectors(cls) -> Set[str]:
        """Returns the set of permitted collector names."""
        return set(ALLOWED_COLLECTOR_NAMES)

    def is_collector_allowed(self, collector_name: str) -> bool:
        """Verifies if a collector is within the authorized allowlist."""
        return collector_name.strip().lower() in ALLOWED_COLLECTOR_NAMES

    def collect(
        self,
        collector_name: str,
        params: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Executes the specified forensic collector locally and returns normalized telemetry.

        Raises:
            ValueError: If the collector name is unsupported or unauthorized.
        """
        clean_name = collector_name.strip().lower()
        if not self.is_collector_allowed(clean_name):
            raise ValueError(
                f"Unauthorized collector '{collector_name}'. "
                f"Allowed collectors: {sorted(list(ALLOWED_COLLECTOR_NAMES))}"
            )

        safe_params = params or {}

        if clean_name == "system":
            return dispatch_system_info()

        elif clean_name == "processes":
            return dispatch_process_info()

        elif clean_name == "network":
            return dispatch_network_info()

        elif clean_name == "files":
            target_path = safe_params.get("target_path")
            max_files = int(safe_params.get("max_files", 50))
            return dispatch_files_info(target_path=target_path, max_files=max_files)

        elif clean_name == "users":
            return dispatch_users_info()

        elif clean_name in ("registry", "windows_metadata"):
            if is_windows():
                return win_collect_registry()
            # On Linux/macOS, gather platform-specific persistence autoruns
            return dispatch_persistence_info()

        else:
            raise ValueError(f"Unhandled collector implementation: '{clean_name}'")
