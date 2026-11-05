"""
JOCKY operation catalog.

One entry per IR operation the language can emit. Each entry declares the
capability label the runtime policy authorises, the schema the operation's
result follows, and the platforms whose adapters implement it. The compiler
stamps this onto every IR operation (blueprint §4.5) and the platform
backend uses it to report unsupported operations explicitly.

The capability labels must stay identical to the runtime allow-list in
backend/app/engine/ir_policy.py; a test keeps the two in step.
"""

from dataclasses import dataclass
from typing import Dict, FrozenSet, Optional, Tuple

ALL_PLATFORMS: FrozenSet[str] = frozenset({"WINDOWS", "LINUX", "MACOS"})
WINDOWS_ONLY: FrozenSet[str] = frozenset({"WINDOWS"})
WINDOWS_AND_LINUX: FrozenSet[str] = frozenset({"WINDOWS", "LINUX"})


@dataclass(frozen=True)
class OperationSpec:
    capability: str
    output_schema: str
    platforms: FrozenSet[str]
    description: str


# (IR type, IR target or report format) -> spec. A None target is the bare form.
OPERATIONS: Dict[Tuple[str, Optional[str]], OperationSpec] = {
    ("COLLECT", "SYSTEM"): OperationSpec(
        "COLLECT_SYSTEM", "jocky.system.v1", ALL_PLATFORMS, "Operating system, host and uptime metadata"
    ),
    ("COLLECT", "PROCESSES"): OperationSpec(
        "COLLECT_PROCESSES", "jocky.process_list.v1", ALL_PLATFORMS, "Running processes and parent relationships"
    ),
    ("COLLECT", "NETWORK"): OperationSpec(
        "COLLECT_NETWORK", "jocky.network.v1", ALL_PLATFORMS, "Interfaces, sockets and active connections"
    ),
    ("COLLECT", "FILES"): OperationSpec(
        "COLLECT_FILES", "jocky.file_list.v1", ALL_PLATFORMS, "File metadata and SHA-256 hashes under a path"
    ),
    ("COLLECT", "USERS"): OperationSpec(
        "COLLECT_USERS", "jocky.users.v1", ALL_PLATFORMS, "Local accounts and sessions"
    ),
    ("COLLECT", "REGISTRY"): OperationSpec(
        "COLLECT_REGISTRY", "jocky.registry.v1", WINDOWS_ONLY, "Windows registry persistence keys"
    ),
    ("COLLECT", "WINDOWS_METADATA"): OperationSpec(
        "COLLECT_WINDOWS_METADATA", "jocky.windows_metadata.v1", WINDOWS_ONLY, "Windows-specific host metadata"
    ),
    ("COLLECT", "SERVICES"): OperationSpec(
        "COLLECT_SERVICES", "jocky.services.v1", ALL_PLATFORMS, "Installed services, systemd units or LaunchDaemons"
    ),
    ("COLLECT", "STARTUP"): OperationSpec(
        "COLLECT_STARTUP", "jocky.startup.v1", ALL_PLATFORMS, "Run keys, startup folders, cron, autostart"
    ),
    ("COLLECT", "DRIVERS"): OperationSpec(
        "COLLECT_DRIVERS", "jocky.drivers.v1", WINDOWS_AND_LINUX, "Kernel drivers or loaded kernel modules"
    ),
    ("COLLECT", "LISTENING_PORTS"): OperationSpec(
        "COLLECT_LISTENING_PORTS", "jocky.listening_ports.v1", ALL_PLATFORMS, "Listening sockets and owners"
    ),
    ("COLLECT", "DNS"): OperationSpec(
        "COLLECT_DNS", "jocky.dns.v1", ALL_PLATFORMS, "DNS resolver configuration and hosts file"
    ),
    ("ANALYZE", None): OperationSpec(
        "ANALYZE_PROCESS_NETWORK", "jocky.analysis.v1", ALL_PLATFORMS, "Process and network correlation"
    ),
    ("ANALYZE", "PROCESS_NETWORK"): OperationSpec(
        "ANALYZE_PROCESS_NETWORK", "jocky.analysis.v1", ALL_PLATFORMS, "Process and network correlation"
    ),
    ("ANALYZE", "DETECTIONS"): OperationSpec(
        "ANALYZE_DETECTIONS", "jocky.detections.v1", ALL_PLATFORMS, "Declarative detection rules and correlation"
    ),
    ("VERIFY", "INTEGRITY"): OperationSpec(
        "VERIFY_INTEGRITY", "jocky.integrity.v1", ALL_PLATFORMS, "Re-hash stored evidence and compare"
    ),
    ("REPORT", None): OperationSpec("REPORT_JSON", "jocky.report.v1", ALL_PLATFORMS, "JSON investigation report"),
    ("REPORT", "JSON"): OperationSpec("REPORT_JSON", "jocky.report.v1", ALL_PLATFORMS, "JSON investigation report"),
    ("REPORT", "HTML"): OperationSpec("REPORT_HTML", "jocky.report.v1", ALL_PLATFORMS, "HTML investigation report"),
    ("REPORT", "MD"): OperationSpec("REPORT_MD", "jocky.report.v1", ALL_PLATFORMS, "Markdown investigation report"),
    ("REPORT", "MARKDOWN"): OperationSpec(
        "REPORT_MD", "jocky.report.v1", ALL_PLATFORMS, "Markdown investigation report"
    ),
}


def lookup(op_type: str, target: Optional[str]) -> Optional[OperationSpec]:
    """Find the catalog entry for an IR operation, or None if it is not a known capability."""
    return OPERATIONS.get((op_type.upper(), target.upper() if target else None))
