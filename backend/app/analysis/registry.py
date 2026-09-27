"""
JOCKY Advanced Technique Registry (Phase 2)

Maintains the authoritative catalog of advanced forensic and threat detection techniques
that JOCKY can safely analyze or detect across Windows, Linux, and macOS endpoints.

Invariants:
- Strictly read-only and defensive.
- NO offensive execution, payload delivery, code injection, or security evasion logic.
- Grounded in existing collectors, correlation graphs, rules, and Evidence Vault.
"""

from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field


class AnalysisStatus(str, Enum):
    """Implementation and detection status of a forensic technique."""
    IMPLEMENTED = "implemented"
    PARTIALLY_IMPLEMENTED = "partially_implemented"
    DETECTABLE = "detectable"
    PLANNED = "planned"
    NOT_IMPLEMENTED = "not_implemented"


class TechniqueCategory(str, Enum):
    """Categorical classification of forensic & threat detection techniques."""
    EXECUTION_DEFENSE_EVASION = "Execution & Defense Evasion"
    PROCESS_HIERARCHY_INJECTION = "Process Ancestry & Injection"
    COMMAND_AND_CONTROL_NETWORK = "Command & Control and Network"
    PERSISTENCE_MECHANISMS = "Persistence Mechanisms"
    PRIVILEGE_DISCOVERY = "Privilege & Security Context"
    INTEGRITY_TAMPER_DETECTION = "Integrity & Tamper Detection"
    CROSS_ARTIFACT_CORRELATION = "Cross-Artifact Correlation"


class MitreMapping(BaseModel):
    """MITRE ATT&CK reference mapping."""
    model_config = ConfigDict(extra="forbid")

    id: str = Field(..., description="MITRE Technique ID (e.g., T1036.005)")
    name: str = Field(..., description="MITRE Technique Name")
    tactic: str = Field(..., description="Primary MITRE ATT&CK Tactic")
    url: Optional[str] = Field(None, description="Official MITRE ATT&CK reference URL")


class TechniqueEntry(BaseModel):
    """Authoritative registry entry for a safe forensic analysis technique."""
    model_config = ConfigDict(extra="forbid")

    technique_id: str = Field(..., description="Unique JOCKY technique identifier")
    technique_name: str = Field(..., description="Human-readable technique name")
    category: TechniqueCategory = Field(..., description="Primary analytical category")
    observable_indicators: List[str] = Field(..., description="Observable digital forensic artifacts/indicators")
    required_evidence: List[str] = Field(..., description="Evidence sources required to evaluate technique")
    relevant_collector: str = Field(..., description="Collector module providing raw telemetry")
    analysis_status: AnalysisStatus = Field(..., description="Current status in JOCKY repository")
    mitre_mapping: Optional[MitreMapping] = Field(None, description="Associated MITRE ATT&CK mapping if applicable")
    demo_availability: bool = Field(False, description="Whether automated demonstration test data is available")
    description: str = Field(..., description="Forensic technical description of the technique")
    detection_rule_id: Optional[str] = Field(None, description="Internal detection rule ID (e.g. RULE-001)")


# ── Canonical Technique Definitions ──────────────────────────────────────────

TECHNIQUES_DATA: List[TechniqueEntry] = [
    TechniqueEntry(
        technique_id="TECH-TMP-EXEC",
        technique_name="Execution from Temporary Directories",
        category=TechniqueCategory.EXECUTION_DEFENSE_EVASION,
        observable_indicators=[
            "Process executable path contains volatile temporary directory paths",
            "Path pattern matches \\temp, \\tmp, \\appdata\\local\\temp, or \\windows\\temp",
            "Short-lived executable launch without legitimate installation footprint"
        ],
        required_evidence=["processes"],
        relevant_collector="processes",
        analysis_status=AnalysisStatus.IMPLEMENTED,
        mitre_mapping=MitreMapping(
            id="T1036.005",
            name="Masquerading: Match Legitimate Name or Location",
            tactic="Defense Evasion",
            url="https://attack.mitre.org/techniques/T1036/005/"
        ),
        demo_availability=True,
        description="Identifies binaries executing out of user or system temporary paths where dropped malware payloads typically run.",
        detection_rule_id="RULE-001"
    ),
    TechniqueEntry(
        technique_id="TECH-PROC-SPAWN",
        technique_name="Suspicious Parent-Child Process Spawning",
        category=TechniqueCategory.PROCESS_HIERARCHY_INJECTION,
        observable_indicators=[
            "Productivity application (e.g., winword, excel, acrobat) spawns command interpreter",
            "Web browser (e.g., chrome, firefox) launches shell without administrative context",
            "Shell interpreter spawned with anomalous commandline arguments"
        ],
        required_evidence=["processes"],
        relevant_collector="processes",
        analysis_status=AnalysisStatus.IMPLEMENTED,
        mitre_mapping=MitreMapping(
            id="T1059.001",
            name="Command and Scripting Interpreter: PowerShell",
            tactic="Execution",
            url="https://attack.mitre.org/techniques/T1059/001/"
        ),
        demo_availability=True,
        description="Detects document macro or browser-based initial execution by analyzing parent-child process relationships.",
        detection_rule_id="RULE-002"
    ),
    TechniqueEntry(
        technique_id="TECH-NET-BACKDOOR",
        technique_name="Anomalous Outbound Network Socket",
        category=TechniqueCategory.COMMAND_AND_CONTROL_NETWORK,
        observable_indicators=[
            "Outbound connection established to high-risk or well-known exploit ports (4444, 1337, 6667, 31337)",
            "Non-standard service port utilized by unknown or unverified process binary",
            "Outbound TCP handshake to anomalous destination IP"
        ],
        required_evidence=["network", "processes"],
        relevant_collector="network",
        analysis_status=AnalysisStatus.IMPLEMENTED,
        mitre_mapping=MitreMapping(
            id="T1571",
            name="Non-Standard Port",
            tactic="Command and Control",
            url="https://attack.mitre.org/techniques/T1571/"
        ),
        demo_availability=True,
        description="Flags processes maintaining active network sockets directed toward known exploitation or backdoor ports.",
        detection_rule_id="RULE-003"
    ),
    TechniqueEntry(
        technique_id="TECH-PROC-HOLLOW",
        technique_name="Unmapped Binary Execution / Process Hollowing Indicator",
        category=TechniqueCategory.PROCESS_HIERARCHY_INJECTION,
        observable_indicators=[
            "Active running process with null or empty on-disk executable path",
            "Process executable inaccessible or deleted after execution start",
            "Disparity between running image memory name and on-disk file system record"
        ],
        required_evidence=["processes"],
        relevant_collector="processes",
        analysis_status=AnalysisStatus.IMPLEMENTED,
        mitre_mapping=MitreMapping(
            id="T1055",
            name="Process Injection",
            tactic="Defense Evasion, Privilege Escalation",
            url="https://attack.mitre.org/techniques/T1055/"
        ),
        demo_availability=True,
        description="Detects potential process hollowing or ephemeral in-memory execution by checking on-disk binary path availability.",
        detection_rule_id="RULE-004"
    ),
    TechniqueEntry(
        technique_id="TECH-REG-AUTORUN",
        technique_name="Suspicious Persistence Script Autorun",
        category=TechniqueCategory.PERSISTENCE_MECHANISMS,
        observable_indicators=[
            "Windows registry Run or RunOnce key invokes script interpreter (.vbs, .ps1, .bat, .cmd)",
            "Command contains powershell, wscript, or cscript with hidden window flags",
            "Autorun entry references non-standard application directories"
        ],
        required_evidence=["windows_metadata", "registry"],
        relevant_collector="windows_metadata",
        analysis_status=AnalysisStatus.IMPLEMENTED,
        mitre_mapping=MitreMapping(
            id="T1547.001",
            name="Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder",
            tactic="Persistence",
            url="https://attack.mitre.org/techniques/T1547/001/"
        ),
        demo_availability=True,
        description="Scans Windows registry autostart locations to detect persistence mechanisms executing scripts at boot or logon.",
        detection_rule_id="RULE-005"
    ),
    TechniqueEntry(
        technique_id="TECH-LOLBINS",
        technique_name="Living-off-the-Land Binaries (LOLBins) Execution",
        category=TechniqueCategory.EXECUTION_DEFENSE_EVASION,
        observable_indicators=[
            "Execution of certutil.exe with -urlcache or -decode arguments",
            "Execution of mshta.exe targeting HTTP/HTTPS remote resource",
            "Execution of bitsadmin.exe /transfer or curl.exe to retrieve external payload",
            "PowerShell invoked with -EncodedCommand or -WindowStyle Hidden"
        ],
        required_evidence=["processes"],
        relevant_collector="processes",
        analysis_status=AnalysisStatus.DETECTABLE,
        mitre_mapping=MitreMapping(
            id="T1036.003",
            name="Masquerading: Rename System Utilities",
            tactic="Defense Evasion",
            url="https://attack.mitre.org/techniques/T1036/003/"
        ),
        demo_availability=True,
        description="Identifies misuse of native operating system administrative utilities to execute arbitrary code or download staging artifacts."
    ),
    TechniqueEntry(
        technique_id="TECH-LINUX-PERSIST",
        technique_name="Linux Persistence via Cron or Systemd Anomaly",
        category=TechniqueCategory.PERSISTENCE_MECHANISMS,
        observable_indicators=[
            "Crontab entry invoking scripts located in volatile directories (/tmp, /var/tmp)",
            "Crontab entry piping remote curl/wget output directly into bash/sh",
            "Systemd service unit executing unmapped or non-standard binaries"
        ],
        required_evidence=["linux_persistence"],
        relevant_collector="linux_collectors",
        analysis_status=AnalysisStatus.DETECTABLE,
        mitre_mapping=MitreMapping(
            id="T1053.003",
            name="Scheduled Task/Job: Cron",
            tactic="Persistence",
            url="https://attack.mitre.org/techniques/T1053/003/"
        ),
        demo_availability=True,
        description="Inspects /etc/crontab, /etc/cron.*, and /etc/systemd/system to identify persistence mechanisms established on POSIX/Linux endpoints."
    ),
    TechniqueEntry(
        technique_id="TECH-MACOS-PERSIST",
        technique_name="macOS LaunchAgent / LaunchDaemon Persistence Anomaly",
        category=TechniqueCategory.PERSISTENCE_MECHANISMS,
        observable_indicators=[
            "Launchd property list (plist) referencing user-writable directories (/Users/Shared, /private/tmp)",
            "Launchd service configured with RunAtLoad=true and KeepAlive=true invoking script interpreters",
            "LaunchAgent definition missing code-signature or legitimate vendor reverse-DNS identifier"
        ],
        required_evidence=["macos_persistence"],
        relevant_collector="macos_collectors",
        analysis_status=AnalysisStatus.DETECTABLE,
        mitre_mapping=MitreMapping(
            id="T1543.001",
            name="Create or Modify System Process: Launch Agent",
            tactic="Persistence",
            url="https://attack.mitre.org/techniques/T1543/001/"
        ),
        demo_availability=True,
        description="Extracts LaunchAgents and LaunchDaemons property lists to identify persistent background jobs configured on macOS endpoints."
    ),
    TechniqueEntry(
        technique_id="TECH-NET-RECON",
        technique_name="Lateral Movement Port Scanning / Reconnaissance",
        category=TechniqueCategory.COMMAND_AND_CONTROL_NETWORK,
        observable_indicators=[
            "Single process PID opening numerous outbound connection attempts across diverse external IPs",
            "Rapid succession of SYN_SENT sockets directed to sequential port ranges",
            "Internal private subnet sweeping from non-administrative application process"
        ],
        required_evidence=["network"],
        relevant_collector="network",
        analysis_status=AnalysisStatus.DETECTABLE,
        mitre_mapping=MitreMapping(
            id="T1046",
            name="Network Service Discovery",
            tactic="Discovery",
            url="https://attack.mitre.org/techniques/T1046/"
        ),
        demo_availability=True,
        description="Identifies internal network discovery or lateral movement attempts by inspecting outbound socket distribution per process."
    ),
    TechniqueEntry(
        technique_id="TECH-USER-DISPARITY",
        technique_name="Account Privilege Disparity / Elevation Context",
        category=TechniqueCategory.PRIVILEGE_DISCOVERY,
        observable_indicators=[
            "Process running under elevated security context (NT AUTHORITY\\SYSTEM or root) initiated by standard user session",
            "Interactive desktop shell executing with mismatched token privileges",
            "Service process executing with standard user credentials in protected system directory"
        ],
        required_evidence=["users", "processes"],
        relevant_collector="users",
        analysis_status=AnalysisStatus.DETECTABLE,
        mitre_mapping=MitreMapping(
            id="T1078",
            name="Valid Accounts",
            tactic="Defense Evasion, Persistence, Privilege Escalation",
            url="https://attack.mitre.org/techniques/T1078/"
        ),
        demo_availability=True,
        description="Cross-correlates process token ownership against active logged-in user accounts to spot privilege escalations."
    ),
    TechniqueEntry(
        technique_id="TECH-TIMESTOMP",
        technique_name="Retroactive Timestamp Alteration / Timestomping",
        category=TechniqueCategory.INTEGRITY_TAMPER_DETECTION,
        observable_indicators=[
            "Disparity between file creation timestamp and parent directory or process creation timestamp",
            "Nanosecond zeroing in file modification timestamps (e.g., .0000000Z)",
            "Modification timestamp chronologically precedes system install or OS build date"
        ],
        required_evidence=["files", "system"],
        relevant_collector="files",
        analysis_status=AnalysisStatus.PARTIALLY_IMPLEMENTED,
        mitre_mapping=MitreMapping(
            id="T1070.006",
            name="Indicator Removal: Timestomp",
            tactic="Defense Evasion",
            url="https://attack.mitre.org/techniques/T1070/006/"
        ),
        demo_availability=True,
        description="Analyzes MAC (Modified, Accessed, Created) file timestamps against system baseline to identify anti-forensic timestomping."
    ),
    TechniqueEntry(
        technique_id="TECH-EVID-TAMPER",
        technique_name="Evidence Vault Cryptographic Tamper Detection",
        category=TechniqueCategory.INTEGRITY_TAMPER_DETECTION,
        observable_indicators=[
            "Recomputed SHA-256 digest differs from sealed acquisition hash",
            "Custody log sequence discontinuity or missing signature verification entry",
            "File length or formatting mismatch in persisted vault JSON artifact"
        ],
        required_evidence=["evidence_vault"],
        relevant_collector="evidence_store",
        analysis_status=AnalysisStatus.IMPLEMENTED,
        mitre_mapping=None,
        demo_availability=True,
        description="Applies mathematical SHA-256 integrity audits over sealed evidence artifacts to guarantee legal tamper-evidence."
    ),
    TechniqueEntry(
        technique_id="TECH-PROC-NET-BIND",
        technique_name="Process-to-Socket Cross-Correlation Binding",
        category=TechniqueCategory.CROSS_ARTIFACT_CORRELATION,
        observable_indicators=[
            "Active network socket entity connected to process PID entity",
            "Correlated process executable hash bound to network transmission record",
            "Unified timeline mapping process start, socket open, and connection state changes"
        ],
        required_evidence=["processes", "network"],
        relevant_collector="dispatcher",
        analysis_status=AnalysisStatus.IMPLEMENTED,
        mitre_mapping=None,
        demo_availability=True,
        description="Constructs a deterministic entity graph linking network socket endpoints directly to the responsible host process."
    ),
    TechniqueEntry(
        technique_id="TECH-PROC-TREE",
        technique_name="Full Process Ancestry Tree Reconstruction",
        category=TechniqueCategory.PROCESS_HIERARCHY_INJECTION,
        observable_indicators=[
            "Deterministic PPID to PID parent-child graph links",
            "Detection of orphaned processes whose parent PID has terminated",
            "Visual collapsible tree visualizer in investigator dashboard"
        ],
        required_evidence=["processes"],
        relevant_collector="processes",
        analysis_status=AnalysisStatus.IMPLEMENTED,
        mitre_mapping=None,
        demo_availability=True,
        description="Builds the complete multi-generation execution tree across running processes to reveal the origin of execution chains."
    ),
    TechniqueEntry(
        technique_id="TECH-EVTX-AUDIT",
        technique_name="Windows Security Event Log Ingestion & Log Clearing Detection",
        category=TechniqueCategory.EXECUTION_DEFENSE_EVASION,
        observable_indicators=[
            "Event ID 1102 (The audit log was cleared) in Windows Security log",
            "Event ID 7045 (A new service was installed in the system)",
            "Discontinuity in event record numbering sequence"
        ],
        required_evidence=["windows_event_logs"],
        relevant_collector="windows_metadata",
        analysis_status=AnalysisStatus.PLANNED,
        mitre_mapping=MitreMapping(
            id="T1070.001",
            name="Indicator Removal: Clear Windows Event Logs",
            tactic="Defense Evasion",
            url="https://attack.mitre.org/techniques/T1070/001/"
        ),
        demo_availability=False,
        description="Extracts Windows Security, System, and PowerShell event channels to detect log clearing or anomalous administrative actions."
    ),
    TechniqueEntry(
        technique_id="TECH-NTFS-ADS",
        technique_name="NTFS Alternate Data Stream (ADS) Concealment",
        category=TechniqueCategory.EXECUTION_DEFENSE_EVASION,
        observable_indicators=[
            "File path contains stream delimiter (file.exe:hidden.dll or file.txt:Zone.Identifier)",
            "Non-zero byte stream attached to benign document file",
            "Executable payload embedded within hidden NTFS attribute stream"
        ],
        required_evidence=["files"],
        relevant_collector="files",
        analysis_status=AnalysisStatus.DETECTABLE,
        mitre_mapping=MitreMapping(
            id="T1564.004",
            name="Hide Artifacts: NTFS File Attributes",
            tactic="Defense Evasion",
            url="https://attack.mitre.org/techniques/T1564/004/"
        ),
        demo_availability=False,
        description="Inspects NTFS Alternate Data Streams attached to filesystem artifacts to uncover hidden executables or zone markers."
    ),
]


# ── Technique Registry Manager ────────────────────────────────────────────────

class TechniqueRegistry:
    """
    Authoritative in-memory registry manager for JOCKY advanced forensic techniques.
    """

    def __init__(self, techniques: Optional[List[TechniqueEntry]] = None):
        self._techniques: Dict[str, TechniqueEntry] = {}
        for t in (techniques or TECHNIQUES_DATA):
            self._techniques[t.technique_id] = t

    def get(self, technique_id: str) -> Optional[TechniqueEntry]:
        """Retrieves a technique by its unique identifier."""
        return self._techniques.get(technique_id.strip())

    def get_by_rule_id(self, rule_id: str) -> Optional[TechniqueEntry]:
        """Retrieves a technique associated with an internal rule ID (e.g. RULE-001)."""
        clean_rule = rule_id.strip().upper()
        for t in self._techniques.values():
            if t.detection_rule_id and t.detection_rule_id.upper() == clean_rule:
                return t
        return None

    def get_by_mitre(self, mitre_id: str) -> Optional[TechniqueEntry]:
        """Retrieves a technique by its MITRE ATT&CK ID (e.g., T1036.005)."""
        clean_mitre = mitre_id.strip().upper()
        for t in self._techniques.values():
            if t.mitre_mapping and t.mitre_mapping.id.upper() == clean_mitre:
                return t
        return None

    def get_by_collector(self, collector_name: str) -> List[TechniqueEntry]:
        """Returns all techniques associated with a specific collector module."""
        clean_col = collector_name.strip().lower()
        return [t for t in self._techniques.values() if t.relevant_collector.lower() == clean_col]

    def list_techniques(
        self,
        category: Optional[TechniqueCategory] = None,
        status: Optional[AnalysisStatus] = None,
        mitre_only: bool = False,
        demo_only: bool = False,
    ) -> List[TechniqueEntry]:
        """
        Filters and returns technique entries matching the provided criteria.
        """
        results = list(self._techniques.values())
        if category:
            results = [t for t in results if t.category == category]
        if status:
            results = [t for t in results if t.analysis_status == status]
        if mitre_only:
            results = [t for t in results if t.mitre_mapping is not None]
        if demo_only:
            results = [t for t in results if t.demo_availability]
        return results

    def get_summary(self) -> Dict[str, Any]:
        """
        Returns an aggregated summary of all registered techniques.
        """
        all_entries = list(self._techniques.values())
        status_counts = {}
        for s in AnalysisStatus:
            status_counts[s.value] = sum(1 for t in all_entries if t.analysis_status == s)

        category_counts = {}
        for c in TechniqueCategory:
            category_counts[c.value] = sum(1 for t in all_entries if t.category == c)

        mitre_mapped_count = sum(1 for t in all_entries if t.mitre_mapping is not None)
        demo_count = sum(1 for t in all_entries if t.demo_availability)

        return {
            "total_techniques": len(all_entries),
            "status_breakdown": status_counts,
            "category_breakdown": category_counts,
            "mitre_mapped_count": mitre_mapped_count,
            "demo_available_count": demo_count,
        }


# ── Global Singleton Accessor ────────────────────────────────────────────────

_registry_instance: Optional[TechniqueRegistry] = None

def get_technique_registry() -> TechniqueRegistry:
    """Returns the singleton instance of the TechniqueRegistry."""
    global _registry_instance
    if _registry_instance is None:
        _registry_instance = TechniqueRegistry()
    return _registry_instance
