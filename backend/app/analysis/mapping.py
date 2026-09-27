"""
JOCKY Forensic Evidence-to-Indicator-to-Technique Mapping Engine (Phase 3)

Implements the structured analytical pipeline:
    Evidence → Observable Indicator → Technique → Forensic Finding

Key Capabilities:
- Extracts concrete observable indicators from normalized forensic telemetry.
- Binds indicators to authoritative TechniqueEntry records from TechniqueRegistry.
- Preserves full evidentiary provenance:
    * evidence_ids (Evidence Vault reference)
    * timestamps (ISO 8601 acquisition and event timestamps)
    * case_id, execution_id, device_id, and target_host
- Operates strictly in read-only analysis mode without any offensive or evasion primitives.
"""

import datetime
import uuid
from typing import Any, Dict, List, Optional, Union
from pydantic import BaseModel, ConfigDict, Field

from .registry import AnalysisStatus, TechniqueCategory, TechniqueEntry, get_technique_registry
from .correlator import generate_process_entity_id, generate_user_entity_id, generate_network_entity_id, generate_file_entity_id


# ── Context & Metadata Preservation ──────────────────────────────────────────

class ForensicContext(BaseModel):
    """Preserves case, device, execution, and vault provenance across analysis."""
    model_config = ConfigDict(extra="ignore")

    case_id: str = Field(default="CASE-UNKNOWN", description="Case identifier")
    execution_id: Optional[str] = Field(default=None, description="Execution run identifier")
    device_id: Optional[str] = Field(default=None, description="Enrolled endpoint device ID if applicable")
    target_host: Optional[str] = Field(default="localhost", description="Target host name")
    timestamp_utc: str = Field(
        default_factory=lambda: datetime.datetime.now(datetime.timezone.utc).isoformat(),
        description="Analysis UTC timestamp"
    )
    evidence_ids: Dict[str, str] = Field(
        default_factory=dict,
        description="Mapping of collector source to Evidence Vault artifact evidence_id"
    )


# ── Reusable Pipeline Primitives: Indicator & Finding ─────────────────────────

class ObservableIndicator(BaseModel):
    """
    Observable Indicator extracted directly from a forensic evidence artifact.
    Evidence → Indicator
    """
    model_config = ConfigDict(extra="forbid")

    indicator_id: str = Field(..., description="Unique indicator identifier (e.g. IND-TEMP-PATH)")
    indicator_type: str = Field(..., description="Type of indicator (e.g. path_anomaly, socket_anomaly)")
    description: str = Field(..., description="Explainable description of what was observed")
    observed_value: Any = Field(..., description="Concrete data value or snippet observed in telemetry")
    collector_source: str = Field(..., description="Originating collector (processes, network, files, etc.)")
    evidence_id: Optional[str] = Field(None, description="Sealed evidence ID in Evidence Vault")
    timestamp: Optional[str] = Field(None, description="Timestamp associated with the indicator event")
    entity_id: Optional[str] = Field(None, description="Associated entity ID (e.g. ENT-PROC-1234)")


class TechniqueFinding(BaseModel):
    """
    Synthesized Forensic Finding binding Indicators to a registered Technique.
    Evidence → Indicator → Technique → Finding
    """
    model_config = ConfigDict(extra="ignore")

    finding_id: str = Field(..., description="Deterministic finding identifier")
    case_id: str = Field(default="", description="Associated forensic case ID")
    device_id: Optional[str] = Field(None, description="Target endpoint device ID if applicable")
    technique: Union[str, Dict[str, Any]] = Field(default="", description="Technique name/identifier or structured metadata")
    technique_id: str = Field(..., description="Registered technique identifier (e.g. TECH-TMP-EXEC)")
    technique_name: str = Field(..., description="Human-readable technique name")
    category: TechniqueCategory = Field(..., description="Technique analytical category")
    severity: str = Field(..., description="Severity level: CRITICAL, HIGH, MEDIUM, LOW, INFORMATIONAL")
    confidence: str = Field(default="HIGH", description="Confidence level: HIGH, MEDIUM, LOW")
    status: str = Field(default="DETECTED", description="Status of finding: DETECTED, SUSPICIOUS, CONFIRMED")
    timestamp: str = Field(default="", description="Timestamp of observed evidence event or finding generation")
    observed_indicator: str = Field(default="", description="Summary of observed forensic indicator")
    explanation: str = Field(default="", description="Forensic explanation of the detected indicator")
    mitre_id: Optional[str] = Field(None, description="MITRE ATT&CK technique ID if mapped")
    mitre_name: Optional[str] = Field(None, description="MITRE ATT&CK technique name")
    mitre_tactic: Optional[str] = Field(None, description="MITRE ATT&CK tactic")
    detection_rule_id: Optional[str] = Field(None, description="Associated detection rule ID if applicable")
    target_entity: str = Field(..., description="Target forensic entity ID")
    summary: str = Field(..., description="Concise executive summary of the finding")
    detailed_description: str = Field(..., description="Detailed forensic explanation")
    recommendation: str = Field(..., description="Actionable investigative recommendation")
    indicators: List[ObservableIndicator] = Field(default_factory=list, description="List of observed indicators")
    evidence_sources: List[str] = Field(default_factory=list, description="Collector evidence sources utilized")
    evidence_ids: List[str] = Field(default_factory=list, description="Sealed Evidence Vault IDs supporting finding")
    context: ForensicContext = Field(..., description="Preserved case/device/execution provenance")


# ── Suspicious Patterns for Indicator Extraction ──────────────────────────────

TEMP_PATH_PATTERNS = [
    r"\temp",
    r"\tmp",
    r"\appdata\local\temp",
    r"\windows\temp",
    "/tmp",
    "/var/tmp",
    "/dev/shm",
]

OFFICE_PARENT_EXECUTABLES = {
    "winword.exe",
    "excel.exe",
    "powerpnt.exe",
    "outlook.exe",
    "acrord32.exe",
    "acrobat.exe",
}

SPAWNED_SHELL_INTERPRETERS = {
    "cmd.exe",
    "powershell.exe",
    "pwsh.exe",
    "wscript.exe",
    "cscript.exe",
    "mshta.exe",
    "bash",
    "sh",
    "zsh",
}

ANOMALOUS_C2_PORTS = {
    4444: "Metasploit default listener",
    1337: "Elite / standard backdoor listener",
    6667: "IRC botnet communications",
    8888: "Non-standard alternative HTTP proxy",
    31337: "Back Orifice backdoor listener",
    23: "Telnet cleartext service",
}

LOLBIN_COMMAND_PATTERNS = [
    ("certutil", "-urlcache", "CertUtil URL cache download indicator"),
    ("certutil", "-decode", "CertUtil base64 decode indicator"),
    ("mshta", "http", "MSHTA remote script execution indicator"),
    ("bitsadmin", "/transfer", "BITSAdmin background transfer indicator"),
    ("powershell", "-enc", "PowerShell encoded command execution indicator"),
    ("powershell", "-windowstyle hidden", "PowerShell hidden window execution indicator"),
]


# ── EvidenceTechniqueMapper ───────────────────────────────────────────────────

class EvidenceTechniqueMapper:
    """
    Extracts observable indicators from evidence and maps them to registered techniques.
    """

    def __init__(self, registry=None):
        self.registry = registry or get_technique_registry()

    def _extract_context(self, evidence_data: Dict[str, Any], explicit_context: Optional[ForensicContext] = None) -> ForensicContext:
        """Constructs a consolidated ForensicContext from evidence payload or explicit arguments."""
        if explicit_context:
            return explicit_context

        case_id = evidence_data.get("case_id") or "CASE-ANALYSIS-001"
        execution_id = evidence_data.get("execution_id")
        device_id = evidence_data.get("device_id")

        sys_data = evidence_data.get("system", {})
        target_host = sys_data.get("hostname") or evidence_data.get("target") or "localhost"

        ev_ids = evidence_data.get("evidence_ids", {})

        return ForensicContext(
            case_id=case_id,
            execution_id=execution_id,
            device_id=device_id,
            target_host=target_host,
            evidence_ids=dict(ev_ids),
        )

    def extract_indicators(self, evidence_data: Dict[str, Any], context: ForensicContext) -> List[ObservableIndicator]:
        """
        Scans normalized evidence dictionaries using modular analyzers (Phase 4)
        to extract all observable indicators across processes, network, execution,
        persistence, and memory artifacts.
        Evidence → Modular Analyzers → Observable Indicators
        """
        from backend.app.analysis.analyzers.process_analyzer import ProcessAnalyzer
        from backend.app.analysis.analyzers.network_analyzer import NetworkAnalyzer
        from backend.app.analysis.analyzers.execution_analyzer import ExecutionAnalyzer
        from backend.app.analysis.analyzers.persistence_analyzer import PersistenceAnalyzer
        from backend.app.analysis.analyzers.memory_analyzer import MemoryAnalyzer

        analyzers = [
            ProcessAnalyzer(),
            NetworkAnalyzer(),
            ExecutionAnalyzer(),
            PersistenceAnalyzer(),
            MemoryAnalyzer(),
        ]
        indicators: List[ObservableIndicator] = []
        for analyzer in analyzers:
            indicators.extend(analyzer.analyze(evidence_data, context))
        return indicators

    def _legacy_extract_indicators(self, evidence_data: Dict[str, Any], context: ForensicContext) -> List[ObservableIndicator]:
        indicators: List[ObservableIndicator] = []

        procs_raw = evidence_data.get("processes", {})
        procs = procs_raw.get("processes", []) if isinstance(procs_raw, dict) else (procs_raw if isinstance(procs_raw, list) else [])
        proc_by_pid = {p.get("pid"): p for p in procs if p.get("pid") is not None}
        proc_ev_id = context.evidence_ids.get("processes")

        # ── 1. Process Telemetry Indicators ──────────────────────────────────
        for p in procs:
            pid = p.get("pid")
            exe = p.get("exe")
            name = (p.get("name") or "unknown").lower()
            cmdline = p.get("cmdline") or ""
            cmdline_str = " ".join(cmdline) if isinstance(cmdline, list) else str(cmdline)
            cmd_lower = cmdline_str.lower()
            ent_id = generate_process_entity_id(pid)
            p_time = p.get("create_time")

            # A. Temporary Directory Execution
            if exe and isinstance(exe, str):
                exe_lower = exe.lower()
                if any(pat in exe_lower for pat in TEMP_PATH_PATTERNS):
                    indicators.append(ObservableIndicator(
                        indicator_id=f"IND-TEMP-PATH-{pid}",
                        indicator_type="path_anomaly",
                        description=f"Process '{name}' (PID: {pid}) executed from volatile path: {exe}",
                        observed_value={"exe": exe, "name": name, "pid": pid},
                        collector_source="processes",
                        evidence_id=proc_ev_id,
                        timestamp=p_time,
                        entity_id=ent_id,
                    ))

            # B. Suspicious Parent-Child Shell Spawn
            ppid = p.get("ppid")
            if name in SPAWNED_SHELL_INTERPRETERS and ppid and ppid in proc_by_pid:
                parent = proc_by_pid[ppid]
                parent_name = (parent.get("name") or "").lower()
                if parent_name in OFFICE_PARENT_EXECUTABLES:
                    indicators.append(ObservableIndicator(
                        indicator_id=f"IND-SHELL-SPAWN-{pid}",
                        indicator_type="ancestry_anomaly",
                        description=f"Productivity application '{parent_name}' (PID: {ppid}) spawned shell '{name}' (PID: {pid})",
                        observed_value={"parent_name": parent_name, "parent_pid": ppid, "child_name": name, "child_pid": pid, "cmdline": cmdline_str},
                        collector_source="processes",
                        evidence_id=proc_ev_id,
                        timestamp=p_time,
                        entity_id=ent_id,
                    ))

            # C. Unmapped Binary Execution (Process Hollowing Indicator)
            if pid not in (0, 4) and (exe is None or not str(exe).strip()) and name not in ("system", "system idle process"):
                indicators.append(ObservableIndicator(
                    indicator_id=f"IND-UNMAPPED-BIN-{pid}",
                    indicator_type="binary_anomaly",
                    description=f"Running process '{name}' (PID: {pid}) has no accessible executable file path on disk",
                    observed_value={"pid": pid, "name": name},
                    collector_source="processes",
                    evidence_id=proc_ev_id,
                    timestamp=p_time,
                    entity_id=ent_id,
                ))

            # D. Living-off-the-Land Binaries (LOLBins) Execution
            for bin_name, arg_pat, desc in LOLBIN_COMMAND_PATTERNS:
                if bin_name in name and arg_pat in cmd_lower:
                    indicators.append(ObservableIndicator(
                        indicator_id=f"IND-LOLBIN-{bin_name.upper()}-{pid}",
                        indicator_type="command_anomaly",
                        description=f"LOLBin execution detected: {desc} (Command: '{cmdline_str}')",
                        observed_value={"pid": pid, "name": name, "cmdline": cmdline_str, "matched_pattern": arg_pat},
                        collector_source="processes",
                        evidence_id=proc_ev_id,
                        timestamp=p_time,
                        entity_id=ent_id,
                    ))

        # ── 2. Network Telemetry Indicators ──────────────────────────────────
        net_raw = evidence_data.get("network", {})
        conns = net_raw.get("connections", []) if isinstance(net_raw, dict) else (net_raw if isinstance(net_raw, list) else [])
        net_ev_id = context.evidence_ids.get("network")

        outbound_conns_by_pid: Dict[int, List[Dict[str, Any]]] = {}

        for conn in conns:
            raddr = conn.get("raddr")
            pid = conn.get("pid")
            proto = conn.get("protocol") or "TCP"

            if isinstance(raddr, dict) and raddr.get("port"):
                r_port = raddr.get("port")
                r_ip = raddr.get("ip", "")
                net_ent = generate_network_entity_id(proto, conn.get("laddr"), raddr)

                # A. High-Risk C2 Backdoor Port
                if r_port in ANOMALOUS_C2_PORTS:
                    indicators.append(ObservableIndicator(
                        indicator_id=f"IND-C2-PORT-{r_port}-{pid}",
                        indicator_type="socket_anomaly",
                        description=f"Outbound socket to anomalous/backdoor port {r_port} ({ANOMALOUS_C2_PORTS[r_port]}) by PID {pid}",
                        observed_value={"raddr": raddr, "laddr": conn.get("laddr"), "status": conn.get("status"), "pid": pid},
                        collector_source="network",
                        evidence_id=net_ev_id,
                        timestamp=conn.get("timestamp"),
                        entity_id=net_ent,
                    ))

                # Track outbound count for port scan indicator
                if pid:
                    outbound_conns_by_pid.setdefault(pid, []).append(conn)

        # B. Lateral Reconnaissance / Port Scanning Indicator
        for pid, p_conns in outbound_conns_by_pid.items():
            distinct_remote_ips = {c.get("raddr", {}).get("ip") for c in p_conns if isinstance(c.get("raddr"), dict) and c.get("raddr", {}).get("ip")}
            if len(distinct_remote_ips) >= 10:
                indicators.append(ObservableIndicator(
                    indicator_id=f"IND-NET-RECON-{pid}",
                    indicator_type="lateral_movement_anomaly",
                    description=f"Process PID {pid} established outbound connections to {len(distinct_remote_ips)} distinct IPs (possible port scan/recon)",
                    observed_value={"pid": pid, "distinct_ip_count": len(distinct_remote_ips)},
                    collector_source="network",
                    evidence_id=net_ev_id,
                    timestamp=None,
                    entity_id=generate_process_entity_id(pid),
                ))

        # ── 3. Windows Registry Autorun Persistence Indicators ────────────────
        wm_raw = evidence_data.get("windows_metadata") or evidence_data.get("registry", {})
        wm_ev_id = context.evidence_ids.get("windows_metadata") or context.evidence_ids.get("registry")
        if isinstance(wm_raw, dict):
            autoruns = wm_raw.get("autoruns", [])
            for entry in autoruns:
                val = str(entry.get("value", entry.get("command", ""))).lower()
                name = entry.get("name", entry.get("entry_name", "UnknownAutorun"))
                if any(ext in val for ext in [".vbs", ".ps1", ".bat", ".cmd", "powershell", "wscript", "cscript"]):
                    indicators.append(ObservableIndicator(
                        indicator_id=f"IND-REG-SCRIPT-{name}",
                        indicator_type="autorun_anomaly",
                        description=f"Windows persistence autorun entry '{name}' executes script interpreter: '{val}'",
                        observed_value=entry,
                        collector_source="windows_metadata",
                        evidence_id=wm_ev_id,
                        timestamp=entry.get("timestamp"),
                        entity_id=f"ENT-REG-{name}",
                    ))

        # ── 4. Linux Persistence Indicators (Cron / Systemd) ─────────────────
        linux_persist = evidence_data.get("linux_persistence", {})
        lin_ev_id = context.evidence_ids.get("linux_persistence")
        if isinstance(linux_persist, dict):
            # Crontab check
            for cron_entry in linux_persist.get("crontabs", []):
                cmd = str(cron_entry.get("command", "")).lower()
                if any(pat in cmd for pat in ["/tmp", "curl", "wget", "nc ", "bash -i"]):
                    indicators.append(ObservableIndicator(
                        indicator_id=f"IND-CRON-ANOMALY-{cron_entry.get('line_number', 0)}",
                        indicator_type="persistence_anomaly",
                        description=f"Linux crontab executes suspicious command: '{cmd}'",
                        observed_value=cron_entry,
                        collector_source="linux_collectors",
                        evidence_id=lin_ev_id,
                        timestamp=None,
                        entity_id="ENT-LINUX-CRON",
                    ))

        # ── 5. Filesystem Timestomping Indicators ─────────────────────────────
        files_raw = evidence_data.get("files", {})
        file_ev_id = context.evidence_ids.get("files")
        file_list = files_raw.get("files", []) if isinstance(files_raw, dict) else (files_raw if isinstance(files_raw, list) else [])
        for f in file_list:
            path = f.get("path", "")
            mod_ts = f.get("modified_time")
            create_ts = f.get("created_time")
            # Zeroed sub-seconds or ancient creation dates
            if mod_ts and isinstance(mod_ts, str) and mod_ts.endswith(".000000Z"):
                indicators.append(ObservableIndicator(
                    indicator_id=f"IND-TIMESTOMP-{f.get('sha256', 'hash')[:8]}",
                    indicator_type="integrity_anomaly",
                    description=f"File at '{path}' exhibits zeroed sub-second precision, indicative of timestomping",
                    observed_value={"path": path, "modified_time": mod_ts},
                    collector_source="files",
                    evidence_id=file_ev_id,
                    timestamp=mod_ts,
                    entity_id=generate_file_entity_id(path, f.get("sha256")),
                ))

        # ── 6. Evidence Vault Tamper Indicator ────────────────────────────────
        vault_audit = evidence_data.get("vault_audit", {})
        if isinstance(vault_audit, dict) and vault_audit.get("vault_status") == "COMPROMISED":
            for tampered in vault_audit.get("tampered_artifacts", []):
                indicators.append(ObservableIndicator(
                    indicator_id=f"IND-VAULT-TAMPER-{tampered.get('evidence_id', 'EVID')}",
                    indicator_type="integrity_anomaly",
                    description=f"Evidence Vault cryptographic mismatch detected for artifact: {tampered.get('evidence_id')}",
                    observed_value=tampered,
                    collector_source="evidence_store",
                    evidence_id=tampered.get("evidence_id"),
                    timestamp=vault_audit.get("audited_at"),
                    entity_id="ENT-VAULT-INTEGRITY",
                ))

        return indicators

    def map_indicators_to_findings(
        self,
        indicators: List[ObservableIndicator],
        context: ForensicContext,
    ) -> List[TechniqueFinding]:
        """
        Maps observable indicators to registered techniques to generate forensic findings.
        Indicator → Technique → Finding
        """
        findings: List[TechniqueFinding] = []

        # Group indicators by matching technique ID
        technique_indicator_map: Dict[str, List[ObservableIndicator]] = {}

        for ind in indicators:
            tech_id = None
            if ind.indicator_type == "path_anomaly":
                tech_id = "TECH-TMP-EXEC"
            elif ind.indicator_type in ("ancestry_anomaly", "privilege_disparity"):
                tech_id = "TECH-PROC-SPAWN"
            elif ind.indicator_type in ("binary_anomaly", "memory_footprint_anomaly"):
                tech_id = "TECH-PROC-HOLLOW"
            elif ind.indicator_type == "command_anomaly":
                tech_id = "TECH-LOLBINS"
            elif ind.indicator_type == "socket_anomaly":
                tech_id = "TECH-NET-BACKDOOR"
            elif ind.indicator_type == "lateral_movement_anomaly":
                tech_id = "TECH-NET-RECON"
            elif ind.indicator_type == "autorun_anomaly":
                tech_id = "TECH-REG-AUTORUN"
            elif ind.indicator_type == "persistence_anomaly":
                if "LAUNCHD" in ind.indicator_id:
                    tech_id = "TECH-MACOS-PERSIST"
                else:
                    tech_id = "TECH-LINUX-PERSIST"
            elif ind.indicator_type == "integrity_anomaly":
                if "IND-VAULT-TAMPER" in ind.indicator_id:
                    tech_id = "TECH-EVID-TAMPER"
                else:
                    tech_id = "TECH-TIMESTOMP"

            if tech_id:
                technique_indicator_map.setdefault(tech_id, []).append(ind)

        # Synthesize each group into a TechniqueFinding
        for tech_id, matched_indicators in technique_indicator_map.items():
            tech = self.registry.get(tech_id)
            if not tech:
                continue

            # Compute severity based on technique or highest indicator severity
            severity_map = {
                "TECH-TMP-EXEC": "HIGH",
                "TECH-PROC-SPAWN": "HIGH",
                "TECH-NET-BACKDOOR": "MEDIUM",
                "TECH-PROC-HOLLOW": "LOW",
                "TECH-REG-AUTORUN": "MEDIUM",
                "TECH-LOLBINS": "HIGH",
                "TECH-LINUX-PERSIST": "MEDIUM",
                "TECH-MACOS-PERSIST": "MEDIUM",
                "TECH-NET-RECON": "HIGH",
                "TECH-EVID-TAMPER": "CRITICAL",
                "TECH-TIMESTOMP": "MEDIUM",
            }
            severity = severity_map.get(tech_id, "MEDIUM")

            # Determine primary target entity
            target_entity = matched_indicators[0].entity_id or f"ENT-{tech.category.name}"

            # Aggregate evidence IDs and sources
            evidence_sources = list({ind.collector_source for ind in matched_indicators})
            evidence_ids = list({ind.evidence_id for ind in matched_indicators if ind.evidence_id})

            finding_slug = uuid.uuid4().hex[:6].upper()
            finding_id = f"FIND-{context.case_id}-{tech_id}-{finding_slug}"

            # Executive summary
            summary = f"Detected {len(matched_indicators)} indicator(s) matching '{tech.technique_name}' ({tech_id})"

            # Detailed forensic description
            details = (
                f"Forensic analysis correlated {len(matched_indicators)} observable indicator(s) "
                f"associated with '{tech.technique_name}' under category '{tech.category.value}'. "
                f"Observable signals: " + "; ".join(ind.description for ind in matched_indicators[:3])
            )

            # Recommendation
            recs = {
                "TECH-TMP-EXEC": "Inspect binary SHA-256 in Evidence Vault and verify if file is cryptographically signed.",
                "TECH-PROC-SPAWN": "Review parent commandline parameters, inspect child process network connections.",
                "TECH-NET-BACKDOOR": "Verify remote host IP reputation, correlate with firewall egress logs, isolate host if untrusted.",
                "TECH-PROC-HOLLOW": "Conduct volatile memory inspection to verify image headers against disk records.",
                "TECH-REG-AUTORUN": "Audit Windows autorun Run keys, verify referenced scripts for valid signatures.",
                "TECH-LOLBINS": "Review full commandline arguments, inspect parent process identity and user security context.",
                "TECH-LINUX-PERSIST": "Audit crontab and systemd service paths, cross-reference against package manager file integrity.",
                "TECH-MACOS-PERSIST": "Audit LaunchAgent and LaunchDaemon plists, verify code signatures against Apple Developer IDs.",
                "TECH-NET-RECON": "Inspect source process privileges, identify if network reconnaissance tools were executed.",
                "TECH-EVID-TAMPER": "IMMEDIATE ATTENTION: Artifact hash mismatch flags unauthorized evidence alteration.",
                "TECH-TIMESTOMP": "Cross-reference $STANDARD_INFORMATION with $FILE_NAME timestamps in NTFS metadata.",
            }
            recommendation = recs.get(tech_id, "Review forensic artifacts in Evidence Vault and correlate with system timeline.")

            first_ts = next((ind.timestamp for ind in matched_indicators if ind.timestamp), context.timestamp_utc or datetime.datetime.now(datetime.timezone.utc).isoformat())
            first_obs = matched_indicators[0].description if matched_indicators else summary

            finding = TechniqueFinding(
                finding_id=finding_id,
                case_id=context.case_id,
                device_id=context.device_id,
                technique=tech.technique_id,
                technique_id=tech.technique_id,
                technique_name=tech.technique_name,
                category=tech.category,
                severity=severity,
                confidence="HIGH" if len(matched_indicators) >= 2 else "MEDIUM",
                status="DETECTED",
                timestamp=first_ts,
                observed_indicator=first_obs,
                explanation=details,
                mitre_id=tech.mitre_mapping.id if tech.mitre_mapping else None,
                mitre_name=tech.mitre_mapping.name if tech.mitre_mapping else None,
                mitre_tactic=tech.mitre_mapping.tactic if tech.mitre_mapping else None,
                detection_rule_id=tech.detection_rule_id,
                target_entity=target_entity,
                summary=summary,
                detailed_description=details,
                recommendation=recommendation,
                indicators=matched_indicators,
                evidence_sources=evidence_sources,
                evidence_ids=evidence_ids,
                context=context,
            )
            findings.append(finding)

        return findings

    def analyze_evidence(
        self,
        evidence_data: Dict[str, Any],
        context: Optional[ForensicContext] = None,
    ) -> List[TechniqueFinding]:
        """
        Executes the full Evidence → Indicator → Technique → Finding pipeline.
        """
        consolidated_context = self._extract_context(evidence_data, context)
        indicators = self.extract_indicators(evidence_data, consolidated_context)
        findings = self.map_indicators_to_findings(indicators, consolidated_context)
        return findings


# ── Global Helper Function ───────────────────────────────────────────────────

def analyze_evidence_techniques(
    evidence_data: Dict[str, Any],
    context: Optional[ForensicContext] = None,
) -> List[Dict[str, Any]]:
    """
    Convenience helper running the mapping pipeline and returning serializable dictionaries.
    """
    mapper = EvidenceTechniqueMapper()
    findings = mapper.analyze_evidence(evidence_data, context)
    return [f.model_dump() for f in findings]
