"""
JOCKY Persistence & Artifact Analysis Module (Phase 4)

Analyzes persistence configurations and filesystem artifact metadata:
- Windows autorun registry entries invoking script interpreters
- Linux crontabs and systemd service units
- macOS LaunchDaemons and LaunchAgents
- Filesystem timestomping indicators (zeroed subseconds, ancient timestamps)
- Evidence Vault cryptographic integrity records

Safety Invariants:
- Strictly passive analysis of collected persistence entries and file metadata.
- NO file deletion, registry manipulation, or system configuration edits.
"""

from typing import Any, Dict, List, Optional
from backend.app.analysis.correlator import generate_file_entity_id
from backend.app.analysis.mapping import ForensicContext, ObservableIndicator


class PersistenceAnalyzer:
    """
    Forensic analyzer evaluating persistence mechanisms across Windows, Linux, and macOS.
    """

    def analyze(self, evidence_data: Dict[str, Any], context: ForensicContext) -> List[ObservableIndicator]:
        """
        Inspects persistence artifacts and extracts persistence-related indicators.
        """
        indicators: List[ObservableIndicator] = []

        # ── 1. Windows Registry Autorun Persistence ───────────────────────────
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

        # ── 2. Linux Persistence (Crontabs & Systemd) ─────────────────────────
        linux_persist = evidence_data.get("linux_persistence", {})
        lin_ev_id = context.evidence_ids.get("linux_persistence")
        if isinstance(linux_persist, dict):
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

            for unit in linux_persist.get("systemd_units", []):
                exec_start = str(unit.get("exec_start", "")).lower()
                if any(pat in exec_start for pat in ["/tmp", "/var/tmp", "curl", "python -c"]):
                    indicators.append(ObservableIndicator(
                        indicator_id=f"IND-SYSTEMD-ANOMALY-{unit.get('name', 'service')}",
                        indicator_type="persistence_anomaly",
                        description=f"Systemd service '{unit.get('name')}' executes suspicious command: '{exec_start}'",
                        observed_value=unit,
                        collector_source="linux_collectors",
                        evidence_id=lin_ev_id,
                        timestamp=None,
                        entity_id=f"ENT-SYSTEMD-{unit.get('name')}",
                    ))

        # ── 3. macOS Persistence (LaunchDaemons / LaunchAgents) ───────────────
        macos_persist = evidence_data.get("macos_persistence", {})
        mac_ev_id = context.evidence_ids.get("macos_persistence")
        if isinstance(macos_persist, dict):
            all_launchd = list(macos_persist.get("launch_daemons", [])) + list(macos_persist.get("launch_agents", []))
            for item in all_launchd:
                prog = str(item.get("program", "")).lower()
                prog_args = " ".join(str(a) for a in item.get("program_arguments", [])).lower()
                combined = f"{prog} {prog_args}"
                if any(pat in combined for pat in ["/tmp", "/users/shared", "curl", "python -c"]):
                    indicators.append(ObservableIndicator(
                        indicator_id=f"IND-LAUNCHD-ANOMALY-{item.get('name', 'plist')}",
                        indicator_type="persistence_anomaly",
                        description=f"macOS launchd service '{item.get('name')}' executes suspicious target: '{combined}'",
                        observed_value=item,
                        collector_source="macos_collectors",
                        evidence_id=mac_ev_id,
                        timestamp=None,
                        entity_id=f"ENT-LAUNCHD-{item.get('name')}",
                    ))

        # ── 4. Filesystem Timestomping Indicators ─────────────────────────────
        files_raw = evidence_data.get("files", {})
        file_ev_id = context.evidence_ids.get("files")
        file_list = files_raw.get("files", []) if isinstance(files_raw, dict) else (files_raw if isinstance(files_raw, list) else [])
        for f in file_list:
            path = f.get("path", "")
            mod_ts = f.get("modified_time")
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

        # ── 5. Evidence Vault Tamper Indicator ────────────────────────────────
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
