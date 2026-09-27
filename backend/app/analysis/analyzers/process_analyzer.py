"""
JOCKY Process Analysis Module (Phase 4)

Analyzes process telemetry to detect:
- Suspicious parent-child process relationships (e.g. document applications spawning shell interpreters)
- Orphaned process execution chains
- Process execution hierarchy anomalies

Safety Invariants:
- Strictly passive analysis of collected evidence data.
- NO process manipulation, termination, hooking, or injection.
"""

from typing import Any, Dict, List, Optional
from backend.app.analysis.correlator import generate_process_entity_id
from backend.app.analysis.mapping import ForensicContext, ObservableIndicator

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


class ProcessAnalyzer:
    """
    Forensic analyzer evaluating process trees, ancestry, and execution relationships.
    """

    def analyze(self, evidence_data: Dict[str, Any], context: ForensicContext) -> List[ObservableIndicator]:
        """
        Inspects process telemetry and extracts process-related indicators.
        """
        indicators: List[ObservableIndicator] = []

        procs_raw = evidence_data.get("processes", {})
        procs = procs_raw.get("processes", []) if isinstance(procs_raw, dict) else (procs_raw if isinstance(procs_raw, list) else [])
        if not procs:
            return indicators

        proc_by_pid = {p.get("pid"): p for p in procs if p.get("pid") is not None}
        proc_ev_id = context.evidence_ids.get("processes")

        for p in procs:
            pid = p.get("pid")
            ppid = p.get("ppid")
            name = (p.get("name") or "unknown").lower()
            cmdline = p.get("cmdline") or ""
            cmdline_str = " ".join(cmdline) if isinstance(cmdline, list) else str(cmdline)
            ent_id = generate_process_entity_id(pid)
            p_time = p.get("create_time")

            # 1. Suspicious Parent-Child Process Spawning (Office/Browser -> Shell)
            if name in SPAWNED_SHELL_INTERPRETERS and ppid and ppid in proc_by_pid:
                parent = proc_by_pid[ppid]
                parent_name = (parent.get("name") or "").lower()
                if parent_name in OFFICE_PARENT_EXECUTABLES:
                    indicators.append(ObservableIndicator(
                        indicator_id=f"IND-PROC-SPAWN-{pid}",
                        indicator_type="ancestry_anomaly",
                        description=f"Productivity application '{parent_name}' (PID: {ppid}) spawned command shell '{name}' (PID: {pid})",
                        observed_value={
                            "parent_name": parent_name,
                            "parent_pid": ppid,
                            "child_name": name,
                            "child_pid": pid,
                            "cmdline": cmdline_str,
                        },
                        collector_source="processes",
                        evidence_id=proc_ev_id,
                        timestamp=p_time,
                        entity_id=ent_id,
                    ))

            # 2. Orphaned Shell Interpreter (Parent PID has already exited / invalid)
            if name in SPAWNED_SHELL_INTERPRETERS and ppid and ppid not in proc_by_pid and ppid not in (0, 1, 4):
                indicators.append(ObservableIndicator(
                    indicator_id=f"IND-ORPHAN-{pid}",
                    indicator_type="ancestry_anomaly",
                    description=f"Command shell interpreter '{name}' (PID: {pid}) is running as an orphaned process (PPID: {ppid} non-existent)",
                    observed_value={"pid": pid, "ppid": ppid, "name": name, "cmdline": cmdline_str},
                    collector_source="processes",
                    evidence_id=proc_ev_id,
                    timestamp=p_time,
                    entity_id=ent_id,
                ))

        return indicators
