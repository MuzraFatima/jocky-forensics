"""
JOCKY Execution Analysis Module (Phase 4)

Analyzes execution paths and binary arguments to detect:
- Binaries executing out of volatile temporary directories
- Living-off-the-Land Binaries (LOLBins) argument misuse (certutil, mshta, bitsadmin, powershell)
- Script interpreters executing anomalous payload download arguments

Safety Invariants:
- Strictly passive analysis of collected process execution telemetry.
- NO arbitrary shell execution, payload generation, or script evaluation.
"""

from typing import Any, Dict, List, Optional
from backend.app.analysis.correlator import generate_process_entity_id
from backend.app.analysis.mapping import ForensicContext, ObservableIndicator

TEMP_PATH_PATTERNS = [
    r"\temp",
    r"\tmp",
    r"\appdata\local\temp",
    r"\windows\temp",
    "/tmp",
    "/var/tmp",
    "/dev/shm",
]

LOLBIN_COMMAND_PATTERNS = [
    ("certutil", "-urlcache", "CertUtil URL cache download indicator"),
    ("certutil", "-decode", "CertUtil base64 decode indicator"),
    ("mshta", "http", "MSHTA remote script execution indicator"),
    ("bitsadmin", "/transfer", "BITSAdmin background transfer indicator"),
    ("powershell", "-enc", "PowerShell encoded command execution indicator"),
    ("powershell", "-windowstyle hidden", "PowerShell hidden window execution indicator"),
    ("curl", " | bash", "Piped shell script download indicator"),
    ("wget", " | sh", "Piped shell script download indicator"),
]


class ExecutionAnalyzer:
    """
    Forensic analyzer evaluating execution locations and commandline arguments.
    """

    def analyze(self, evidence_data: Dict[str, Any], context: ForensicContext) -> List[ObservableIndicator]:
        """
        Inspects process paths and commandlines to extract execution-related indicators.
        """
        indicators: List[ObservableIndicator] = []

        procs_raw = evidence_data.get("processes", {})
        procs = procs_raw.get("processes", []) if isinstance(procs_raw, dict) else (procs_raw if isinstance(procs_raw, list) else [])
        if not procs:
            return indicators

        proc_ev_id = context.evidence_ids.get("processes")

        for p in procs:
            pid = p.get("pid")
            exe = p.get("exe")
            name = (p.get("name") or "unknown").lower()
            cmdline = p.get("cmdline") or ""
            cmdline_str = " ".join(cmdline) if isinstance(cmdline, list) else str(cmdline)
            cmd_lower = cmdline_str.lower()
            ent_id = generate_process_entity_id(pid)
            p_time = p.get("create_time")

            # 1. Execution from Temporary Directory
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

            # 2. Living-off-the-Land Binaries (LOLBins) Execution
            for bin_name, arg_pat, desc in LOLBIN_COMMAND_PATTERNS:
                if bin_name in name and arg_pat in cmd_lower:
                    indicators.append(ObservableIndicator(
                        indicator_id=f"IND-LOLBIN-{bin_name.upper()}-{pid}",
                        indicator_type="command_anomaly",
                        description=f"LOLBin execution detected: {desc} (Command: '{cmdline_str}')",
                        observed_value={
                            "pid": pid,
                            "name": name,
                            "cmdline": cmdline_str,
                            "matched_pattern": arg_pat,
                        },
                        collector_source="processes",
                        evidence_id=proc_ev_id,
                        timestamp=p_time,
                        entity_id=ent_id,
                    ))

        return indicators
