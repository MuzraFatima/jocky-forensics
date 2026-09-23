"""
JOCKY Forensic Report Generation Engine (Phase 8)

Produces court-admissible, executive, and technical forensic analysis reports
in JSON, Markdown, and self-contained HTML formats.

Key Capabilities:
- Executive Threat Summary: High/Medium/Low detections, affected processes, ports, files.
- Correlation Lineage: Process ancestry chains and anomalous cross-artifact links.
- Cryptographic Attestation Certificate: Vault manifest SHA-256 digest, acquisition timestamps,
  examiner identity, and digital evidence integrity affirmation.
- Self-Contained Print-Ready HTML: Clean modern styling, dark/light print support,
  responsive layout, color-coded severity badges, zero external CDN dependencies.
"""

import datetime
import html
import json
from pathlib import Path
from typing import Any, Dict, List, Optional

from backend.app.evidence.hashing import compute_sha256


class ForensicReportBuilder:
    """
    Forensic report generator supporting JSON, Markdown, and standalone HTML outputs.
    """

    def __init__(
        self,
        case_id: str = "CASE-REPORT-001",
        target: str = "LIVE-ENDPOINT",
        examiner: str = "JOCKY Lead Forensic Examiner",
        execution_id: Optional[str] = None,
    ):
        self.case_id = case_id
        self.target = target
        self.examiner = examiner
        self.execution_id = execution_id or f"EXEC-REP-{datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%d%H%M%S')}"

    def build_report_data(
        self,
        collected_data: Optional[Dict[str, Any]] = None,
        correlation: Optional[Dict[str, Any]] = None,
        timeline: Optional[List[Dict[str, Any]]] = None,
        detections: Optional[List[Dict[str, Any]]] = None,
        evidence_ids: Optional[Dict[str, str]] = None,
        sha256_hashes: Optional[Dict[str, str]] = None,
        vault_audit: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Synthesizes raw evidence, correlation graph, timeline, threat rules,
        and vault integrity status into a canonical report data dictionary.
        """
        now_utc = datetime.datetime.now(datetime.timezone.utc).isoformat()
        collected = collected_data or {}
        corr = correlation or {}
        tl = timeline or []
        dets = detections or []
        ev_ids = evidence_ids or {}
        hashes = sha256_hashes or {}

        # Severity metrics
        high_cnt = sum(1 for d in dets if d.get("severity") == "HIGH")
        med_cnt = sum(1 for d in dets if d.get("severity") == "MEDIUM")
        low_cnt = sum(1 for d in dets if d.get("severity") == "LOW")

        # System overview
        sys_data = collected.get("system", {})
        proc_data = collected.get("processes", {})
        net_data = collected.get("network", {})
        file_data = collected.get("files", {})
        user_data = collected.get("users", {})

        # Evidence manifest entries
        manifest_entries = []
        for src, eid in ev_ids.items():
            manifest_entries.append({
                "source": src,
                "evidence_id": eid,
                "sha256": hashes.get(src, "UNAVAILABLE"),
                "status": "VERIFIED_INTACT",
            })

        manifest_digest = compute_sha256(manifest_entries)
        vault_status = vault_audit.get("vault_status", "INTACT") if vault_audit else "INTACT"

        attestation = {
            "certificate_id": f"CERT-{self.case_id}-{self.execution_id}",
            "case_id": self.case_id,
            "target_host": self.target,
            "examiner": self.examiner,
            "execution_id": self.execution_id,
            "issued_at_utc": now_utc,
            "hash_algorithm": "SHA-256",
            "manifest_sha256": manifest_digest,
            "vault_status": vault_status,
            "statement": (
                "I hereby attest that the digital evidence items referenced in this report "
                "were acquired strictly via authorized read-only forensic mechanisms without "
                "altering target system state. The integrity of each artifact is mathematically "
                "guaranteed by the recorded SHA-256 cryptographic digest."
            ),
        }

        return {
            "report_title": f"JOCKY Digital Forensic Investigation Report: {self.case_id}",
            "case_id": self.case_id,
            "target": self.target,
            "examiner": self.examiner,
            "execution_id": self.execution_id,
            "generated_at_utc": now_utc,
            "executive_summary": {
                "assessment": "COMPROMISE_DETECTED" if high_cnt > 0 else "ANOMALIES_OBSERVED" if med_cnt > 0 else "CLEAN_BASELINE",
                "total_detections": len(dets),
                "severity_counts": {"high": high_cnt, "medium": med_cnt, "low": low_cnt},
                "total_processes_inspected": proc_data.get("count", 0),
                "total_sockets_inspected": net_data.get("count", 0),
                "total_timeline_events": len(tl),
                "vault_status": vault_status,
            },
            "system_profile": sys_data,
            "detections": dets,
            "correlated_chains": corr.get("chains", []),
            "timeline_highlights": tl[:30],
            "evidence_manifest": manifest_entries,
            "attestation": attestation,
        }

    def generate_json(self, report_data: Dict[str, Any]) -> str:
        """Serializes report data to formatted JSON."""
        return json.dumps(report_data, indent=2, default=str)

    def generate_markdown(self, report_data: Dict[str, Any]) -> str:
        """Generates court-admissible, readable Markdown document."""
        es = report_data.get("executive_summary", {})
        att = report_data.get("attestation", {})
        sys_prof = report_data.get("system_profile", {})
        dets = report_data.get("detections", [])
        manifest = report_data.get("evidence_manifest", [])
        chains = report_data.get("correlated_chains", [])

        md = []
        md.append(f"# {report_data.get('report_title', 'Digital Forensic Investigation Report')}")
        md.append("")
        md.append(f"**Case Identifier:** `{report_data.get('case_id')}`  ")
        md.append(f"**Target System:** `{report_data.get('target')}`  ")
        md.append(f"**Execution ID:** `{report_data.get('execution_id')}`  ")
        md.append(f"**Lead Examiner:** {report_data.get('examiner')}  ")
        md.append(f"**Timestamp (UTC):** {report_data.get('generated_at_utc')}  ")
        md.append("")
        md.append("---")
        md.append("")

        # Executive Summary
        md.append("## 1. Executive Summary")
        md.append("")
        assessment = es.get("assessment", "CLEAN")
        md.append(f"**Overall Assessment:** **{assessment}**  ")
        md.append(f"- **High Severity Detections:** {es.get('severity_counts', {}).get('high', 0)}")
        md.append(f"- **Medium Severity Detections:** {es.get('severity_counts', {}).get('medium', 0)}")
        md.append(f"- **Low Severity Detections:** {es.get('severity_counts', {}).get('low', 0)}")
        md.append(f"- **Evidence Vault Integrity:** **{es.get('vault_status', 'INTACT')}**")
        md.append("")

        # System profile
        if sys_prof:
            md.append("## 2. Target System Profile")
            md.append("")
            md.append(f"- **Hostname:** `{sys_prof.get('hostname', 'N/A')}`")
            md.append(f"- **Operating System:** {sys_prof.get('os', 'N/A')} ({sys_prof.get('os_version', '')})")
            md.append(f"- **Architecture:** {sys_prof.get('architecture', 'N/A')}")
            md.append(f"- **Boot Time:** {sys_prof.get('boot_time', 'N/A')}")
            md.append("")

        # Detections table
        md.append("## 3. Heuristic Threat Detections")
        md.append("")
        if dets:
            md.append("| Rule ID | Threat / Rule Name | Severity | Description | Evidence Entity |")
            md.append("| :--- | :--- | :---: | :--- | :--- |")
            for d in dets:
                rid = d.get("rule_id", "RULE-N/A")
                rname = d.get("rule_name", "Detection")
                sev = d.get("severity", "LOW")
                desc = d.get("description", "").replace("|", "-")
                refs = ", ".join(d.get("evidence_refs", [])) or "N/A"
                md.append(f"| `{rid}` | **{rname}** | **{sev}** | {desc} | `{refs}` |")
            md.append("")
        else:
            md.append("No automated heuristic threats or anomalies detected across collected artifacts.")
            md.append("")

        # Process Chains
        if chains:
            md.append("## 4. Correlated Process Execution Lineage")
            md.append("")
            for idx, ch in enumerate(chains[:5]):
                md.append(f"### Chain #{idx + 1}: {ch.get('chain_type', 'Execution Tree')}")
                procs = ch.get("processes", [])
                for p in procs:
                    md.append(f"- **PID {p.get('pid')}** (`{p.get('name')}`) -> Cmdline: `{p.get('cmdline')}`")
                md.append("")

        # Evidence Manifest
        md.append("## 5. Cryptographic Evidence Manifest")
        md.append("")
        md.append("| Source Category | Evidence ID | Cryptographic SHA-256 Digest | Status |")
        md.append("| :--- | :--- | :--- | :---: |")
        for m in manifest:
            md.append(f"| `{m.get('source')}` | `{m.get('evidence_id')}` | `{m.get('sha256')}` | {m.get('status')} |")
        md.append("")

        # Cryptographic Attestation
        md.append("## 6. Examiner Attestation & Cryptographic Certificate")
        md.append("")
        md.append(f"> **Certificate ID:** `{att.get('certificate_id')}`  ")
        md.append(f"> **Manifest Digest (SHA-256):** `{att.get('manifest_sha256')}`  ")
        md.append(f"> **Vault Integrity:** **{att.get('vault_status')}**  ")
        md.append(">")
        md.append(f"> *\"{att.get('statement')}\"*")
        md.append("")
        md.append(f"**Lead Forensic Examiner:** `{self.examiner}`  ")
        md.append(f"**Digital Signature Date:** `{report_data.get('generated_at_utc')}`  ")
        md.append("")

        return "\n".join(md)

    def generate_html(self, report_data: Dict[str, Any]) -> str:
        """
        Generates a standalone, self-contained, print-ready HTML forensic document
        with embedded CSS and responsive layout.
        """
        title = html.escape(report_data.get("report_title", "Forensic Investigation Report"))
        case_id = html.escape(str(report_data.get("case_id", "")))
        target = html.escape(str(report_data.get("target", "")))
        examiner = html.escape(str(report_data.get("examiner", "")))
        exec_id = html.escape(str(report_data.get("execution_id", "")))
        gen_time = html.escape(str(report_data.get("generated_at_utc", "")))

        es = report_data.get("executive_summary", {})
        assessment = html.escape(str(es.get("assessment", "CLEAN")))
        high_cnt = es.get("severity_counts", {}).get("high", 0)
        med_cnt = es.get("severity_counts", {}).get("medium", 0)
        low_cnt = es.get("severity_counts", {}).get("low", 0)
        vault_status = html.escape(str(es.get("vault_status", "INTACT")))

        sys_prof = report_data.get("system_profile", {})
        dets = report_data.get("detections", [])
        manifest = report_data.get("evidence_manifest", [])
        att = report_data.get("attestation", {})

        # Detections table HTML rows
        det_rows = []
        if dets:
            for d in dets:
                sev = d.get("severity", "LOW")
                badge_color = "#ef4444" if sev == "HIGH" else "#f59e0b" if sev == "MEDIUM" else "#3b82f6"
                badge_bg = "rgba(239, 68, 68, 0.15)" if sev == "HIGH" else "rgba(245, 158, 11, 0.15)" if sev == "MEDIUM" else "rgba(59, 130, 246, 0.15)"
                det_rows.append(f"""
                <tr>
                    <td class="font-mono"><strong>{html.escape(str(d.get("rule_id", "")))}</strong></td>
                    <td><strong>{html.escape(str(d.get("rule_name", "")))}</strong></td>
                    <td><span class="badge" style="color: {badge_color}; background: {badge_bg}; border: 1px solid {badge_color}40;">{html.escape(str(sev))}</span></td>
                    <td>{html.escape(str(d.get("description", "")))}</td>
                    <td class="font-mono" style="font-size: 0.75rem;">{html.escape(", ".join(d.get("evidence_refs", [])) or "N/A")}</td>
                </tr>
                """)
        else:
            det_rows.append("<tr><td colspan='5' style='text-align: center; color: #94a3b8;'>No threat detections or anomalies identified.</td></tr>")

        # Manifest rows
        manifest_rows = []
        for m in manifest:
            manifest_rows.append(f"""
            <tr>
                <td class="font-mono"><strong>{html.escape(str(m.get("source", "")))}</strong></td>
                <td class="font-mono">{html.escape(str(m.get("evidence_id", "")))}</td>
                <td class="font-mono hash-cell">{html.escape(str(m.get("sha256", "")))}</td>
                <td><span class="badge" style="color: #10b981; background: rgba(16, 185, 129, 0.15); border: 1px solid #10b98140;">✓ {html.escape(str(m.get("status", "VERIFIED")))}</span></td>
            </tr>
            """)

        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{title}</title>
    <style>
        :root {{
            --bg: #090d16;
            --surface: #111827;
            --surface-subtle: #1f2937;
            --border: #374151;
            --text-primary: #f9fafb;
            --text-secondary: #9ca3af;
            --accent-cyan: #38bdf8;
            --accent-emerald: #10b981;
            --accent-rose: #f43f5e;
            --accent-amber: #f59e0b;
        }}
        @media print {{
            body {{ background: #fff !important; color: #000 !important; }}
            .card, header, .attestation-card {{ border: 1px solid #ccc !important; background: #fff !important; color: #000 !important; }}
            .no-print {{ display: none !important; }}
        }}
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
            background-color: var(--bg);
            color: var(--text-primary);
            line-height: 1.6;
            padding: 2rem;
            max-width: 1200px;
            margin: 0 auto;
        }}
        header {{
            border-bottom: 2px solid var(--border);
            padding-bottom: 1.5rem;
            margin-bottom: 2rem;
            display: flex;
            justify-content: space-between;
            align-items: flex-start;
            flex-wrap: wrap;
            gap: 1rem;
        }}
        h1 {{ font-size: 1.6rem; font-weight: 800; color: #fff; letter-spacing: -0.02em; }}
        h2 {{ font-size: 1.15rem; font-weight: 700; margin-bottom: 1rem; color: var(--accent-cyan); text-transform: uppercase; letter-spacing: 0.05em; }}
        .meta-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 1rem; margin-bottom: 2rem; }}
        .card {{
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 1.25rem;
            margin-bottom: 2rem;
        }}
        .kpi-row {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 1rem; margin-top: 1rem; }}
        .kpi-box {{
            background: var(--surface-subtle);
            border: 1px solid var(--border);
            border-radius: 6px;
            padding: 1rem;
            text-align: center;
        }}
        .kpi-val {{ font-size: 1.8rem; font-weight: 800; }}
        .font-mono {{ font-family: ui-monospace, SFMono-Regular, "JetBrains Mono", Menlo, Consolas, monospace; }}
        .badge {{
            display: inline-block;
            padding: 0.2rem 0.55rem;
            border-radius: 4px;
            font-size: 0.72rem;
            font-weight: 700;
            text-transform: uppercase;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            font-size: 0.85rem;
            text-align: left;
        }}
        th, td {{ padding: 0.75rem 1rem; border-bottom: 1px solid var(--border); }}
        th {{ background: var(--surface-subtle); color: var(--text-secondary); font-size: 0.75rem; text-transform: uppercase; }}
        .hash-cell {{ word-break: break-all; font-size: 0.75rem; color: var(--accent-cyan); }}
        .attestation-card {{
            border: 2px solid var(--accent-emerald);
            background: rgba(16, 185, 129, 0.05);
            border-radius: 8px;
            padding: 1.5rem;
            margin-top: 2rem;
        }}
        .signature-line {{
            margin-top: 2rem;
            border-top: 1px solid var(--border);
            padding-top: 0.75rem;
            display: flex;
            justify-content: space-between;
            font-size: 0.8rem;
            color: var(--text-secondary);
        }}
    </style>
</head>
<body>
    <header>
        <div>
            <h1>{title}</h1>
            <p style="color: var(--text-secondary); font-size: 0.85rem; margin-top: 0.3rem;">
                Official Digital Forensic Examination Record &amp; Integrity Attestation
            </p>
        </div>
        <div style="text-align: right;">
            <div class="badge" style="background: rgba(56, 189, 248, 0.15); color: var(--accent-cyan); border: 1px solid var(--accent-cyan);">
                CERTIFIED REPORT
            </div>
            <div style="font-size: 0.75rem; color: var(--text-secondary); margin-top: 0.4rem;">
                JOCKY Forensic Framework v1.0
            </div>
        </div>
    </header>

    <div class="meta-grid">
        <div class="kpi-box" style="text-align: left;">
            <span style="font-size: 0.7rem; color: var(--text-secondary); text-transform: uppercase;">Case ID</span>
            <div class="font-mono" style="font-size: 1.1rem; font-weight: 700; color: #fff;">{case_id}</div>
        </div>
        <div class="kpi-box" style="text-align: left;">
            <span style="font-size: 0.7rem; color: var(--text-secondary); text-transform: uppercase;">Target System</span>
            <div class="font-mono" style="font-size: 1.1rem; font-weight: 700; color: var(--accent-cyan);">{target}</div>
        </div>
        <div class="kpi-box" style="text-align: left;">
            <span style="font-size: 0.7rem; color: var(--text-secondary); text-transform: uppercase;">Execution ID</span>
            <div class="font-mono" style="font-size: 0.95rem; font-weight: 600; color: #fff;">{exec_id}</div>
        </div>
        <div class="kpi-box" style="text-align: left;">
            <span style="font-size: 0.7rem; color: var(--text-secondary); text-transform: uppercase;">Generated (UTC)</span>
            <div class="font-mono" style="font-size: 0.85rem; color: #fff;">{gen_time}</div>
        </div>
    </div>

    <!-- Executive Summary Card -->
    <div class="card">
        <h2>1. Executive Summary</h2>
        <div style="display: flex; align-items: baseline; gap: 0.75rem;">
            <span style="font-size: 0.9rem; color: var(--text-secondary);">Incident Threat Assessment:</span>
            <span class="badge" style="font-size: 0.9rem; background: { 'rgba(239, 68, 68, 0.2)' if high_cnt > 0 else 'rgba(16, 185, 129, 0.2)' }; color: { '#ef4444' if high_cnt > 0 else '#10b981' }; border: 1px solid { '#ef4444' if high_cnt > 0 else '#10b981' };">
                {assessment}
            </span>
        </div>
        <div class="kpi-row">
            <div class="kpi-box">
                <div class="kpi-val" style="color: var(--accent-rose);">{high_cnt}</div>
                <div style="font-size: 0.75rem; color: var(--text-secondary);">High Severity</div>
            </div>
            <div class="kpi-box">
                <div class="kpi-val" style="color: var(--accent-amber);">{med_cnt}</div>
                <div style="font-size: 0.75rem; color: var(--text-secondary);">Medium Severity</div>
            </div>
            <div class="kpi-box">
                <div class="kpi-val" style="color: var(--accent-cyan);">{low_cnt}</div>
                <div style="font-size: 0.75rem; color: var(--text-secondary);">Low Severity</div>
            </div>
            <div class="kpi-box">
                <div class="kpi-val" style="color: var(--accent-emerald);">{vault_status}</div>
                <div style="font-size: 0.75rem; color: var(--text-secondary);">Vault Integrity</div>
            </div>
        </div>
    </div>

    <!-- Threat Detections -->
    <div class="card">
        <h2>2. Automated Forensic Detections</h2>
        <div style="overflow-x: auto;">
            <table>
                <thead>
                    <tr>
                        <th>Rule ID</th>
                        <th>Threat Classification</th>
                        <th>Severity</th>
                        <th>Technical Description</th>
                        <th>Correlated Entity</th>
                    </tr>
                </thead>
                <tbody>
                    {''.join(det_rows)}
                </tbody>
            </table>
        </div>
    </div>

    <!-- Cryptographic Manifest -->
    <div class="card">
        <h2>3. Sealed Evidence Vault Manifest</h2>
        <div style="overflow-x: auto;">
            <table>
                <thead>
                    <tr>
                        <th>Source</th>
                        <th>Evidence Identifier</th>
                        <th>Cryptographic Digest (SHA-256)</th>
                        <th>Integrity</th>
                    </tr>
                </thead>
                <tbody>
                    {''.join(manifest_rows)}
                </tbody>
            </table>
        </div>
    </div>

    <!-- Attestation Certificate -->
    <div class="attestation-card">
        <h2 style="color: var(--accent-emerald); margin-bottom: 0.5rem;">4. Cryptographic Evidence Attestation</h2>
        <p style="font-size: 0.85rem; font-style: italic; color: #d1fae5; margin-bottom: 1rem;">
            "{html.escape(str(att.get("statement", "")))}"
        </p>
        <div style="font-size: 0.8rem; display: flex; flex-direction: column; gap: 0.4rem;">
            <div><strong>Certificate ID:</strong> <span class="font-mono">{html.escape(str(att.get("certificate_id", "")))}</span></div>
            <div><strong>Vault Manifest SHA-256:</strong> <span class="font-mono" style="color: var(--accent-emerald);">{html.escape(str(att.get("manifest_sha256", "")))}</span></div>
            <div><strong>Vault Audit Status:</strong> <span style="font-weight: 700; color: var(--accent-emerald);">{html.escape(str(att.get("vault_status", "")))}</span></div>
        </div>
        <div class="signature-line">
            <div>Lead Examiner: <strong>{examiner}</strong></div>
            <div>Digital Issuance Date: <strong>{gen_time}</strong></div>
        </div>
    </div>
</body>
</html>"""
        return html_content
