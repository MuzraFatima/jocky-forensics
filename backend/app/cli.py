"""
JOCKY Forensic Framework — Standalone Command-Line Interface (Phase 10)

Provides a headless, scriptable CLI for incident response, scripted triage,
automated evidence acquisition, and vault auditing without a GUI.

Commands:
    jocky compile <script_file>
    jocky execute <script_file> [--format HTML|MD|JSON] [--output <path>]
    jocky audit [--case <case_id>]
    jocky export <case_id> [--output <path>]
    jocky report [--format HTML|MD|JSON] [--output <path>]
    jocky serve [--host 127.0.0.1] [--port 8000]
"""

import argparse
import json
import sys
from pathlib import Path
from typing import Optional

from backend.app.language.compiler import compile_jocky
from backend.app.engine import execute_jocky_ir
from backend.app.evidence import _default_vault
from backend.app.reporting import ForensicReportBuilder


def cmd_compile(args: argparse.Namespace) -> int:
    """Compiles a JOCKY script file and validates syntax & semantics."""
    script_path = Path(args.script_file)
    if not script_path.exists():
        print(f"Error: Script file '{args.script_file}' not found.", file=sys.stderr)
        return 1

    script_text = script_path.read_text(encoding="utf-8")
    result = compile_jocky(script_text)

    if result["success"]:
        ir = result["ir"]
        print(f"[+] Compilation SUCCESSFUL ({result['tokens_count']} tokens)")
        print(f"    Case ID:    {ir.get('case_id')}")
        print(f"    Target:     {ir.get('target')}")
        print(f"    IR Version: {ir.get('version')}")
        print(f"    Operations: {len(ir.get('operations', []))}")
        for op in ir.get("operations", []):
            print(f"      - {op.get('type')} {op.get('target') or ''} {op.get('format') or ''}")
        return 0
    else:
        err = result["error"]
        print(f"[-] Compilation FAILED: {err.get('error_type')}", file=sys.stderr)
        print(f"    Line {err.get('line')}, Column {err.get('column')}: {err.get('message')}", file=sys.stderr)
        return 1


def cmd_execute(args: argparse.Namespace) -> int:
    """Executes a JOCKY script through the full IR pipeline and outputs report."""
    script_path = Path(args.script_file)
    if not script_path.exists():
        print(f"Error: Script file '{args.script_file}' not found.", file=sys.stderr)
        return 1

    script_text = script_path.read_text(encoding="utf-8")
    comp = compile_jocky(script_text)
    if not comp["success"]:
        print(f"[-] Compilation error: {comp['error'].get('message')}", file=sys.stderr)
        return 1

    ir = comp["ir"]
    print(f"[*] Executing JOCKY IR for case '{ir.get('case_id')}'...")
    receipt = execute_jocky_ir(ir)

    if not receipt["success"]:
        print(f"[-] Execution failed: {receipt.get('error')}", file=sys.stderr)
        return 1

    print(f"[+] Execution completed successfully!")
    print(f"    Artifacts collected: {len(receipt.get('evidence_ids', {}))}")
    print(f"    Integrity verified:  {receipt.get('integrity_status', {}).get('verified')}")

    # Build report in requested format
    fmt = (args.format or "HTML").upper()
    builder = ForensicReportBuilder(
        case_id=receipt["case_id"],
        target=receipt["target"],
    )
    rep_data = builder.build_report_data(
        collected_data=receipt.get("collected_data"),
        correlation=receipt.get("correlation"),
        timeline=receipt.get("timeline"),
        detections=receipt.get("detections"),
        evidence_ids=receipt.get("evidence_ids"),
        sha256_hashes=receipt.get("sha256_hashes"),
    )

    if fmt == "HTML":
        out_content = builder.generate_html(rep_data)
    elif fmt in ("MD", "MARKDOWN"):
        out_content = builder.generate_markdown(rep_data)
    else:
        out_content = builder.generate_json(rep_data)

    if args.output:
        out_p = Path(args.output)
        out_p.parent.mkdir(parents=True, exist_ok=True)
        out_p.write_text(out_content, encoding="utf-8")
        print(f"[+] Report written to: {out_p.resolve()}")
    else:
        if fmt == "JSON":
            print(out_content)
        else:
            print(f"[+] Report generated ({len(out_content)} bytes). Use --output to save.")

    return 0


def cmd_audit(args: argparse.Namespace) -> int:
    """Audits the Evidence Vault cryptographic integrity."""
    print("[*] Auditing Evidence Vault cryptographic integrity...")
    audit = _default_vault.verify_vault_integrity(case_id=args.case)

    print(f"[+] Vault Status: {audit['vault_status']}")
    print(f"    Total Artifacts: {audit['total_artifacts']}")
    print(f"    Valid Artifacts: {audit['valid_count']}")
    print(f"    Tampered Count:  {audit['tampered_count']}")

    if audit["tampered_count"] > 0:
        print("[-] WARNING: Tampered artifacts detected:")
        for ta in audit["tampered_artifacts"]:
            print(f"    - ID: {ta.get('evidence_id')} | Stored: {ta.get('stored_hash')[:16]}... | Recomputed: {ta.get('recomputed_hash')[:16]}...")
        return 2

    return 0


def cmd_export(args: argparse.Namespace) -> int:
    """Exports a signed evidence bundle with manifest."""
    case_id = args.case_id
    out_file = args.output or f"jocky_bundle_{case_id}.json"
    print(f"[*] Exporting evidence bundle for case '{case_id}'...")
    bundle = _default_vault.export_vault_bundle(case_id=case_id, output_path=out_file)
    print(f"[+] Bundle exported to: {out_file}")
    print(f"    Artifacts:       {bundle['manifest']['artifact_count']}")
    print(f"    Manifest SHA256: {bundle['manifest']['manifest_sha256']}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    """Constructs the JOCKY CLI argument parser."""
    parser = argparse.ArgumentParser(
        prog="jocky",
        description="JOCKY Forensic Framework — Authorized Incident Response CLI",
    )
    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # compile
    p_compile = subparsers.add_parser("compile", help="Compile and validate JOCKY DSL script")
    p_compile.add_argument("script_file", help="Path to JOCKY script file (.jocky)")

    # execute
    p_exec = subparsers.add_parser("execute", help="Execute JOCKY IR pipeline and output report")
    p_exec.add_argument("script_file", help="Path to JOCKY script file")
    p_exec.add_argument("--format", choices=["HTML", "MD", "JSON"], default="HTML", help="Report output format")
    p_exec.add_argument("--output", "-o", help="File path to save the generated report")

    # audit
    p_audit = subparsers.add_parser("audit", help="Audit Evidence Vault cryptographic integrity")
    p_audit.add_argument("--case", help="Optional case ID filter")

    # export
    p_export = subparsers.add_parser("export", help="Export cryptographically signed evidence bundle")
    p_export.add_argument("case_id", help="Case identifier to export")
    p_export.add_argument("--output", "-o", help="Destination path for bundle JSON")

    return parser


def main(argv: Optional[list] = None) -> int:
    """Main CLI entrypoint."""
    parser = build_parser()
    args = parser.parse_args(argv)

    if not args.command:
        parser.print_help()
        return 0

    if args.command == "compile":
        return cmd_compile(args)
    elif args.command == "execute":
        return cmd_execute(args)
    elif args.command == "audit":
        return cmd_audit(args)
    elif args.command == "export":
        return cmd_export(args)

    return 0


if __name__ == "__main__":
    sys.exit(main())
