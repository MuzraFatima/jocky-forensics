"""
JOCKY Forensic Analysis Framework - FastAPI Backend Entrypoint

Authorized digital-forensics research prototype for SIH26148.
Exposes REST endpoints for script parsing, policy validation, execution monitoring,
evidence verification, and report retrieval.
"""

from typing import Any, Dict, List, Optional

from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from backend.app.language import (
    JockyError,
    JockySyntaxError,
    JockyValidationError,
    compile_jocky,
    parse_jocky_script,
)
from backend.app.engine import ForensicExecutor, PolicyEngine, execute_jocky_ir

app = FastAPI(
    title="JOCKY Forensic Analysis Framework API",
    version="0.1.0",
    description="Authorized domain-specific forensic scripting & analysis framework",
)

# CORS configuration for React frontend communication
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

policy_engine = PolicyEngine()
executor = ForensicExecutor(policy_engine=policy_engine)


class ScriptParseRequest(BaseModel):
    script: str = Field(..., description="Raw JOCKY forensic script source text")


class CorrelateRequest(BaseModel):
    evidence: Optional[Dict[str, Any]] = None


class EvidencePayloadRequest(BaseModel):
    evidence: Optional[Dict[str, Any]] = None


class VaultSealRequest(BaseModel):
    case_id: str = Field(..., description="Case identifier")
    source: str = Field(..., description="Evidence source (e.g., system, processes, network)")
    data: Any = Field(..., description="Forensic data payload to seal")
    who: Optional[str] = "Forensic Investigator"
    why: Optional[str] = "Authorized forensic acquisition"
    what: Optional[str] = None
    execution_id: Optional[str] = None
    collector_identity: Optional[str] = "JOCKY-Collector"
    collector_version: Optional[str] = "1.0.0"
    target_host: Optional[str] = None


class VaultVerifyRequest(BaseModel):
    evidence_id: Optional[str] = None
    case_id: Optional[str] = None
    who: Optional[str] = "Forensic Verifier"
    why: Optional[str] = "Cryptographic integrity verification"


class VaultTamperRequest(BaseModel):
    evidence_id: str
    key_to_alter: Optional[str] = "tampered_flag"
    new_val: Optional[str] = "MODIFIED_DATA"


class ReportGenerationRequest(BaseModel):
    case_id: Optional[str] = "CASE-REPORT-001"
    target: Optional[str] = "LIVE-ENDPOINT"
    format: Optional[str] = "HTML"
    examiner: Optional[str] = "JOCKY Lead Forensic Examiner"
    evidence: Optional[Dict[str, Any]] = None


@app.get("/")
def read_root():
    """Root endpoint providing framework metadata."""
    return {
        "framework": "JOCKY",
        "description": "Domain-Specific Forensic Analysis Framework",
        "version": "0.1.0",
        "status": "operational",
        "scope": "Authorized read-only digital forensics",
    }


@app.get("/api/health")
def health_check():
    """Health check endpoint to verify backend operational readiness."""
    return {
        "status": "healthy",
        "framework": "JOCKY",
        "version": "0.1.0",
        "stage": "skeleton",
    }


@app.post("/api/jocky/parse")
def parse_endpoint(request: ScriptParseRequest):
    """
    Parse a JOCKY DSL script into AST and Validated Execution Plan.
    Returns AST, execution plan, and JOCKY IR on success,
    or structured error with line & column info.
    """
    try:
        result = parse_jocky_script(request.script)
        return {
            "success": True,
            "ast": result["ast"],
            "execution_plan": result["execution_plan"],
            "ir": result.get("ir"),
        }
    except JockyError as exc:
        return JSONResponse(
            status_code=400,
            content={
                "success": False,
                "error_type": exc.__class__.__name__,
                "message": exc.message,
                "line": exc.line,
                "column": exc.column,
            },
        )


@app.post("/api/jocky/compile")
def compile_endpoint(request: ScriptParseRequest):
    """
    Phase-1 JOCKY Compiler endpoint.

    Runs the full compilation pipeline:
        Source → Lexer → Parser → AST → Semantic Validation → JOCKY IR

    Returns on success::

        {
            "success": True,
            "tokens_count": <int>,
            "ast": <dict>,
            "ir": <dict>,
            "summary": {
                "case_id": "...",
                "target": "...",
                "operation_count": <int>,
                "operations": ["COLLECT SYSTEM", ...]
            }
        }

    Returns on error::

        HTTP 400 + { "success": False, "error_type": ..., "message": ...,
                     "line": ..., "column": ... }

    Does NOT execute any operations.
    """
    result = compile_jocky(request.script)

    if not result["success"]:
        err = result["error"]
        return JSONResponse(
            status_code=400,
            content={
                "success": False,
                "error_type": err.get("error_type", "JockyError"),
                "message": err.get("message", "Unknown compiler error"),
                "line": err.get("line"),
                "column": err.get("column"),
            },
        )

    ir = result["ir"]
    # Build a human-readable summary of each IR operation
    op_labels = []
    for op in ir.get("operations", []):
        op_type = op.get("type", "")
        op_target = op.get("target", "")
        op_fmt = op.get("format", "")
        if op_type == "COLLECT":
            parts = [f"COLLECT {op_target}"]
            for f in op.get("filters", []):
                parts.append(f"  WHERE {f['field']} {f['operator']} {f['value']}")
            op_labels.append("\n".join(parts))
        elif op_type == "ANALYZE" and op_target:
            op_labels.append(f"ANALYZE {op_target}")
        elif op_type == "REPORT" and op_fmt:
            op_labels.append(f"REPORT FORMAT {op_fmt}")
        else:
            op_labels.append(op_type if not op_target else f"{op_type} {op_target}")

    return {
        "success": True,
        "tokens_count": result["tokens_count"],
        "ast": result["ast"],
        "ir": ir,
        "summary": {
            "case_id": ir.get("case_id"),
            "target": ir.get("target"),
            "ir_version": ir.get("version"),
            "operation_count": len(ir.get("operations", [])),
            "operations": op_labels,
        },
    }


@app.post("/api/jocky/validate")
def validate_endpoint(request: ScriptParseRequest):
    """
    Parse script, generate execution plan, and evaluate against the Policy Engine.
    Returns policy decision with approved/rejected operations and read-only invariants.
    """
    try:
        parse_result = parse_jocky_script(request.script)
        execution_plan = parse_result["execution_plan"]
        policy_decision = policy_engine.evaluate(execution_plan)

        return {
            "success": True,
            "case_id": execution_plan.get("case_id"),
            "target": execution_plan.get("target"),
            "policy_decision": policy_decision,
            "execution_plan": execution_plan,
        }
    except JockyError as exc:
        return JSONResponse(
            status_code=400,
            content={
                "success": False,
                "error_type": exc.__class__.__name__,
                "message": exc.message,
                "line": exc.line,
                "column": exc.column,
            },
        )


@app.post("/api/jocky/investigate")
def investigate_endpoint(request: ScriptParseRequest):
    """
    Executes the end-to-end JOCKY forensic investigation pipeline:
    1. Parse JOCKY script
    2. Check operations against Policy Engine
    3. Execute safe read-only collectors (SYSTEM, PROCESSES, NETWORK)
    4. Store artifacts in EvidenceStore with SHA-256 hashes
    5. Perform heuristic analysis and verify cryptographic integrity
    6. Return complete investigation results
    """
    try:
        parse_result = parse_jocky_script(request.script)
        execution_plan = parse_result["execution_plan"]
        investigation_result = executor.run_investigation(execution_plan)
        return investigation_result
    except JockyError as exc:
        return JSONResponse(
            status_code=400,
            content={
                "success": False,
                "error_type": exc.__class__.__name__,
                "message": exc.message,
                "line": exc.line,
                "column": exc.column,
            },
        )


@app.post("/api/jocky/execute")
def execute_endpoint(request: ScriptParseRequest):
    """
    Phase-2 IR-native Execute endpoint.

    Runs the full JOCKY IR pipeline:
        JOCKY Source
          → Lexer → Parser → AST → Validator → JOCKY IR
          → IR Policy Check
          → Execution Plan (per-operation capability approval)
          → Forensic Collectors (SYSTEM / PROCESSES / NETWORK)
          → Evidence Store (SHA-256 + chain of custody)
          → Execution Receipt

    This endpoint is distinct from /api/jocky/investigate (legacy task-based path).
    It specifically exercises IRExecutor and evaluate_ir_policy, demonstrating the
    JOCKY IR → Policy → Execution pipeline defined in Phase 2.

    Returns:
        200 + Execution Receipt on success
        403 if any IR operation is denied by the policy engine
        400 on JOCKY syntax / semantic compilation error
    """
    compile_result = compile_jocky(request.script)

    if not compile_result["success"]:
        err = compile_result["error"]
        return JSONResponse(
            status_code=400,
            content={
                "success": False,
                "error_type": err.get("error_type", "JockyError"),
                "message": err.get("message", "Compilation error"),
                "line": err.get("line"),
                "column": err.get("column"),
            },
        )

    ir = compile_result["ir"]

    # Pre-flight: policy check before full execution
    from backend.app.engine import evaluate_ir_policy
    policy_result = evaluate_ir_policy(ir)

    if not policy_result["allowed"]:
        return JSONResponse(
            status_code=403,
            content={
                "success": False,
                "error_type": "PolicyDenied",
                "message": policy_result["reason"],
                "policy_result": policy_result,
                "ir": ir,
            },
        )

    # Full IR execution
    receipt = execute_jocky_ir(ir)
    return receipt


# ---------------------------------------------------------------------------
# Phase 3: Direct Forensic Collector Endpoints
# ---------------------------------------------------------------------------

@app.get("/api/forensics/collectors")
def list_collectors_endpoint():
    """
    Lists all available read-only forensic collectors and their capabilities.
    """
    from backend.app.collectors import get_collectors
    collectors = get_collectors()
    return {
        "framework": "JOCKY",
        "phase": 3,
        "scope": "Authorized read-only forensic collection",
        "collectors": [
            {
                "name": name,
                "active": callable(fn),
                "read_only": True,
                "description": fn.__doc__.strip().split("\n")[0] if callable(fn) and fn.__doc__ else "Forensic collector",
            }
            for name, fn in collectors.items()
        ],
    }


@app.get("/api/forensics/collect/{source}")
def direct_collect_endpoint(source: str, target_path: str = None):
    """
    Directly triggers a read-only forensic collector without requiring a script.
    Supported sources: system, processes, network, files, users, windows_metadata, registry.
    """
    from backend.app.collectors import get_collectors
    collectors = get_collectors()
    canonical_source = source.lower()

    if canonical_source not in collectors or not callable(collectors[canonical_source]):
        return JSONResponse(
            status_code=404,
            content={
                "success": False,
                "error": f"Unknown or inactive collector '{source}'.",
                "available_collectors": list(collectors.keys()),
            },
        )

    collector_fn = collectors[canonical_source]
    try:
        if canonical_source == "files" and target_path:
            artifact = collector_fn(target_path=target_path)
        else:
            artifact = collector_fn()

        return {
            "success": True,
            "source": canonical_source,
            "artifact": artifact,
        }
    except Exception as exc:
        return JSONResponse(
            status_code=500,
            content={
                "success": False,
                "source": canonical_source,
                "error": str(exc),
            },
        )


@app.get("/api/forensics/correlate")
def get_correlate_live():
    """
    Phase 4: Run live forensic collectors (processes, network, files, users)
    and return the unified correlation graph, entity IDs, process tree, and chains.
    """
    from backend.app.analysis.correlator import correlate_evidence
    from backend.app.collectors.files import collect_files_info
    from backend.app.collectors.network import collect_network_info
    from backend.app.collectors.processes import collect_process_info
    from backend.app.collectors.users import collect_users_info

    try:
        proc_data = collect_process_info()
        net_data = collect_network_info()
        file_data = collect_files_info(max_files=30)
        user_data = collect_users_info()

        correlation = correlate_evidence({
            "processes": proc_data,
            "network": net_data,
            "files": file_data,
            "users": user_data,
        })
        return {
            "success": True,
            "correlation": correlation,
        }
    except Exception as exc:
        return JSONResponse(
            status_code=500,
            content={"success": False, "error": str(exc)},
        )


@app.post("/api/forensics/correlate")
def post_correlate(request: CorrelateRequest):
    """
    Phase 4: Correlate arbitrary evidence payload.
    """
    from backend.app.analysis.correlator import correlate_evidence
    try:
        evidence = request.evidence or {}
        correlation = correlate_evidence(evidence)
        return {
            "success": True,
            "correlation": correlation,
        }
    except Exception as exc:
        return JSONResponse(
            status_code=500,
            content={"success": False, "error": str(exc)},
        )


@app.get("/api/forensics/timeline")
def get_timeline_live():
    """
    Phase 5: Reconstruct chronological forensic timeline from live system artifacts.
    """
    from backend.app.analysis.timeline import build_forensic_timeline
    from backend.app.collectors.files import collect_files_info
    from backend.app.collectors.network import collect_network_info
    from backend.app.collectors.processes import collect_process_info
    from backend.app.collectors.system import collect_system_info
    from backend.app.collectors.users import collect_users_info
    from backend.app.collectors.windows_metadata import collect_windows_metadata

    try:
        raw_evidence = {
            "system": collect_system_info(),
            "processes": collect_process_info(),
            "network": collect_network_info(),
            "files": collect_files_info(max_files=30),
            "users": collect_users_info(),
            "windows_metadata": collect_windows_metadata(),
        }
        events = build_forensic_timeline(raw_evidence)
        return {
            "success": True,
            "count": len(events),
            "timeline": events,
        }
    except Exception as exc:
        return JSONResponse(
            status_code=500,
            content={"success": False, "error": str(exc)},
        )


@app.post("/api/forensics/timeline")
def post_timeline(request: EvidencePayloadRequest):
    """
    Phase 5: Reconstruct chronological forensic timeline from supplied evidence payload.
    """
    from backend.app.analysis.timeline import build_forensic_timeline
    try:
        evidence = request.evidence or {}
        events = build_forensic_timeline(evidence)
        return {
            "success": True,
            "count": len(events),
            "timeline": events,
        }
    except Exception as exc:
        return JSONResponse(
            status_code=500,
            content={"success": False, "error": str(exc)},
        )


@app.get("/api/forensics/analysis")
def get_analysis_live():
    """
    Phase 5: Run deterministic heuristic forensic detection rules against live artifacts.
    """
    from backend.app.analysis.rules import evaluate_forensic_rules
    from backend.app.collectors.files import collect_files_info
    from backend.app.collectors.network import collect_network_info
    from backend.app.collectors.processes import collect_process_info
    from backend.app.collectors.windows_metadata import collect_windows_metadata

    try:
        raw_evidence = {
            "processes": collect_process_info(),
            "network": collect_network_info(),
            "files": collect_files_info(max_files=30),
            "windows_metadata": collect_windows_metadata(),
        }
        detections = evaluate_forensic_rules(raw_evidence)
        high = sum(1 for d in detections if d.get("severity") == "HIGH")
        medium = sum(1 for d in detections if d.get("severity") == "MEDIUM")
        low = sum(1 for d in detections if d.get("severity") == "LOW")

        return {
            "success": True,
            "total_detections": len(detections),
            "severity_counts": {
                "high": high,
                "medium": medium,
                "low": low,
            },
            "detections": detections,
        }
    except Exception as exc:
        return JSONResponse(
            status_code=500,
            content={"success": False, "error": str(exc)},
        )


@app.post("/api/forensics/analysis")
def post_analysis(request: EvidencePayloadRequest):
    """
    Phase 5: Run deterministic heuristic forensic detection rules against supplied evidence payload.
    """
    from backend.app.analysis.rules import evaluate_forensic_rules
    try:
        evidence = request.evidence or {}
        detections = evaluate_forensic_rules(evidence)
        high = sum(1 for d in detections if d.get("severity") == "HIGH")
        medium = sum(1 for d in detections if d.get("severity") == "MEDIUM")
        low = sum(1 for d in detections if d.get("severity") == "LOW")

        return {
            "success": True,
            "total_detections": len(detections),
            "severity_counts": {
                "high": high,
                "medium": medium,
                "low": low,
            },
            "detections": detections,
        }
    except Exception as exc:
        return JSONResponse(
            status_code=500,
            content={"success": False, "error": str(exc)},
        )


# ---------------------------------------------------------------------------
# Phase 6: Evidence Vault & Tamper-Evident Chain of Custody Endpoints
# ---------------------------------------------------------------------------

@app.get("/api/forensics/vault/list")
def vault_list_endpoint(case_id: Optional[str] = None):
    """
    Phase 6: List sealed evidence artifacts in the Evidence Vault with cryptographic status.
    """
    from backend.app.evidence import _default_vault
    try:
        audit = _default_vault.verify_vault_integrity(case_id=case_id)
        return {
            "success": True,
            "case_id": case_id or "ALL",
            "vault_status": audit["vault_status"],
            "total_artifacts": audit["total_artifacts"],
            "valid_count": audit["valid_count"],
            "tampered_count": audit["tampered_count"],
            "artifacts": audit["artifacts_summary"],
        }
    except Exception as exc:
        return JSONResponse(
            status_code=500,
            content={"success": False, "error": str(exc)},
        )


@app.get("/api/forensics/vault/artifact/{evidence_id}")
def vault_get_artifact_endpoint(evidence_id: str):
    """
    Phase 6: Retrieve a specific sealed artifact and its complete chain-of-custody ledger.
    """
    from backend.app.evidence import _default_vault
    artifact = _default_vault.get_artifact(evidence_id)
    if not artifact:
        return JSONResponse(
            status_code=404,
            content={"success": False, "error": f"Artifact '{evidence_id}' not found in vault."},
        )
    return {
        "success": True,
        "artifact": artifact,
    }


@app.post("/api/forensics/vault/seal")
def vault_seal_endpoint(request: VaultSealRequest):
    """
    Phase 6: Cryptographically seal a forensic payload into the Evidence Vault.
    Computes SHA-256, binds execution metadata, records ACQUIRED custody event.
    """
    from backend.app.evidence import _default_vault
    try:
        sealed = _default_vault.seal_artifact(
            case_id=request.case_id,
            source=request.source,
            data=request.data,
            who=request.who or "Forensic Investigator",
            why=request.why or "Authorized forensic acquisition",
            what=request.what,
            execution_id=request.execution_id,
            collector_identity=request.collector_identity or "JOCKY-Collector",
            collector_version=request.collector_version or "1.0.0",
            target_host=request.target_host,
        )
        return {
            "success": True,
            "evidence_id": sealed["evidence_id"],
            "case_id": sealed["case_id"],
            "sha256": sealed["sha256"],
            "execution_id": sealed["execution_id"],
            "timestamp_utc": sealed["timestamp_utc"],
            "sealed_record": sealed,
        }
    except Exception as exc:
        return JSONResponse(
            status_code=500,
            content={"success": False, "error": str(exc)},
        )


@app.post("/api/forensics/vault/verify")
def vault_verify_endpoint(request: VaultVerifyRequest):
    """
    Phase 6: Cryptographically verify an artifact or audit the entire vault.
    Recomputes SHA-256 against stored hash and records a VERIFIED or TAMPER_DETECTED event.
    """
    from backend.app.evidence import _default_vault
    try:
        if request.evidence_id:
            result = _default_vault.verify_artifact(
                evidence_id=request.evidence_id,
                who=request.who or "Forensic Verifier",
                why=request.why or "Cryptographic integrity verification",
            )
            return {"success": True, "verification": result}
        else:
            result = _default_vault.verify_vault_integrity(case_id=request.case_id)
            return {"success": True, "vault_audit": result}
    except FileNotFoundError as exc:
        return JSONResponse(
            status_code=404,
            content={"success": False, "error": str(exc)},
        )
    except Exception as exc:
        return JSONResponse(
            status_code=500,
            content={"success": False, "error": str(exc)},
        )


@app.get("/api/forensics/vault/audit")
def vault_audit_endpoint(case_id: Optional[str] = None):
    """
    Phase 6: Full cryptographic audit report and chronological custody ledger across all artifacts.
    """
    from backend.app.evidence import _default_vault
    try:
        audit_summary = _default_vault.verify_vault_integrity(case_id=case_id)
        custody_ledger = _default_vault.get_audit_ledger(case_id=case_id)
        return {
            "success": True,
            "case_id": case_id or "ALL",
            "vault_status": audit_summary["vault_status"],
            "audit_summary": audit_summary,
            "custody_ledger": custody_ledger,
            "total_ledger_events": len(custody_ledger),
        }
    except Exception as exc:
        return JSONResponse(
            status_code=500,
            content={"success": False, "error": str(exc)},
        )


@app.get("/api/forensics/vault/export/{case_id}")
def vault_export_endpoint(case_id: str):
    """
    Phase 6: Export all sealed artifacts for a case in a cryptographically manifest-signed bundle.
    """
    from backend.app.evidence import _default_vault
    try:
        bundle = _default_vault.export_vault_bundle(case_id=case_id)
        return {
            "success": True,
            "bundle": bundle,
        }
    except Exception as exc:
        return JSONResponse(
            status_code=500,
            content={"success": False, "error": str(exc)},
        )


@app.post("/api/forensics/vault/simulate-tampering")
def vault_simulate_tampering_endpoint(request: VaultTamperRequest):
    """
    Phase 6: Test/Demonstration endpoint to simulate evidence tampering on disk.
    Alters payload without recalculating recorded SHA-256 hash.
    """
    from backend.app.evidence import _default_vault
    try:
        modified = _default_vault.simulate_tampering(
            evidence_id=request.evidence_id,
            key_to_alter=request.key_to_alter or "tampered_flag",
            new_val=request.new_val or "MODIFIED_DATA",
        )
        if not modified:
            return JSONResponse(
                status_code=404,
                content={"success": False, "error": f"Evidence '{request.evidence_id}' not found."},
            )
        return {
            "success": True,
            "evidence_id": request.evidence_id,
            "tampered": True,
            "message": "Data payload modified on disk without updating recorded SHA-256 hash.",
        }
    except Exception as exc:
        return JSONResponse(
            status_code=500,
            content={"success": False, "error": str(exc)},
        )


# ---------------------------------------------------------------------------
# Phase 7: Cross-Platform Forensics Status Endpoint
# ---------------------------------------------------------------------------

@app.get("/api/forensics/platform")
def get_platform_info():
    """
    Phase 7: Return system platform detection, supported collector capabilities,
    and cross-platform execution mode (Windows / Linux).
    """
    import platform
    current_os = platform.system()
    return {
        "success": True,
        "platform": current_os,
        "release": platform.release(),
        "architecture": platform.machine(),
        "is_windows": current_os == "Windows",
        "is_linux": current_os == "Linux",
        "read_only": True,
        "supported_collectors": [
            "system",
            "processes",
            "network",
            "files",
            "users",
            "persistence",
        ],
        "capabilities": {
            "windows": [
                "win32_registry",
                "scheduled_tasks",
                "win_services",
                "ntfs_metadata",
                "powershell_logging",
            ],
            "linux": [
                "os_release",
                "proc_fs",
                "cron_tabs",
                "systemd_units",
                "passwd_shadow",
                "bash_history",
            ],
        },
    }


# ---------------------------------------------------------------------------
# Phase 8: Forensic Report Generation Endpoints
# ---------------------------------------------------------------------------

@app.post("/api/forensics/report")
def generate_report_endpoint(request: ReportGenerationRequest):
    """
    Phase 8: Generate a structured forensic investigation report in JSON, Markdown, or HTML.
    Includes executive threat summary, correlation lineage, evidence manifest,
    and cryptographic attestation certificate.
    """
    from backend.app.reporting import ForensicReportBuilder
    from backend.app.analysis.correlator import correlate_evidence
    from backend.app.analysis.timeline import build_forensic_timeline
    from backend.app.analysis.rules import evaluate_forensic_rules
    from backend.app.evidence import _default_vault

    try:
        evidence = request.evidence
        if not evidence:
            from backend.app.collectors.files import collect_files_info
            from backend.app.collectors.network import collect_network_info
            from backend.app.collectors.processes import collect_process_info
            from backend.app.collectors.system import collect_system_info
            from backend.app.collectors.users import collect_users_info
            from backend.app.collectors.windows_metadata import collect_windows_metadata

            evidence = {
                "system": collect_system_info(),
                "processes": collect_process_info(),
                "network": collect_network_info(),
                "files": collect_files_info(max_files=30),
                "users": collect_users_info(),
                "windows_metadata": collect_windows_metadata(),
            }

        # Downstream analysis
        correlation = correlate_evidence(evidence)
        timeline = build_forensic_timeline(evidence)
        detections = evaluate_forensic_rules(evidence)
        vault_audit = _default_vault.verify_vault_integrity(case_id=request.case_id)

        builder = ForensicReportBuilder(
            case_id=request.case_id or "CASE-REPORT-001",
            target=request.target or "LIVE-ENDPOINT",
            examiner=request.examiner or "JOCKY Lead Forensic Examiner",
        )

        report_data = builder.build_report_data(
            collected_data=evidence,
            correlation=correlation,
            timeline=timeline,
            detections=detections,
            vault_audit=vault_audit,
        )

        fmt = (request.format or "HTML").upper()
        if fmt == "HTML":
            content = builder.generate_html(report_data)
        elif fmt in ("MD", "MARKDOWN"):
            content = builder.generate_markdown(report_data)
        else:
            content = builder.generate_json(report_data)

        return {
            "success": True,
            "format": fmt,
            "report_data": report_data,
            "content": content,
            "attestation": report_data.get("attestation"),
        }
    except Exception as exc:
        return JSONResponse(
            status_code=500,
            content={"success": False, "error": str(exc)},
        )


@app.get("/api/forensics/report/live")
def get_live_report_endpoint(format: str = "HTML", case_id: str = "CASE-LIVE-001"):
    """
    Phase 8: Directly generates a live report across active collectors in the specified format.
    """
    req = ReportGenerationRequest(case_id=case_id, format=format)
    return generate_report_endpoint(req)


@app.get("/api/forensics/report/download")
def download_report_endpoint(format: str = "html", case_id: str = "CASE-LIVE-001"):
    """
    Phase 8: Downloads the generated forensic report as an attachment (.html, .md, or .json).
    """
    fmt_clean = format.lower().strip()
    req_format = "HTML" if fmt_clean == "html" else "MARKDOWN" if fmt_clean in ("md", "markdown") else "JSON"
    res = generate_report_endpoint(ReportGenerationRequest(case_id=case_id, format=req_format))

    if isinstance(res, JSONResponse):
        return res

    content = res.get("content", "")
    safe_case = case_id.replace(" ", "_")

    if req_format == "HTML":
        media_type = "text/html; charset=utf-8"
        filename = f"jocky_report_{safe_case}.html"
    elif req_format == "MARKDOWN":
        media_type = "text/markdown; charset=utf-8"
        filename = f"jocky_report_{safe_case}.md"
    else:
        media_type = "application/json; charset=utf-8"
        filename = f"jocky_report_{safe_case}.json"

    return Response(
        content=content,
        media_type=media_type,
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )



