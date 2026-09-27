"""
JOCKY Forensic Analysis Framework - FastAPI Backend Entrypoint

Authorized digital-forensics research prototype for SIH26148.
Exposes REST endpoints for script parsing, policy validation, execution monitoring,
evidence verification, and report retrieval.
"""

import os
import sys
from pathlib import Path

# Ensure project root is in sys.path
_repo_root = Path(__file__).resolve().parent.parent.parent
if str(_repo_root) not in sys.path:
    sys.path.insert(0, str(_repo_root))

from typing import Any, Dict, List, Optional

from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from backend.app.language import (
    JockyError,
    JockySyntaxError,
    JockyValidationError,
    compile_jocky,
    parse_jocky_script,
)
from backend.app.engine import ForensicExecutor, PolicyEngine, execute_jocky_ir
from backend.app.security import security_router
from backend.app.agents.routes import router as agent_router

app = FastAPI(
    title="JOCKY Forensic Analysis Framework API",
    version="0.1.0",
    description="Authorized domain-specific forensic scripting & analysis framework",
)

# CORS configuration for React frontend communication & live deployment
cors_origins_env = os.getenv("CORS_ORIGINS", "")
if cors_origins_env.strip():
    allowed_origins = [o.strip() for o in cors_origins_env.split(",") if o.strip()]
else:
    allowed_origins = [
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:3000",
        "http://127.0.0.1:3000",
        "http://localhost:8000",
        "http://127.0.0.1:8000",
    ]

# If allowed_origins contains "*", browsers disallow credentials=True
allow_all = "*" in allowed_origins or cors_origins_env.strip() == "*"

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"] if allow_all else allowed_origins,
    allow_origin_regex=os.getenv("CORS_ORIGIN_REGEX", None),
    allow_credentials=True if not allow_all else False,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount Security & Incident Response router
app.include_router(security_router)

# Mount Endpoint Agent router
app.include_router(agent_router)

policy_engine = PolicyEngine()
executor = ForensicExecutor(policy_engine=policy_engine)



class ScriptParseRequest(BaseModel):
    script: str = Field(..., description="Raw JOCKY forensic script source text")
    device_id: Optional[str] = Field(None, description="Optional target enrolled endpoint device ID")
    wait_timeout: Optional[int] = Field(30, description="Timeout in seconds to await endpoint execution")


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


@app.get("/api")
@app.get("/api/status")
def read_root():
    """API root/status endpoint providing framework metadata."""
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
    import re
    import uuid

    # Normalize bare 'COLLECT FILES' if not followed by a path string
    normalized_script = re.sub(
        r'(?i)^\s*COLLECT\s+FILES\s*$',
        'COLLECT FILES "evidence"',
        request.script,
        flags=re.MULTILINE,
    )

    compile_result = compile_jocky(normalized_script)

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

    # Check if target is a remote enrolled endpoint
    target_device_id = (request.device_id or "").strip()
    is_remote = bool(target_device_id and target_device_id.lower() != "local")

    from backend.app.evidence import _default_vault

    if is_remote:
        import time
        from backend.app.agents.manager import get_agent_manager
        from backend.app.agents.models import AgentJob, AllowedCollector, CollectorOperation
        from backend.app.engine.providers import EndpointEvidenceProvider

        agent_manager = get_agent_manager()
        dev = agent_manager.get_device(target_device_id)
        if not dev:
            return JSONResponse(
                status_code=400,
                content={
                    "success": False,
                    "error_type": "DeviceNotFound",
                    "message": f"Target endpoint device '{target_device_id}' not found.",
                },
            )
        if not agent_manager.is_device_active(target_device_id):
            return JSONResponse(
                status_code=400,
                content={
                    "success": False,
                    "error_type": "DeviceNotActive",
                    "message": f"Target endpoint device '{target_device_id}' is not active or has been revoked.",
                },
            )

        case_id = ir.get("case_id") or "DEFAULT-CASE"
        exec_id = f"EXEC-{uuid.uuid4().hex[:8].upper()}"

        # Extract required collector operations
        allowed_ops = []
        expected_collectors = []
        for op in ir.get("operations", []):
            if op.get("type", "").upper() == "COLLECT":
                col_str = (op.get("target") or "").lower()
                try:
                    col_enum = AllowedCollector(col_str)
                    params = {}
                    if "path" in op and op["path"]:
                        params["target_path"] = op["path"]
                    allowed_ops.append(
                        CollectorOperation(
                            collector=col_enum,
                            params=params,
                            filters=op.get("filters", []),
                        )
                    )
                    expected_collectors.append(col_str)
                except ValueError:
                    pass

        if not allowed_ops:
            return JSONResponse(
                status_code=400,
                content={
                    "success": False,
                    "error_type": "NoOperations",
                    "message": "Script contains no valid forensic collection operations for endpoint.",
                },
            )

        job_id = f"JOB-{uuid.uuid4().hex[:8].upper()}"
        timeout_secs = min(max(request.wait_timeout or 30, 5), 120)

        job = AgentJob(
            job_id=job_id,
            user_id=dev.user_id,
            device_id=dev.device_id,
            case_id=case_id,
            execution_id=exec_id,
            allowed_operations=allowed_ops,
            timeout_seconds=timeout_secs,
        )
        agent_manager.enqueue_job(dev.device_id, job)

        # Await completion from endpoint
        start_wait = time.time()
        while time.time() - start_wait < timeout_secs:
            if agent_manager.is_execution_complete(exec_id, expected_collectors):
                break
            time.sleep(0.1)

        if not agent_manager.is_execution_complete(exec_id, expected_collectors):
            return JSONResponse(
                status_code=408,
                content={
                    "success": False,
                    "error_type": "EndpointTimeout",
                    "message": f"Timed out waiting for endpoint agent '{dev.device_id}' to upload evidence.",
                    "execution_id": exec_id,
                    "job_id": job_id,
                    "expected_collectors": expected_collectors,
                },
            )

        submissions = agent_manager.get_results(exec_id)
        provider = EndpointEvidenceProvider(
            evidence=submissions,
            expected_device_id=dev.device_id,
            expected_execution_id=exec_id,
        )

        receipt = execute_jocky_ir(ir, collector_provider=provider)
        receipt["execution_id"] = exec_id
        receipt["target_device_id"] = dev.device_id
        receipt["target_host"] = dev.hostname
        receipt["device_platform"] = dev.platform
        receipt["collector_identity"] = "JOCKY-Endpoint-Agent"
        receipt["errors"] = [receipt["error"]] if receipt.get("error") else []

        evidence_collected_list = []
        for category, data in receipt.get("collected_data", {}).items():
            evid_id = receipt.get("evidence_ids", {}).get(category)
            sha = receipt.get("sha256_hashes", {}).get(category)
            try:
                sealed = _default_vault.seal_artifact(
                    case_id=case_id,
                    source=category,
                    data=data,
                    who=f"JOCKY Endpoint Agent ({dev.device_id})",
                    why=f"Authorized endpoint acquisition for {case_id}",
                    execution_id=exec_id,
                    collector_identity="JOCKY-Endpoint-Agent",
                    collector_version=dev.agent_version,
                    target_host=dev.hostname,
                )
                evid_id = sealed["evidence_id"]
                sha = sealed["sha256"]
                receipt.setdefault("evidence_ids", {})[category] = evid_id
                receipt.setdefault("sha256_hashes", {})[category] = sha
            except Exception:
                pass
            evidence_collected_list.append({
                "category": category,
                "evidence_id": evid_id,
                "sha256": sha,
                "data": data,
            })
        receipt["evidence_collected"] = evidence_collected_list
        agent_manager.clear_results(exec_id)
        return receipt

    # Full Local IR execution
    receipt = execute_jocky_ir(ir)

    case_id = receipt.get("case_id") or "DEFAULT-CASE"
    target = receipt.get("target") or "LOCAL-HOST"
    exec_id = ir.get("execution_id") or receipt.get("execution_id") or f"EXEC-{uuid.uuid4().hex[:8].upper()}"

    receipt["execution_id"] = exec_id
    receipt["errors"] = [receipt["error"]] if receipt.get("error") else []

    # Seal each collected evidence in the Evidence Vault to persist through the vault flow
    evidence_collected_list = []
    for category, data in receipt.get("collected_data", {}).items():
        evid_id = receipt.get("evidence_ids", {}).get(category)
        sha = receipt.get("sha256_hashes", {}).get(category)
        try:
            sealed = _default_vault.seal_artifact(
                case_id=case_id,
                source=category,
                data=data,
                who="JOCKY IR Pipeline",
                why=f"IR execution collection for {case_id}",
                execution_id=exec_id,
                target_host=target,
            )
            evid_id = sealed["evidence_id"]
            sha = sealed["sha256"]
            receipt.setdefault("evidence_ids", {})[category] = evid_id
            receipt.setdefault("sha256_hashes", {})[category] = sha
        except Exception:
            pass
        evidence_collected_list.append({
            "category": category,
            "evidence_id": evid_id,
            "sha256": sha,
            "data": data,
        })
    receipt["evidence_collected"] = evidence_collected_list
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
        "is_macos": current_os in ("Darwin", "macOS"),
        "is_darwin": current_os in ("Darwin", "macOS"),
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
            "macos": [
                "system_version_plist",
                "launch_daemons",
                "launch_agents",
                "mach_o_binaries",
                "posix_users",
                "cron_tabs",
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
        from backend.app.analysis import ForensicContext, analyze_evidence_techniques, build_mitre_analysis

        forensic_ctx = ForensicContext(
            case_id=request.case_id or "CASE-REPORT-001",
            target_host=request.target or "LIVE-ENDPOINT",
        )
        technique_findings = analyze_evidence_techniques(evidence, forensic_ctx)
        mitre_analysis = build_mitre_analysis(technique_findings, forensic_ctx)

        correlation = correlate_evidence(evidence, findings=technique_findings)
        timeline = build_forensic_timeline(evidence, findings=technique_findings)
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
            technique_findings=technique_findings,
            mitre_analysis=mitre_analysis,
        )

        fmt = (request.format or "HTML").upper()
        if fmt == "HTML":
            content = builder.generate_html(report_data)
        elif fmt in ("MD", "MARKDOWN"):
            content = builder.generate_markdown(report_data)
        else:
            content = builder.generate_json(report_data)

        saved_path = builder.save_report(content, fmt)

        return {
            "success": True,
            "format": fmt,
            "report_data": report_data,
            "content": content,
            "saved_path": str(saved_path),
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


# ---------------------------------------------------------------------------
# Phase 2: Advanced Forensic Technique Registry Endpoints
# ---------------------------------------------------------------------------

@app.get("/api/forensics/techniques/stats/summary")
def get_technique_summary_endpoint():
    """
    Phase 2: Returns aggregated summary counts of all registered advanced forensic techniques.
    """
    from backend.app.analysis.registry import get_technique_registry
    registry = get_technique_registry()
    return {
        "success": True,
        "summary": registry.get_summary(),
    }


@app.get("/api/forensics/techniques")
def list_techniques_endpoint(
    category: Optional[str] = None,
    status: Optional[str] = None,
    mitre_only: bool = False,
    demo_only: bool = False,
):
    """
    Phase 2: Returns list of safe advanced forensic techniques that JOCKY can analyze or detect.
    Supports filtering by category, status, MITRE mapping, or demo availability.
    """
    from backend.app.analysis.registry import (
        AnalysisStatus,
        TechniqueCategory,
        get_technique_registry,
    )
    registry = get_technique_registry()

    cat_filter = None
    if category:
        for c in TechniqueCategory:
            if c.value.lower() == category.lower() or c.name.lower() == category.lower():
                cat_filter = c
                break

    status_filter = None
    if status:
        for s in AnalysisStatus:
            if s.value.lower() == status.lower() or s.name.lower() == status.lower():
                status_filter = s
                break

    techniques = registry.list_techniques(
        category=cat_filter,
        status=status_filter,
        mitre_only=mitre_only,
        demo_only=demo_only,
    )
    return {
        "success": True,
        "count": len(techniques),
        "techniques": [t.model_dump() for t in techniques],
    }


@app.get("/api/forensics/techniques/{technique_id}")
def get_technique_endpoint(technique_id: str):
    """
    Phase 2: Retrieves detailed specification for a specific forensic technique by ID or MITRE ID.
    """
    from backend.app.analysis.registry import get_technique_registry
    registry = get_technique_registry()
    tech = registry.get(technique_id) or registry.get_by_mitre(technique_id)
    if not tech:
        return JSONResponse(
            status_code=404,
            content={"success": False, "error": f"Technique '{technique_id}' not found in registry."},
        )
    return {
        "success": True,
        "technique": tech.model_dump(),
    }


class TechniqueAnalysisRequest(BaseModel):
    evidence: Optional[Dict[str, Any]] = None
    case_id: Optional[str] = "CASE-ANALYSIS-001"
    execution_id: Optional[str] = None
    device_id: Optional[str] = None
    target_host: Optional[str] = "localhost"


@app.post("/api/forensics/analyze/techniques")
def analyze_techniques_endpoint(request: TechniqueAnalysisRequest):
    """
    Phase 3: Analyzes forensic evidence through the Evidence → Indicator → Technique → Finding pipeline.
    Preserves evidence IDs, timestamps, device ID, case ID, and execution ID.
    """
    from backend.app.analysis import ForensicContext, analyze_evidence_techniques
    from backend.app.collectors.files import collect_files_info
    from backend.app.collectors.network import collect_network_info
    from backend.app.collectors.processes import collect_process_info
    from backend.app.collectors.system import collect_system_info

    evidence = request.evidence
    if not evidence:
        evidence = {
            "system": collect_system_info(),
            "processes": collect_process_info(),
            "network": collect_network_info(),
            "files": collect_files_info(max_files=15),
        }

    ctx = ForensicContext(
        case_id=request.case_id or "CASE-ANALYSIS-001",
        execution_id=request.execution_id,
        device_id=request.device_id,
        target_host=request.target_host or "localhost",
    )

    findings = analyze_evidence_techniques(evidence, ctx)
    from backend.app.analysis.mitre import build_mitre_analysis
    mitre_analysis = build_mitre_analysis(findings, ctx)
    return {
        "success": True,
        "case_id": ctx.case_id,
        "execution_id": ctx.execution_id,
        "device_id": ctx.device_id,
        "target_host": ctx.target_host,
        "findings_count": len(findings),
        "findings": findings,
        "mitre_analysis": mitre_analysis,
    }


# -----------------------------------------------------------------------------
# Static Frontend Serving (Single-Service Deployment Mode)
# -----------------------------------------------------------------------------
_dist_dir = _repo_root / "frontend" / "dist"
if _dist_dir.is_dir():
    _assets_dir = _dist_dir / "assets"
    if _assets_dir.is_dir():
        app.mount("/assets", StaticFiles(directory=str(_assets_dir)), name="assets")

    @app.get("/")
    async def serve_root():
        index_file = _dist_dir / "index.html"
        if index_file.is_file():
            return FileResponse(str(index_file))
        return JSONResponse(status_code=404, content={"detail": "Frontend index.html not found"})

    @app.get("/{full_path:path}")
    async def serve_spa_frontend(full_path: str):
        # Don't intercept API routes, OpenAPI docs, or Swagger
        if full_path.startswith("api") or full_path.startswith("docs") or full_path.startswith("openapi.json"):
            return JSONResponse(status_code=404, content={"detail": "Not Found"})
        file_path = _dist_dir / full_path
        if file_path.is_file():
            return FileResponse(str(file_path))
        index_file = _dist_dir / "index.html"
        if index_file.is_file():
            return FileResponse(str(index_file))
        return JSONResponse(status_code=404, content={"detail": "Not Found"})




