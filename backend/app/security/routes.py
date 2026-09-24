"""
JOCKY Forensic Framework — Security & Incident Response API Routes

Exposes endpoints for:
- Authentication (login, logout, session verification)
- Security analyst availability & chat channel
- AI forensic assistant fallback
- Critical incident alert triage
- Forensic report generation & secure queue delivery
- Chronological audit logging
"""

from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Header, HTTPException, Request, Response
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from .audit import get_audit_events, record_audit_event
from .auth import authenticate_user, revoke_token, validate_token
from .analyst import analyst_manager, get_analyst_status, set_analyst_status
from .ai_provider import query_ai_assistant
from .incident import get_current_incident
from .report_queue import report_queue, send_or_queue_report

router = APIRouter(tags=["Security & Incident Response"])


# ─── Pydantic Request Models ────────────────────────────────────────────────

class LoginRequest(BaseModel):
    username: str = Field(..., description="Investigator username or email")
    password: str = Field(..., description="Investigator access password")
    case_id: Optional[str] = "LAB-2026-001"


class LogoutRequest(BaseModel):
    token: Optional[str] = None
    report_sent_status: Optional[str] = "LOGOUT_WITHOUT_SENDING"
    case_id: Optional[str] = "LAB-2026-001"


class AnalystToggleRequest(BaseModel):
    status: str = Field(..., description="ONLINE, OFFLINE, or BUSY")


class ServiceToggleRequest(BaseModel):
    reachable: bool = Field(..., description="Simulate security service reachability")


class ChatMessageRequest(BaseModel):
    message: str = Field(..., description="Investigator question or statement")
    mode: Optional[str] = "auto"  # auto, analyst, ai
    case_id: Optional[str] = "LAB-2026-001"
    incident_id: Optional[str] = None
    context: Optional[Dict[str, Any]] = None


class ReportSendRequest(BaseModel):
    case_id: Optional[str] = "LAB-2026-001"
    target: Optional[str] = "LAB-PC"
    format: Optional[str] = "HTML"
    examiner: Optional[str] = "JOCKY Lead Forensic Examiner"
    destination: Optional[str] = "SOC-INGESTION-SERVICE"
    evidence: Optional[Dict[str, Any]] = None


class ReportGenerateRequest(BaseModel):
    case_id: Optional[str] = "LAB-2026-001"
    target: Optional[str] = "LAB-PC"
    format: Optional[str] = "HTML"
    examiner: Optional[str] = "JOCKY Lead Forensic Examiner"
    evidence: Optional[Dict[str, Any]] = None


# ─── 1. Authentication Endpoints ───────────────────────────────────────────

@router.post("/api/auth/login")
@router.post("/auth/login")
def login_endpoint(req: LoginRequest, request: Request):
    """Authenticates investigator credentials and issues a secure session token."""
    client_ip = request.client.host if request.client else "127.0.0.1"
    session = authenticate_user(
        username=req.username,
        password=req.password,
        case_id=req.case_id,
        ip_address=client_ip,
    )
    if not session:
        return JSONResponse(
            status_code=401,
            content={
                "success": False,
                "error": "Invalid investigator credentials. Please verify your username and password.",
            },
        )
    return {"success": True, "session": session}


@router.post("/api/auth/logout")
@router.post("/auth/logout")
def logout_endpoint(
    req: LogoutRequest,
    authorization: Optional[str] = Header(None),
):
    """Terminates investigator session and records audit event."""
    token = req.token or authorization
    session = validate_token(token)
    user = session["username"] if session else "INVESTIGATOR"
    revoked = revoke_token(
        token=token,
        user=user,
        case_id=req.case_id or "GENERAL",
        report_sent_status=req.report_sent_status,
    )
    return {"success": True, "revoked": revoked}


@router.get("/api/auth/me")
@router.get("/auth/me")
def me_endpoint(authorization: Optional[str] = Header(None)):
    """Verifies session token and returns active investigator identity."""
    session = validate_token(authorization)
    if not session:
        return JSONResponse(status_code=401, content={"success": False, "error": "Unauthorized session."})
    return {"success": True, "session": session}


# ─── 2. Security Analyst & AI Chat Endpoints ───────────────────────────────

@router.get("/api/security/analyst/status")
@router.get("/security/analyst/status")
def analyst_status_endpoint():
    """Returns Tier-2/Tier-3 human security analyst presence status."""
    return {"success": True, **get_analyst_status()}


@router.post("/api/security/analyst/toggle")
def analyst_toggle_endpoint(req: AnalystToggleRequest):
    """Allows toggling analyst status (ONLINE / OFFLINE / BUSY) for demonstration."""
    try:
        updated = set_analyst_status(req.status)
        return {"success": True, **updated}
    except ValueError as e:
        return JSONResponse(status_code=400, content={"success": False, "error": str(e)})


@router.post("/api/security/service/toggle")
def service_toggle_endpoint(req: ServiceToggleRequest):
    """Toggles simulated reachability of the centralized security reporting endpoint."""
    state = report_queue.set_service_reachable(req.reachable)
    return {"success": True, "service_reachable": state}


@router.post("/api/security/chat")
@router.post("/security/chat")
def security_chat_endpoint(
    req: ChatMessageRequest,
    authorization: Optional[str] = Header(None),
):
    """
    Unified chat endpoint:
    - Routes to Human Security Analyst if ONLINE.
    - If analyst is OFFLINE or mode=='ai', routes to AI Forensic Assistant provider.
    """
    session = validate_token(authorization)
    user = session["username"] if session else "INVESTIGATOR"
    analyst_stat = get_analyst_status()["status"]

    target_mode = req.mode or "auto"
    use_ai = (target_mode == "ai") or (target_mode == "auto" and analyst_stat == "OFFLINE")

    if use_ai:
        # Route through AI Provider Abstraction (strictly no Groq)
        result = query_ai_assistant(
            query=req.message,
            user=user,
            case_id=req.case_id or "LAB-2026-001",
            context=req.context or {},
        )
        return {"success": True, **result}
    else:
        # Route through Human Analyst Channel
        result = analyst_manager.process_message(
            message=req.message,
            user=user,
            case_id=req.case_id or "LAB-2026-001",
            incident_id=req.incident_id,
        )
        return {"success": True, **result}


# ─── 3. Critical Incident Alert Endpoint ───────────────────────────────────

@router.get("/api/security/incident/current")
@router.get("/security/incident/current")
def current_incident_endpoint(
    case_id: str = "LAB-2026-001",
    target: str = "LAB-PC",
    authorization: Optional[str] = Header(None),
):
    """Evaluates active forensic heuristics and returns current incident triage status."""
    session = validate_token(authorization)
    user = session["username"] if session else "INVESTIGATOR"

    incident = get_current_incident(
        case_id=case_id,
        target=target,
        user=user,
        record_audit=True,
    )
    return {"success": True, "incident": incident}


# ─── 4. Forensic Report Generation & Secure Delivery Queue ─────────────────

@router.post("/api/reports/generate")
@router.post("/reports/generate")
def generate_report_alias_endpoint(
    req: ReportGenerateRequest,
    authorization: Optional[str] = Header(None),
):
    """Generates structured forensic investigation report using ForensicReportBuilder."""
    from backend.app.reporting import ForensicReportBuilder
    from backend.app.analysis.correlator import correlate_evidence
    from backend.app.analysis.timeline import build_forensic_timeline
    from backend.app.analysis.rules import evaluate_forensic_rules
    from backend.app.evidence import _default_vault

    session = validate_token(authorization)
    user = session["username"] if session else (req.examiner or "JOCKY Lead Forensic Examiner")

    try:
        evidence = req.evidence
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

        correlation = correlate_evidence(evidence)
        timeline = build_forensic_timeline(evidence)
        detections = evaluate_forensic_rules(evidence)
        vault_audit = _default_vault.verify_vault_integrity(case_id=req.case_id)

        builder = ForensicReportBuilder(
            case_id=req.case_id or "LAB-2026-001",
            target=req.target or "LAB-PC",
            examiner=user,
        )

        report_data = builder.build_report_data(
            collected_data=evidence,
            correlation=correlation,
            timeline=timeline,
            detections=detections,
            vault_audit=vault_audit,
        )

        fmt = (req.format or "HTML").upper()
        if fmt == "HTML":
            content = builder.generate_html(report_data)
        elif fmt in ("MD", "MARKDOWN"):
            content = builder.generate_markdown(report_data)
        else:
            content = builder.generate_json(report_data)

        record_audit_event(
            action="REPORT_GENERATED",
            user=user,
            case_id=req.case_id,
            result="SUCCESS",
            details={
                "format": fmt,
                "findings_count": len(detections),
                "vault_status": vault_audit.get("status", "VERIFIED"),
            },
        )

        return {
            "success": True,
            "format": fmt,
            "report_data": report_data,
            "content": content,
            "attestation": report_data.get("attestation"),
        }
    except Exception as exc:
        return JSONResponse(status_code=500, content={"success": False, "error": str(exc)})


@router.post("/api/security/report/send")
@router.post("/security/report/send")
def send_report_endpoint(
    req: ReportSendRequest,
    authorization: Optional[str] = Header(None),
):
    """
    Generates forensic report, validates creation, and attempts delivery to security service.
    Returns status: SENT if delivery succeeded, or QUEUED if service is unavailable.
    """
    session = validate_token(authorization)
    user = session["username"] if session else (req.examiner or "INVESTIGATOR")

    # Step 1: Generate report
    gen_req = ReportGenerateRequest(
        case_id=req.case_id,
        target=req.target,
        format=req.format,
        examiner=user,
        evidence=req.evidence,
    )
    gen_result = generate_report_alias_endpoint(gen_req, authorization)

    if isinstance(gen_result, JSONResponse):
        return gen_result

    report_data = gen_result.get("report_data", {})
    raw_content = gen_result.get("content", "")

    # Step 2: Enqueue and attempt delivery
    delivery_record = send_or_queue_report(
        case_id=req.case_id or "LAB-2026-001",
        format_type=req.format or "HTML",
        report_data=report_data,
        raw_content=raw_content,
        destination=req.destination or "SOC-INGESTION-SERVICE",
        user=user,
    )

    return {
        "success": True,
        "delivery": delivery_record,
        "attestation": report_data.get("attestation"),
    }


@router.get("/api/security/report/status/{report_id}")
@router.get("/security/report/status/{report_id}")
def report_status_endpoint(report_id: str):
    """Queries tracking status of a queued/sent report."""
    status_item = report_queue.get_report_status(report_id)
    if not status_item:
        raise HTTPException(status_code=404, detail=f"Report ID '{report_id}' not found in queue.")
    return {"success": True, "report": status_item}


@router.get("/api/security/report/queue")
@router.get("/security/report/queue")
def report_queue_list_endpoint():
    """Lists all queued, pending, and sent forensic reports."""
    items = report_queue.get_all_queued()
    return {
        "success": True,
        "total": len(items),
        "service_reachable": report_queue.is_service_reachable(),
        "queue": items,
    }


@router.post("/api/security/report/retry/{report_id}")
def report_retry_endpoint(
    report_id: str,
    authorization: Optional[str] = Header(None),
):
    """Manually retries delivery of a queued or failed forensic report."""
    session = validate_token(authorization)
    user = session["username"] if session else "INVESTIGATOR"

    retried = report_queue.retry_report(report_id, user=user)
    if not retried:
        raise HTTPException(status_code=404, detail=f"Report ID '{report_id}' not found.")
    return {"success": True, "report": retried}


# ─── 5. Audit Logging Endpoint ─────────────────────────────────────────────

@router.get("/api/security/audit")
@router.get("/security/audit")
def audit_events_endpoint(
    limit: int = 100,
    action: Optional[str] = None,
    case_id: Optional[str] = None,
):
    """Retrieves chronological security and investigative audit events."""
    events = get_audit_events(limit=limit, action=action, case_id=case_id)
    return {
        "success": True,
        "total": len(events),
        "events": events,
    }
