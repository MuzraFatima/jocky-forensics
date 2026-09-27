"""
JOCKY Endpoint Agent — FastAPI REST API Routes

Provides endpoints for:
1. POST /api/agents/pairing/generate - Investigator generates 10-min pairing code
2. POST /api/agents/pair             - Agent claims code and enrolls
3. POST /api/agents/heartbeat        - Periodic health & presence beacon
4. GET  /api/agents/jobs             - Device polls for assigned forensic jobs
5. POST /api/agents/result           - Agent submits acquired telemetry with SHA-256 validation
6. GET  /api/agents/devices          - Investigator lists owned endpoints with online status
7. POST /api/agents/devices/{id}/revoke - Investigator revokes device access immediately

Safety Invariants:
- All investigator actions require valid session tokens via existing auth (validate_token).
- All agent actions require Bearer device token authentication (verify_device_token).
- Server recomputes SHA-256 on evidence payloads; rejects mismatches with TRANSMISSION_TAMPERED (HTTP 400).
- No bearer tokens or token hashes are ever logged, returned in device listings, or put in query params.
- No arbitrary commands or write actions are exposed or supported.
"""

import datetime
from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Depends, Header, HTTPException, Request, Response, status
from fastapi.responses import JSONResponse

from backend.app.evidence.hashing import compute_sha256
from backend.app.security.auth import validate_token
from .manager import AgentManager, get_agent_manager
from .models import (
    AgentHeartbeatRequest,
    AgentHeartbeatResponse,
    DeviceRecord,
    DeviceStatus,
    EvidenceSubmission,
    PairingCodeGenerateRequest,
    PairingCodeGenerateResponse,
    PairingExchangeRequest,
    PairingExchangeResponse,
)

router = APIRouter(prefix="/api/agents", tags=["Endpoint Agents"])

# Threshold for considering a device actively online (heartbeat within 90 seconds)
ONLINE_THRESHOLD_SECONDS = 90


# ─── Authentication Dependencies ──────────────────────────────────────────────

def get_current_investigator(authorization: Optional[str] = Header(None)) -> Dict[str, Any]:
    """
    Validates investigator session using the project's existing authentication mechanism.
    Rejects unauthenticated or expired requests with HTTP 401.
    """
    if not authorization:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authorization header missing. Investigator authentication required.",
        )

    session = validate_token(authorization)
    if not session:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired investigator session.",
        )
    return session


def get_authenticated_device(
    authorization: Optional[str] = Header(None),
    x_device_id: Optional[str] = Header(None, alias="X-Device-Id"),
    agent_manager: AgentManager = Depends(get_agent_manager),
) -> DeviceRecord:
    """
    Validates endpoint agent device token using timing-safe comparison against stored salted hash.
    Rejects missing, invalid, or revoked devices with HTTP 401.
    """
    if not authorization:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authorization header missing. Agent device token required.",
        )

    clean_token = authorization.strip()
    if clean_token.startswith("Bearer "):
        clean_token = clean_token[7:].strip()

    if not clean_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Malformed Authorization header.",
        )

    # 1. If X-Device-Id is supplied, verify directly
    if x_device_id:
        dev = agent_manager.verify_device_token(x_device_id.strip(), clean_token)
        if not dev:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Device authentication failed or device has been revoked.",
            )
        return dev

    # 2. Fallback: Search registered active devices matching the bearer token
    # (Enables clients that only send Authorization: Bearer <token>)
    active_devices = [d for d in agent_manager.list_devices() if d.status == DeviceStatus.ACTIVE and not d.is_revoked]
    for candidate in active_devices:
        dev = agent_manager.verify_device_token(candidate.device_id, clean_token)
        if dev:
            return dev

    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Device authentication failed or device has been revoked.",
    )


# ─── 1. Pairing Code Generation ───────────────────────────────────────────────

@router.post(
    "/pairing/generate",
    response_model=PairingCodeGenerateResponse,
    summary="Generate single-use pairing code for an endpoint",
)
def generate_pairing_code_endpoint(
    request: Optional[PairingCodeGenerateRequest] = None,
    session: Dict[str, Any] = Depends(get_current_investigator),
    agent_manager: AgentManager = Depends(get_agent_manager),
):
    """
    Authenticated investigator generates a short-lived 8-character pairing code
    with a 10-minute expiry bound to their user account.
    """
    user_id = session.get("username")
    if not user_id:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Session missing username.")

    req = request or PairingCodeGenerateRequest()
    try:
        response = agent_manager.generate_pairing_code(
            user_id=user_id,
            device_name=req.device_name,
            case_id=req.case_id,
        )
        return response
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


# ─── 2. Pairing Exchange (Enrollment) ─────────────────────────────────────────

@router.post(
    "/pair",
    response_model=PairingExchangeResponse,
    summary="Enroll device and exchange pairing code for device token",
)
def pair_device_endpoint(
    request: PairingExchangeRequest,
    agent_manager: AgentManager = Depends(get_agent_manager),
):
    """
    Endpoint agent exchanges a valid pairing code to enroll.
    Returns the raw device_token exactly once.
    """
    try:
        response = agent_manager.exchange_pairing_code(request)
        return response
    except ValueError as e:
        err_msg = str(e)
        status_code = status.HTTP_400_BAD_REQUEST
        if "expired" in err_msg.lower() or "invalid" in err_msg.lower():
            status_code = status.HTTP_400_BAD_REQUEST
        return JSONResponse(
            status_code=status_code,
            content={
                "success": False,
                "error": err_msg,
                "error_type": "PairingFailed",
            },
        )


# ─── 3. Heartbeat ─────────────────────────────────────────────────────────────

@router.post(
    "/heartbeat",
    response_model=AgentHeartbeatResponse,
    summary="Endpoint presence and status beacon",
)
def heartbeat_endpoint(
    request: AgentHeartbeatRequest,
    device: DeviceRecord = Depends(get_authenticated_device),
    agent_manager: AgentManager = Depends(get_agent_manager),
):
    """
    Authenticated device sends periodic heartbeats to update its presence and telemetry.
    """
    # Enforce device identity parity
    if request.device_id != device.device_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Payload device_id does not match authenticated device identity.",
        )

    agent_manager.update_heartbeat(
        device_id=device.device_id,
        hostname=request.hostname,
        platform=request.platform,
        agent_version=request.agent_version,
    )

    pending_count = agent_manager.get_pending_jobs_count(device.device_id)
    return AgentHeartbeatResponse(
        acknowledged=True,
        server_time=datetime.datetime.now(datetime.timezone.utc),
        pending_jobs_count=pending_count,
    )


# ─── 4. Job Polling ───────────────────────────────────────────────────────────

@router.get(
    "/jobs",
    summary="Poll for pending forensic collection jobs assigned to this device",
)
def poll_jobs_endpoint(
    device: DeviceRecord = Depends(get_authenticated_device),
    agent_manager: AgentManager = Depends(get_agent_manager),
):
    """
    Authenticated agent polls for the oldest pending job assigned specifically to its device_id.
    Returns {"job": null} when no jobs are queued.
    """
    job = agent_manager.get_pending_job(device.device_id)
    if not job:
        return {"success": True, "job": None}

    return {"success": True, "job": job.model_dump(mode="json")}


# ─── 5. Evidence Result Submission ────────────────────────────────────────────

@router.post(
    "/result",
    summary="Submit acquired forensic telemetry with SHA-256 validation",
)
def submit_evidence_result_endpoint(
    submission: EvidenceSubmission,
    device: DeviceRecord = Depends(get_authenticated_device),
    agent_manager: AgentManager = Depends(get_agent_manager),
):
    """
    Authenticated agent uploads acquired telemetry.
    The server recomputes the SHA-256 over the payload and rejects any mismatch with TRANSMISSION_TAMPERED (HTTP 400).
    """
    # 1. Device identity scope check
    if submission.device_id != device.device_id:
        return JSONResponse(
            status_code=status.HTTP_403_FORBIDDEN,
            content={
                "success": False,
                "error": "Submission device_id does not match authenticated device.",
                "error_type": "DeviceMismatch",
            },
        )

    # 2. Server-side SHA-256 recomputation over exact payload
    server_sha256 = compute_sha256(submission.payload)

    # 3. Cryptographic integrity check
    if server_sha256.lower() != submission.agent_sha256.lower():
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={
                "success": False,
                "error": "Evidence payload SHA-256 mismatch: transmission tampering or corruption detected.",
                "error_type": "TRANSMISSION_TAMPERED",
                "server_sha256": server_sha256,
                "agent_sha256": submission.agent_sha256,
            },
        )

    # 4. Store in temporary in-memory result registry (NOT central vault yet)
    agent_manager.add_result(submission.execution_id, submission)

    return {
        "success": True,
        "message": "Evidence payload received and cryptographically verified.",
        "execution_id": submission.execution_id,
        "collector": submission.collector.value,
        "sha256": server_sha256,
    }


# ─── 6. Device List ───────────────────────────────────────────────────────────

@router.get(
    "/devices",
    summary="List all endpoint devices belonging to the authenticated investigator",
)
def list_devices_endpoint(
    session: Dict[str, Any] = Depends(get_current_investigator),
    agent_manager: AgentManager = Depends(get_agent_manager),
):
    """
    Lists enrolled devices owned by the authenticated investigator.
    Never exposes tokens or hashes.
    """
    user_id = session.get("username")
    devices = agent_manager.list_devices(user_id=user_id)

    now = datetime.datetime.now(datetime.timezone.utc)
    safe_devices = []

    for dev in devices:
        # Determine online status based on last_seen
        is_online = False
        if dev.last_seen and dev.status == DeviceStatus.ACTIVE and not dev.is_revoked:
            last_seen_dt = dev.last_seen
            if last_seen_dt.tzinfo is None:
                last_seen_dt = last_seen_dt.replace(tzinfo=datetime.timezone.utc)
            delta = (now - last_seen_dt).total_seconds()
            if delta <= ONLINE_THRESHOLD_SECONDS:
                is_online = True

        safe_devices.append({
            "device_id": dev.device_id,
            "user_id": dev.user_id,
            "hostname": dev.hostname,
            "platform": dev.platform,
            "agent_version": dev.agent_version,
            "created_at": dev.created_at.isoformat() if dev.created_at else None,
            "last_seen": dev.last_seen.isoformat() if dev.last_seen else None,
            "status": dev.status.value,
            "is_online": is_online,
            "is_revoked": dev.is_revoked,
            "revoked_at": dev.revoked_at.isoformat() if dev.revoked_at else None,
        })

    return {"success": True, "devices": safe_devices}


# ─── 7. Device Revocation ─────────────────────────────────────────────────────

@router.post(
    "/devices/{device_id}/revoke",
    summary="Revoke access for an endpoint device immediately",
)
def revoke_device_endpoint(
    device_id: str,
    session: Dict[str, Any] = Depends(get_current_investigator),
    agent_manager: AgentManager = Depends(get_agent_manager),
):
    """
    Investigator immediately revokes access for their endpoint device.
    Device token is invalidated and pending jobs are cleared.
    """
    user_id = session.get("username")
    dev = agent_manager.get_device(device_id)

    if not dev:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Device {device_id} not found.",
        )

    if dev.user_id != user_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You are not authorized to revoke a device belonging to another investigator.",
        )

    revoked = agent_manager.revoke_device(device_id, user_id=user_id)
    if not revoked:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Failed to revoke device {device_id}.",
        )

    return {
        "success": True,
        "message": f"Device {device_id} has been revoked immediately.",
        "device_id": device_id,
    }
