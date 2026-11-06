"""
Role-based access control for the forensic API (blueprint §3.4, §10).

Every request under /api/jocky/ and /api/forensics/ needs a valid session
token. What it may do depends on the account's role:

    viewer        read results, compile and validate scripts, verify evidence
    investigator  everything a viewer can, plus anything that collects from
                  the host or writes evidence (execute, collect, detect, seal,
                  live correlation, report generation)
    admin         everything, including the tamper-simulation demo endpoint

Job titles map onto those levels (ROLE_LEVELS). An unknown title is treated
as investigator, matching the default role given at registration.

Denied requests are written to the hash-chained audit log. Setting
JOCKY_AUTH_DISABLED=1 turns enforcement off; the legacy API tests use that,
and tests/test_rbac.py checks enforcement with it on.
"""

import os
import re
from typing import Optional, Tuple

from fastapi.responses import JSONResponse

from .audit import record_audit_event
from .auth import validate_token

VIEWER, INVESTIGATOR, ADMIN = 1, 2, 3
LEVEL_NAMES = {VIEWER: "viewer", INVESTIGATOR: "investigator", ADMIN: "admin"}

ROLE_LEVELS = {
    "digital evidence auditor": VIEWER,
    "auditor": VIEWER,
    "viewer": VIEWER,
    "lead forensic examiner": INVESTIGATOR,
    "incident responder": INVESTIGATOR,
    "forensic investigator": INVESTIGATOR,
    "investigator": INVESTIGATOR,
    "soc incident commander": ADMIN,
    "admin": ADMIN,
}

PROTECTED_PREFIXES = ("/api/jocky/", "/api/forensics/")

# (method, path regex, minimum level). First match wins; otherwise GET needs viewer
# and any other method needs investigator.
RULES = [
    ("POST", r"^/api/forensics/vault/simulate-tampering$", ADMIN),
    ("POST", r"^/api/jocky/(parse|compile|validate)$", VIEWER),
    ("POST", r"^/api/forensics/vault/verify$", VIEWER),
    ("GET", r"^/api/forensics/collect/", INVESTIGATOR),
    ("GET", r"^/api/forensics/(correlate|timeline|analysis|report/live)$", INVESTIGATOR),
]


def required_level(method: str, path: str) -> int:
    for rule_method, pattern, level in RULES:
        if method == rule_method and re.search(pattern, path):
            return level
    return VIEWER if method in ("GET", "HEAD") else INVESTIGATOR


def role_level(role: Optional[str]) -> int:
    return ROLE_LEVELS.get((role or "").strip().lower(), INVESTIGATOR)


def auth_enforced() -> bool:
    return os.getenv("JOCKY_AUTH_DISABLED", "").strip().lower() not in ("1", "true", "yes")


def check_request(method: str, path: str, token: Optional[str]) -> Tuple[Optional[int], Optional[dict]]:
    """Return (status, body) to reject the request, or (None, session) to let it through."""
    session = validate_token(token) if token else None
    if not session:
        return 401, {
            "success": False,
            "error_type": "AuthenticationRequired",
            "message": "Sign in first: this endpoint needs a valid session token.",
        }
    needed = required_level(method, path)
    have = role_level(session.get("role"))
    if have < needed:
        record_audit_event(
            "ACCESS_DENIED",
            user=session.get("username"),
            result="DENIED",
            details={"method": method, "path": path, "role": session.get("role"),
                     "required": LEVEL_NAMES[needed]},
        )
        return 403, {
            "success": False,
            "error_type": "InsufficientRole",
            "message": f"{session.get('role')} accounts cannot do this; it needs the {LEVEL_NAMES[needed]} level.",
            "required": LEVEL_NAMES[needed],
            "role": session.get("role"),
        }
    return None, session


class RBACMiddleware:
    """
    Plain ASGI middleware (not BaseHTTPMiddleware): it only inspects the
    request line and headers, answers 401/403 itself, and otherwise hands the
    untouched request to the app. No extra task or response buffering, so a
    browser aborting a request mid-stream cannot wedge the server.
    """

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        method = scope.get("method", "GET")
        path = scope.get("path", "")
        if method == "OPTIONS" or not path.startswith(PROTECTED_PREFIXES) or not auth_enforced():
            return await self.app(scope, receive, send)
        headers = {k.decode("latin-1").lower(): v.decode("latin-1") for k, v in scope.get("headers", [])}
        auth = headers.get("authorization", "")
        token = auth[7:].strip() if auth.lower().startswith("bearer ") else (auth.strip() or None)
        status, body = check_request(method, path, token)
        if status:
            return await JSONResponse(status_code=status, content=body)(scope, receive, send)
        return await self.app(scope, receive, send)
