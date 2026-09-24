"""
JOCKY Forensic Framework — Authentication & Session Management

Provides secure session token management, investigator authentication,
and route authorization guards.

Safety Invariants:
- Secrets are evaluated strictly on the backend.
- Demo/Development authentication is clearly declared in metadata.
- Audit events are emitted for every login, failure, and logout.
"""

import hmac
import os
import secrets
import threading
import time
from typing import Any, Dict, Optional

from .audit import record_audit_event

# Configuration from environment with secure demo defaults
DEFAULT_DEMO_USER = os.getenv("JOCKY_DEMO_USER", "investigator@jocky.local")
DEFAULT_DEMO_PASS = os.getenv("JOCKY_DEMO_PASSWORD", "jocky-forensics-2026")
DEFAULT_ADMIN_USER = os.getenv("JOCKY_ADMIN_USER", "admin@jocky.local")
DEFAULT_ADMIN_PASS = os.getenv("JOCKY_ADMIN_PASSWORD", "admin-forensics-2026")

SESSION_TTL_SECONDS = int(os.getenv("JOCKY_SESSION_TTL", "28800"))  # 8 hours default


class AuthManager:
    """Manages active investigator sessions and authentication checks."""

    def __init__(self):
        self._lock = threading.Lock()
        # token -> session dict
        self._sessions: Dict[str, Dict[str, Any]] = {}
        # Pre-seed demo users
        self._users = {
            DEFAULT_DEMO_USER.lower(): {
                "username": DEFAULT_DEMO_USER,
                "password": DEFAULT_DEMO_PASS,
                "role": "Lead Forensic Examiner",
                "badge": "SIH26148-EXAMINER",
                "clearance": "AUTHORIZED_FORENSIC_OPERATOR",
            },
            DEFAULT_ADMIN_USER.lower(): {
                "username": DEFAULT_ADMIN_USER,
                "password": DEFAULT_ADMIN_PASS,
                "role": "SOC Incident Commander",
                "badge": "SIH26148-ADMIN",
                "clearance": "FULL_INCIDENT_COORDINATOR",
            },
            # Also allow short username "admin" / "investigator" for convenience
            "admin": {
                "username": DEFAULT_ADMIN_USER,
                "password": DEFAULT_ADMIN_PASS,
                "role": "SOC Incident Commander",
                "badge": "SIH26148-ADMIN",
                "clearance": "FULL_INCIDENT_COORDINATOR",
            },
            "investigator": {
                "username": DEFAULT_DEMO_USER,
                "password": DEFAULT_DEMO_PASS,
                "role": "Lead Forensic Examiner",
                "badge": "SIH26148-EXAMINER",
                "clearance": "AUTHORIZED_FORENSIC_OPERATOR",
            },
        }

    def authenticate(
        self,
        username: str,
        password: str,
        case_id: Optional[str] = "GENERAL",
        ip_address: Optional[str] = "127.0.0.1",
    ) -> Optional[Dict[str, Any]]:
        """
        Authenticates credentials using timing-safe comparison.
        Returns session payload on success, None on failure.
        """
        if not username or not password:
            record_audit_event(
                action="FAILED_LOGIN",
                user=username or "EMPTY",
                case_id=case_id,
                result="FAILED",
                details={"reason": "Missing username or password"},
                ip_address=ip_address,
            )
            return None

        u_clean = username.strip().lower()
        user_record = self._users.get(u_clean)

        if not user_record:
            record_audit_event(
                action="FAILED_LOGIN",
                user=username,
                case_id=case_id,
                result="FAILED",
                details={"reason": "Unknown investigator identifier"},
                ip_address=ip_address,
            )
            return None

        # Timing-safe password verification
        expected_pass = user_record["password"]
        if not hmac.compare_digest(password.encode("utf-8"), expected_pass.encode("utf-8")):
            record_audit_event(
                action="FAILED_LOGIN",
                user=username,
                case_id=case_id,
                result="FAILED",
                details={"reason": "Invalid credentials provided"},
                ip_address=ip_address,
            )
            return None

        # Generate cryptographic bearer session token
        token = f"jocky_auth_{secrets.token_hex(24)}"
        session_data = {
            "token": token,
            "username": user_record["username"],
            "role": user_record["role"],
            "badge": user_record["badge"],
            "clearance": user_record["clearance"],
            "case_id": case_id or "GENERAL",
            "authenticated_at": time.time(),
            "expires_at": time.time() + SESSION_TTL_SECONDS,
            "is_demo_mode": True,
        }

        with self._lock:
            self._sessions[token] = session_data

        record_audit_event(
            action="LOGIN",
            user=user_record["username"],
            case_id=case_id,
            result="SUCCESS",
            details={
                "role": user_record["role"],
                "badge": user_record["badge"],
                "auth_type": "DEMO_DEVELOPMENT_STORE",
            },
            ip_address=ip_address,
        )

        return session_data

    def validate_session(self, token: Optional[str]) -> Optional[Dict[str, Any]]:
        """Validates bearer token against active unexpired sessions."""
        if not token or not isinstance(token, str):
            return None

        clean_token = token.strip()
        if clean_token.startswith("Bearer "):
            clean_token = clean_token[7:].strip()

        with self._lock:
            session = self._sessions.get(clean_token)
            if not session:
                return None

            if time.time() > session["expires_at"]:
                del self._sessions[clean_token]
                return None

            return session

    def revoke_session(
        self,
        token: Optional[str],
        user: Optional[str] = None,
        case_id: Optional[str] = "GENERAL",
        report_sent_status: Optional[str] = None,
    ) -> bool:
        """Revokes an active session upon logout."""
        if not token:
            return False

        clean_token = token.strip()
        if clean_token.startswith("Bearer "):
            clean_token = clean_token[7:].strip()

        with self._lock:
            session = self._sessions.pop(clean_token, None)

        user_name = user or (session.get("username") if session else "INVESTIGATOR")
        record_audit_event(
            action="LOGOUT",
            user=user_name,
            case_id=case_id,
            result="SUCCESS",
            details={
                "report_sent_status": report_sent_status or "LOGOUT_WITHOUT_SENDING",
            },
        )
        return True


# Global singleton
auth_manager = AuthManager()


def authenticate_user(
    username: str,
    password: str,
    case_id: Optional[str] = "GENERAL",
    ip_address: Optional[str] = "127.0.0.1",
) -> Optional[Dict[str, Any]]:
    return auth_manager.authenticate(username, password, case_id, ip_address)


def validate_token(token: Optional[str]) -> Optional[Dict[str, Any]]:
    return auth_manager.validate_session(token)


def revoke_token(
    token: Optional[str],
    user: Optional[str] = None,
    case_id: Optional[str] = "GENERAL",
    report_sent_status: Optional[str] = None,
) -> bool:
    return auth_manager.revoke_session(token, user, case_id, report_sent_status)
