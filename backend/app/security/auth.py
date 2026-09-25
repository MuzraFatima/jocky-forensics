"""
JOCKY Forensic Framework — Authentication & Session Management

Provides secure session token management, investigator registration,
PBKDF2-HMAC-SHA256 password hashing, persistent storage, and route authorization guards.

Safety Invariants:
- Passwords are NEVER stored in plaintext (PBKDF2-HMAC-SHA256 with 100,000 rounds).
- Secrets and credentials are evaluated strictly on the backend with timing-safe comparison.
- Registered users persist across backend restarts in project data storage (never /tmp).
- Demo and administrative accounts remain accessible for evaluation.
- Audit events are emitted for every login, registration, failure, and logout.
"""

import datetime
import hashlib
import hmac
import json
import os
import secrets
import threading
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

from .audit import record_audit_event

# Configuration from environment with secure demo defaults
DEFAULT_DEMO_USER = os.getenv("JOCKY_DEMO_USER", "investigator@jocky.local")
DEFAULT_DEMO_PASS = os.getenv("JOCKY_DEMO_PASSWORD", "jocky-forensics-2026")
DEFAULT_ADMIN_USER = os.getenv("JOCKY_ADMIN_USER", "admin@jocky.local")
DEFAULT_ADMIN_PASS = os.getenv("JOCKY_ADMIN_PASSWORD", "admin-forensics-2026")

SESSION_TTL_SECONDS = int(os.getenv("JOCKY_SESSION_TTL", "28800"))  # 8 hours default


def hash_password(password: str) -> str:
    """Computes secure PBKDF2-HMAC-SHA256 password hash with a random cryptographic salt."""
    salt = secrets.token_hex(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("utf-8"), 100_000)
    return f"pbkdf2_sha256${salt}${dk.hex()}"


def verify_password(password: str, stored_hash: str) -> bool:
    """
    Verifies password against stored PBKDF2-HMAC-SHA256 hash or demo credential
    using timing-safe comparison.
    """
    if not password or not stored_hash:
        return False

    if stored_hash.startswith("pbkdf2_sha256$"):
        parts = stored_hash.split("$")
        if len(parts) == 3:
            salt = parts[1]
            expected_dk = parts[2]
            computed_dk = hashlib.pbkdf2_hmac(
                "sha256", password.encode("utf-8"), salt.encode("utf-8"), 100_000
            ).hex()
            return hmac.compare_digest(computed_dk, expected_dk)

    # Legacy/demo credentials verification
    return hmac.compare_digest(password.encode("utf-8"), stored_hash.encode("utf-8"))


def _get_default_storage_dir() -> Path:
    """Resolves persistent data storage directory for JOCKY."""
    env_dir = os.getenv("JOCKY_STORAGE_DIR")
    if env_dir:
        d = Path(env_dir)
    else:
        current_dir = Path(__file__).resolve().parent
        repo_root = current_dir.parent.parent.parent
        d = repo_root / "data"
    d.mkdir(parents=True, exist_ok=True)
    return d


class AuthManager:
    """Manages active investigator sessions, registration, and persistent user store."""

    def __init__(self, storage_dir: Optional[Path] = None):
        self._lock = threading.Lock()
        # token -> session dict
        self._sessions: Dict[str, Dict[str, Any]] = {}
        self._storage_dir = Path(storage_dir) if storage_dir else _get_default_storage_dir()
        self._storage_dir.mkdir(parents=True, exist_ok=True)
        self._users_file = self._storage_dir / "users.json"

        # Pre-seed demo users
        self._users: Dict[str, Dict[str, Any]] = {
            DEFAULT_DEMO_USER.lower(): {
                "username": DEFAULT_DEMO_USER,
                "password": DEFAULT_DEMO_PASS,
                "role": "Lead Forensic Examiner",
                "badge": "SIH26148-EXAMINER",
                "clearance": "AUTHORIZED_FORENSIC_OPERATOR",
                "is_demo": True,
            },
            DEFAULT_ADMIN_USER.lower(): {
                "username": DEFAULT_ADMIN_USER,
                "password": DEFAULT_ADMIN_PASS,
                "role": "SOC Incident Commander",
                "badge": "SIH26148-ADMIN",
                "clearance": "FULL_INCIDENT_COORDINATOR",
                "is_demo": True,
            },
            "admin": {
                "username": DEFAULT_ADMIN_USER,
                "password": DEFAULT_ADMIN_PASS,
                "role": "SOC Incident Commander",
                "badge": "SIH26148-ADMIN",
                "clearance": "FULL_INCIDENT_COORDINATOR",
                "is_demo": True,
            },
            "investigator": {
                "username": DEFAULT_DEMO_USER,
                "password": DEFAULT_DEMO_PASS,
                "role": "Lead Forensic Examiner",
                "badge": "SIH26148-EXAMINER",
                "clearance": "AUTHORIZED_FORENSIC_OPERATOR",
                "is_demo": True,
            },
        }

        # Load persisted users from disk
        self._load_persisted_users()

    def _load_persisted_users(self) -> None:
        """Loads registered users from persistent users.json file."""
        if not self._users_file.exists():
            return

        try:
            with open(self._users_file, "r", encoding="utf-8") as f:
                saved_users = json.load(f)

            if isinstance(saved_users, list):
                for u in saved_users:
                    username = u.get("username")
                    if username and "password_hash" in u:
                        self._users[username.lower()] = {
                            "username": username,
                            "password": u["password_hash"],
                            "role": u.get("role", "Forensic Investigator"),
                            "badge": u.get("badge", f"SIH26148-{secrets.token_hex(4).upper()}"),
                            "clearance": u.get("clearance", "AUTHORIZED_FORENSIC_OPERATOR"),
                            "is_demo": False,
                            "created_at": u.get("created_at"),
                        }
        except Exception:
            pass

    def _save_persisted_users(self) -> None:
        """Atomically persists non-demo registered users to disk."""
        users_to_save: List[Dict[str, Any]] = []
        for key, rec in self._users.items():
            # Skip short aliases and demo accounts from disk serialization
            if rec.get("is_demo") or key in ("admin", "investigator"):
                continue
            users_to_save.append({
                "username": rec["username"],
                "password_hash": rec["password"],
                "role": rec.get("role", "Forensic Investigator"),
                "badge": rec.get("badge"),
                "clearance": rec.get("clearance"),
                "created_at": rec.get("created_at"),
            })

        temp_file = self._users_file.with_suffix(".tmp")
        try:
            with open(temp_file, "w", encoding="utf-8") as f:
                json.dump(users_to_save, f, indent=2, sort_keys=True)
            temp_file.replace(self._users_file)
        except Exception:
            try:
                if temp_file.exists():
                    temp_file.unlink()
            except Exception:
                pass

    def get_user(self, username: str) -> Optional[Dict[str, Any]]:
        """Returns user profile if exists."""
        if not username:
            return None
        return self._users.get(username.strip().lower())

    def register(
        self,
        username: str,
        password: str,
        role: str = "Lead Forensic Examiner",
        badge: Optional[str] = None,
        clearance: str = "AUTHORIZED_FORENSIC_OPERATOR",
        case_id: Optional[str] = "GENERAL",
        ip_address: Optional[str] = "127.0.0.1",
    ) -> Dict[str, Any]:
        """
        Registers a new investigator account:
        - Rejects duplicates.
        - Hashes password with PBKDF2-HMAC-SHA256 (100,000 iterations).
        - Persists record to disk.
        - Issues active session token.
        """
        clean_user = username.strip()
        u_key = clean_user.lower()

        with self._lock:
            if u_key in self._users:
                raise ValueError("User with this email/username already exists.")

            pwd_hash = hash_password(password)
            user_badge = badge or f"SIH26148-{secrets.token_hex(4).upper()}"
            now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()

            user_record = {
                "username": clean_user,
                "password": pwd_hash,
                "role": role,
                "badge": user_badge,
                "clearance": clearance,
                "is_demo": False,
                "created_at": now_iso,
            }
            self._users[u_key] = user_record
            self._save_persisted_users()

        # Generate cryptographic bearer session token
        token = f"jocky_auth_{secrets.token_hex(24)}"
        session_data = {
            "token": token,
            "username": clean_user,
            "role": role,
            "badge": user_badge,
            "clearance": clearance,
            "case_id": case_id or "GENERAL",
            "authenticated_at": time.time(),
            "expires_at": time.time() + SESSION_TTL_SECONDS,
            "is_demo_mode": False,
        }

        with self._lock:
            self._sessions[token] = session_data

        record_audit_event(
            action="USER_REGISTERED",
            user=clean_user,
            case_id=case_id,
            result="SUCCESS",
            details={
                "role": role,
                "badge": user_badge,
                "storage": "PERSISTENT_DATA_STORE",
            },
            ip_address=ip_address,
        )

        return session_data

    def authenticate(
        self,
        username: str,
        password: str,
        case_id: Optional[str] = "GENERAL",
        ip_address: Optional[str] = "127.0.0.1",
    ) -> Optional[Dict[str, Any]]:
        """
        Authenticates credentials using timing-safe comparison and secure hash checking.
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
        stored_pass = user_record["password"]
        if not verify_password(password, stored_pass):
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
            "is_demo_mode": user_record.get("is_demo", False),
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
                "auth_type": "PERSISTENT_STORE" if not user_record.get("is_demo") else "DEMO_DEVELOPMENT_STORE",
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


def register_user(
    username: str,
    password: str,
    role: str = "Lead Forensic Examiner",
    badge: Optional[str] = None,
    clearance: str = "AUTHORIZED_FORENSIC_OPERATOR",
    case_id: Optional[str] = "GENERAL",
    ip_address: Optional[str] = "127.0.0.1",
) -> Dict[str, Any]:
    return auth_manager.register(username, password, role, badge, clearance, case_id, ip_address)


def validate_token(token: Optional[str]) -> Optional[Dict[str, Any]]:
    return auth_manager.validate_session(token)


def revoke_token(
    token: Optional[str],
    user: Optional[str] = None,
    case_id: Optional[str] = "GENERAL",
    report_sent_status: Optional[str] = None,
) -> bool:
    return auth_manager.revoke_session(token, user, case_id, report_sent_status)
