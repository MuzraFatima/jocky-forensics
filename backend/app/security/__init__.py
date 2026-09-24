"""
JOCKY Forensic Framework — Security & Incident Response Subsystem

Provides audit logging, authentication, analyst availability management,
AI fallback abstraction, secure report queueing, and incident response workflow.
"""

from .audit import audit_logger, record_audit_event, get_audit_events
from .auth import auth_manager, authenticate_user, validate_token, revoke_token
from .analyst import analyst_manager, get_analyst_status, set_analyst_status
from .ai_provider import BaseAIProvider, get_ai_provider
from .report_queue import report_queue, send_or_queue_report
from .incident import get_current_incident
from .routes import router as security_router

__all__ = [
    "audit_logger",
    "record_audit_event",
    "get_audit_events",
    "auth_manager",
    "authenticate_user",
    "validate_token",
    "revoke_token",
    "analyst_manager",
    "get_analyst_status",
    "set_analyst_status",
    "BaseAIProvider",
    "get_ai_provider",
    "report_queue",
    "send_or_queue_report",
    "get_current_incident",
    "security_router",
]
