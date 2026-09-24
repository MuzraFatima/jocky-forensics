"""
JOCKY Forensic Framework — Security Analyst Availability Manager

Manages analyst presence states (ONLINE, OFFLINE, BUSY) and simulates
human analyst chat channels for demonstration/training environments.

Safety Invariants:
- Clearly identifies itself as "Demo Security Analyst" / "Analyst Simulation".
- Never claims an unverified human received or acknowledged critical reports.
- Records ANALYST_CONTACT audit events.
"""

import threading
import time
from typing import Any, Dict, List, Optional
from .audit import record_audit_event


class AnalystManager:
    """Manages simulated Tier-2/Tier-3 Human Security Analyst availability and channel."""

    def __init__(self):
        self._lock = threading.Lock()
        self._status = "ONLINE"  # ONLINE, OFFLINE, BUSY
        self._analyst_profile = {
            "name": "Sarah Connor, CISSP",
            "title": "Lead Incident Response Analyst",
            "tier": "Tier-3 Cyber Defense",
            "soc_center": "National Forensic Response Center (Simulation)",
            "callsign": "JOCKY-DEFENDER-01",
        }
        self._chat_history: List[Dict[str, Any]] = [
            {
                "id": "msg-001",
                "sender": "analyst",
                "sender_name": "Sarah Connor (Demo Analyst)",
                "timestamp": time.time() - 300,
                "text": "SOC Analyst standing by. I am monitoring your investigation session under authorized read-only protocol. How can I assist with triage?",
                "role": "analyst",
            }
        ]

    def get_status(self) -> Dict[str, Any]:
        """Returns current analyst status and profile metadata."""
        with self._lock:
            status = self._status

        return {
            "status": status,
            "is_simulation": True,
            "disclaimer": "Demo Security Analyst / Analyst Simulation Environment. No real external SOC connected.",
            "analyst_name": self._analyst_profile["name"] if status != "OFFLINE" else None,
            "analyst_title": self._analyst_profile["title"] if status != "OFFLINE" else None,
            "tier": self._analyst_profile["tier"],
            "callsign": self._analyst_profile["callsign"],
            "status_label": "Security Analyst Online" if status == "ONLINE" else (
                "Security Analyst Busy" if status == "BUSY" else "Security Analyst Unavailable"
            ),
        }

    def set_status(self, new_status: str) -> Dict[str, Any]:
        """Updates analyst status for demonstration or manual escalation testing."""
        clean_status = new_status.upper().strip()
        if clean_status not in ("ONLINE", "OFFLINE", "BUSY"):
            raise ValueError(f"Invalid analyst status '{new_status}'. Allowed: ONLINE, OFFLINE, BUSY.")

        with self._lock:
            self._status = clean_status

        return self.get_status()

    def process_message(
        self,
        message: str,
        user: str = "INVESTIGATOR",
        case_id: str = "GENERAL",
        incident_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Processes an incoming human analyst message.
        If analyst is ONLINE, responds with forensic analyst guidance.
        If OFFLINE, returns indicator so client falls back to AI assistant.
        """
        with self._lock:
            current_status = self._status

        if current_status == "OFFLINE":
            return {
                "success": False,
                "channel": "analyst",
                "status": "OFFLINE",
                "message": "Security analyst is currently unavailable.",
                "fallback_offered": "AI_FORENSIC_ASSISTANT",
            }

        # Human Analyst Online channel response
        record_audit_event(
            action="ANALYST_CONTACT",
            user=user,
            case_id=case_id,
            result="SUCCESS",
            details={
                "incident_id": incident_id,
                "query_length": len(message),
                "channel": "DEMO_ANALYST_SIMULATION",
            },
        )

        response_text = self._generate_analyst_response(message, case_id, incident_id)

        reply = {
            "id": f"msg-reply-{int(time.time() * 1000)}",
            "sender": "analyst",
            "sender_name": f"{self._analyst_profile['name']} (Demo Analyst)",
            "timestamp": time.time(),
            "text": response_text,
            "role": "analyst",
            "is_simulation": True,
            "case_id": case_id,
        }

        with self._lock:
            self._chat_history.append({
                "id": f"msg-user-{int(time.time() * 1000)}",
                "sender": "user",
                "sender_name": user,
                "timestamp": time.time(),
                "text": message,
                "role": "investigator",
            })
            self._chat_history.append(reply)

        return {
            "success": True,
            "channel": "analyst",
            "status": current_status,
            "reply": reply,
            "disclaimer": "Demo Security Analyst simulation response.",
        }

    def get_history(self) -> List[Dict[str, Any]]:
        with self._lock:
            return list(self._chat_history)

    def _generate_analyst_response(self, query: str, case_id: str, incident_id: Optional[str]) -> str:
        q_lower = query.lower()
        if "incident" in q_lower or "alert" in q_lower:
            return (
                f"Acknowledged potential incident report for Case '{case_id}'. "
                "Per JOCKY read-only protocol, ensure you preserve the Evidence Vault artifacts. "
                "Do not terminate processes directly from the investigator workstation until evidence hashes are sealed. "
                "Would you like me to initiate a structured forensic report queue for senior command?"
            )
        elif "hash" in q_lower or "sha" in q_lower or "integrity" in q_lower:
            return (
                "Regarding cryptographic integrity: all JOCKY acquisitions calculate SHA-256 upon collection. "
                "Check the Evidence Vault ledger to confirm that no on-disk payloads have drifted."
            )
        elif "report" in q_lower or "send" in q_lower or "export" in q_lower:
            return (
                "You can generate a comprehensive JSON/HTML report from the Forensic Reports tab or click 'Generate & Send'. "
                "If the centralized SOC report endpoint is momentarily offline, JOCKY will securely queue the payload."
            )
        else:
            return (
                f"Analyst {self._analyst_profile['name']} here: reviewing telemetry for Case '{case_id}'. "
                "Observations recorded in session audit log. Please execute a timeline scan and correlate any suspicious sockets "
                "prior to closing your investigation session."
            )


# Global singleton
analyst_manager = AnalystManager()


def get_analyst_status() -> Dict[str, Any]:
    return analyst_manager.get_status()


def set_analyst_status(status: str) -> Dict[str, Any]:
    return analyst_manager.set_status(status)
