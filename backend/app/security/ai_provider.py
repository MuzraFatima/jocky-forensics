"""
JOCKY Forensic Framework — AI Forensic Provider Abstraction

Provides a modular interface for AI forensic advisory assistants when human
security analysts are offline.

Safety Invariants:
- NOT connected to Groq (explicit architectural constraint).
- In the absence of an external provider, provides strict, deterministic, safe fallback responses.
- Receives controlled, sanitized investigation context rather than direct host/shell access.
- Does NOT fabricate forensic findings or modify evidence artifacts.
- Emits AI_ASSISTANCE_USED audit events.
"""

from abc import ABC, abstractmethod
import os
import time
from typing import Any, Dict, Optional
from .audit import record_audit_event


class BaseAIProvider(ABC):
    """Abstract Base Class for AI Forensic Assistant Providers."""

    @abstractmethod
    def get_provider_name(self) -> str:
        """Returns the identifier of the AI provider."""
        pass

    @abstractmethod
    def is_available(self) -> bool:
        """Returns True if the provider is configured and reachable."""
        pass

    @abstractmethod
    def generate_advisory(
        self,
        query: str,
        context: Optional[Dict[str, Any]] = None,
    ) -> str:
        """Generates an advisory response using controlled context."""
        pass


class SafeFallbackAIProvider(BaseAIProvider):
    """
    Standard compliant fallback provider when no external LLM is configured.
    Guarantees no hallucination and provides deterministic incident guidance.
    """

    def get_provider_name(self) -> str:
        return "Safe-Deterministic-Fallback"

    def is_available(self) -> bool:
        # Fallback is always available as safety mechanism
        return True

    def generate_advisory(
        self,
        query: str,
        context: Optional[Dict[str, Any]] = None,
    ) -> str:
        # Check if an external provider key was provided in environment (e.g. OpenAI / Anthropic)
        # Note: Groq is deliberately forbidden per prompt instructions.
        external_configured = bool(os.getenv("JOCKY_AI_API_KEY"))

        if not external_configured:
            # Deterministic, safe response per specification
            return (
                "AI assistance is currently unavailable. "
                "Please use the forensic report and contact the appropriate security team."
            )

        # If configured later, context is constrained:
        case_id = (context or {}).get("case_id", "LIVE-INVESTIGATION")
        return (
            f"[AI Forensic Assistant - Case {case_id}]\n"
            "Forensic Context Summary: The JOCKY analysis engine operates under strict read-only constraints. "
            "Please review the timeline entries and evidence ledger for anomalies."
        )


class DemoForensicAdvisor(BaseAIProvider):
    """
    Read-only contextual advisor for demonstration environments.
    Explains JOCKY indicators without inventing evidence or executing commands.
    """

    def get_provider_name(self) -> str:
        return "JOCKY-Contextual-Advisor (Demo Simulation)"

    def is_available(self) -> bool:
        return True

    def generate_advisory(
        self,
        query: str,
        context: Optional[Dict[str, Any]] = None,
    ) -> str:
        ctx = context or {}
        case_id = ctx.get("case_id", "LAB-2026-001")
        detections_count = ctx.get("detections_count", 0)

        q_lower = query.lower()
        if "what" in q_lower and ("rule" in q_lower or "heuristic" in q_lower or "detection" in q_lower):
            return (
                f"[AI Forensic Assistant]\n"
                f"For Case '{case_id}', JOCKY evaluates 5 baseline heuristic detection rules:\n"
                "• RULE-001: Execution from Temporary Directories (HIGH severity)\n"
                "• RULE-002: Suspicious Parent-Child Process Spawning (HIGH severity)\n"
                "• RULE-003: Anomalous Outbound Network Socket (MEDIUM severity)\n"
                "• RULE-004: Unmapped Binary Execution (MEDIUM severity)\n"
                "• RULE-005: Suspicious Persistence Autorun Entry (MEDIUM severity)\n"
                "These indicators highlight anomalies for human analyst verification and do not prove definitive compromise."
            )
        elif "integrity" in q_lower or "sha" in q_lower:
            return (
                f"[AI Forensic Assistant]\n"
                "All forensic artifacts sealed in the Evidence Vault calculate SHA-256 digests immediately upon acquisition. "
                "The immutable ledger prevents retrospective tampering. Check the Evidence Vault tab to view cryptographic attestation."
            )
        else:
            return (
                f"[AI Forensic Assistant — Case '{case_id}']\n"
                f"Controlled Context: {detections_count} active heuristic indicators detected.\n"
                "Guidance: Review the Timeline to observe chronological execution sequences. "
                "Before closing your session, use 'Generate & Send Report' to transmit findings to the security team."
            )


def get_ai_provider() -> BaseAIProvider:
    """Factory function returning the configured AI provider."""
    provider_mode = os.getenv("JOCKY_AI_PROVIDER_MODE", "demo").lower()
    if provider_mode == "fallback_strict":
        return SafeFallbackAIProvider()
    # Default to contextual demo advisor for SIH prototype
    return DemoForensicAdvisor()


def query_ai_assistant(
    query: str,
    user: str = "INVESTIGATOR",
    case_id: str = "GENERAL",
    context: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Invokes the AI provider with controlled forensic context and records an audit event.
    """
    provider = get_ai_provider()
    advisory = provider.generate_advisory(query=query, context=context)

    record_audit_event(
        action="AI_ASSISTANCE_USED",
        user=user,
        case_id=case_id,
        result="SUCCESS",
        details={
            "provider": provider.get_provider_name(),
            "query_length": len(query),
            "context_keys": list((context or {}).keys()),
        },
    )

    return {
        "success": True,
        "channel": "ai",
        "provider": provider.get_provider_name(),
        "timestamp": time.time(),
        "reply": advisory,
        "is_simulation": True,
    }
