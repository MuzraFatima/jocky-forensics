"""
JOCKY Endpoint Forensic Agent Package

Enables an authorized investigator to connect their local device/endpoint to the central
JOCKY web dashboard, receive declarative forensic collection jobs, execute read-only
forensic collectors locally, compute cryptographic SHA-256 hashes, and stream verified
telemetry back to the backend.

Components:
- config: Configuration persistence and credential store (.jocky-agent.json)
- adapter: Zero-duplication adapter calling backend.app.collectors.dispatcher
- runner: Allowlist-enforced execution engine and canonical SHA-256 calculator
- client: HTTPS REST daemon communicating with the central JOCKY backend
"""

__version__ = "1.0.0"

from .config import AgentConfig
from .adapter import CollectorAdapter
from .runner import AgentRunner
from .client import EndpointAgentClient

__all__ = [
    "__version__",
    "AgentConfig",
    "CollectorAdapter",
    "AgentRunner",
    "EndpointAgentClient",
]
