"""
JOCKY Endpoint Agent Subsystem

Provides backend data models, device pairing lifecycle, and secure REST communication
interfaces for remote authorized forensic endpoint collection.
"""

from .models import (
    AgentHeartbeatRequest,
    AgentHeartbeatResponse,
    AgentJob,
    AllowedCollector,
    CollectorOperation,
    DeviceRecord,
    DeviceStatus,
    EvidenceSubmission,
    PairingCodeGenerateRequest,
    PairingCodeGenerateResponse,
    PairingExchangeRequest,
    PairingExchangeResponse,
)
from .manager import (
    AgentManager,
    get_agent_manager,
    hash_device_token,
    verify_device_token_hash,
)

__all__ = [
    "AllowedCollector",
    "DeviceStatus",
    "CollectorOperation",
    "PairingCodeGenerateRequest",
    "PairingCodeGenerateResponse",
    "PairingExchangeRequest",
    "PairingExchangeResponse",
    "AgentHeartbeatRequest",
    "AgentHeartbeatResponse",
    "AgentJob",
    "EvidenceSubmission",
    "DeviceRecord",
    "AgentManager",
    "get_agent_manager",
    "hash_device_token",
    "verify_device_token_hash",
]
