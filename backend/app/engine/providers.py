"""
JOCKY Forensic Execution Engine — Collector Provider Abstraction

Defines the CollectorProvider interface and implementations:
1. LocalCollectorProvider: Default provider invoking local read-only collectors on the current host.
2. EndpointEvidenceProvider: Provider consuming pre-collected, verified evidence from an authorized endpoint.

Safety Invariants:
- LocalCollectorProvider uses the existing, authorized read-only collectors.
- EndpointEvidenceProvider NEVER accesses the local machine, executes shell commands, or runs scripts.
- EndpointEvidenceProvider validates collector allowlist and device/execution scoping.
- Evidence is treated strictly as structured data, never as executable code.
"""

from abc import ABC, abstractmethod
import datetime
from typing import Any, Dict, List, Optional, Set, Union

from backend.app.collectors.files import collect_files_info
from backend.app.collectors.network import collect_network_info
from backend.app.collectors.processes import collect_process_info
from backend.app.collectors.system import collect_system_info
from backend.app.collectors.users import collect_users_info
from backend.app.collectors.windows_metadata import (
    collect_registry_info,
    collect_windows_metadata,
)

# Strict allowlist of permissible collector sources
ALLOWED_COLLECTORS: Set[str] = {
    "system",
    "processes",
    "network",
    "files",
    "users",
    "registry",
    "windows_metadata",
}


class CollectorProvider(ABC):
    """
    Abstract interface for acquiring forensic evidence payloads.
    Decouples evidence retrieval from local vs remote endpoint execution.
    """

    @abstractmethod
    def collect_system(self, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Acquires system-level forensic telemetry."""
        pass

    @abstractmethod
    def collect_processes(self, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Acquires running processes telemetry."""
        pass

    @abstractmethod
    def collect_network(self, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Acquires network sockets and active connections telemetry."""
        pass

    @abstractmethod
    def collect_files(
        self, target_path: Optional[str] = None, params: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Acquires target file and directory metadata."""
        pass

    @abstractmethod
    def collect_users(self, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Acquires system user accounts and session telemetry."""
        pass

    @abstractmethod
    def collect_registry(self, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Acquires registry or persistence autorun telemetry."""
        pass

    @abstractmethod
    def collect_windows_metadata(self, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Acquires Windows-specific forensic persistence metadata."""
        pass

    def get_evidence(
        self, collector_name: str, params: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Convenience dispatcher to retrieve evidence by collector name."""
        clean_name = collector_name.strip().lower()
        if clean_name not in ALLOWED_COLLECTORS:
            raise ValueError(f"Unsupported collector type: '{collector_name}'")

        if clean_name == "system":
            return self.collect_system(params)
        elif clean_name == "processes":
            return self.collect_processes(params)
        elif clean_name == "network":
            return self.collect_network(params)
        elif clean_name == "files":
            target_path = params.get("target_path") if params else None
            return self.collect_files(target_path=target_path, params=params)
        elif clean_name == "users":
            return self.collect_users(params)
        elif clean_name == "registry":
            return self.collect_registry(params)
        elif clean_name == "windows_metadata":
            return self.collect_windows_metadata(params)
        else:
            raise ValueError(f"Unhandled collector type: '{collector_name}'")


# ─── 1. Local Collector Provider ──────────────────────────────────────────────

class LocalCollectorProvider(CollectorProvider):
    """
    Default provider that executes existing read-only collectors directly
    on the local host environment.
    """

    def collect_system(self, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        return collect_system_info()

    def collect_processes(self, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        return collect_process_info()

    def collect_network(self, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        return collect_network_info()

    def collect_files(
        self, target_path: Optional[str] = None, params: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        path = target_path or (params.get("target_path") if params else None)
        return collect_files_info(target_path=path)

    def collect_users(self, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        return collect_users_info()

    def collect_registry(self, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        return collect_registry_info()

    def collect_windows_metadata(self, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        return collect_windows_metadata()


# ─── 2. Endpoint Evidence Provider ────────────────────────────────────────────

class EndpointEvidenceProvider(CollectorProvider):
    """
    Consumes pre-collected forensic evidence acquired from an authorized Endpoint Agent.

    Invariants:
    - Never touches the local host or executes local system inspection.
    - Validates collector allowlist and optional device_id / execution_id scoping.
    - Treats all payloads strictly as passive structured data, not executable code.
    """

    def __init__(
        self,
        evidence: Optional[Union[Dict[str, Any], List[Any]]] = None,
        expected_device_id: Optional[str] = None,
        expected_execution_id: Optional[str] = None,
    ):
        self.expected_device_id = expected_device_id.strip() if expected_device_id else None
        self.expected_execution_id = expected_execution_id.strip() if expected_execution_id else None
        self._evidence_by_collector: Dict[str, Dict[str, Any]] = {}

        if evidence is not None:
            self._ingest_evidence(evidence)

    def _ingest_evidence(self, evidence: Union[Dict[str, Any], List[Any]]) -> None:
        """Validates and indices pre-collected evidence payloads."""
        if isinstance(evidence, list):
            # List of EvidenceSubmission objects or dict representations
            for item in evidence:
                # Extract attributes whether Pydantic model or dict
                if hasattr(item, "collector"):
                    collector_val = item.collector.value if hasattr(item.collector, "value") else str(item.collector)
                    device_id = getattr(item, "device_id", None)
                    execution_id = getattr(item, "execution_id", None)
                    payload = getattr(item, "payload", None)
                elif isinstance(item, dict):
                    collector_val = item.get("collector")
                    device_id = item.get("device_id")
                    execution_id = item.get("execution_id")
                    payload = item.get("payload")
                else:
                    raise ValueError(f"Invalid evidence submission item type: {type(item)}")

                self._validate_and_store(collector_val, payload, device_id, execution_id)

        elif isinstance(evidence, dict):
            # Direct mapping of {collector_name: payload_dict}
            for col_name, payload in evidence.items():
                self._validate_and_store(col_name, payload)
        else:
            raise ValueError(f"Unsupported evidence container type: {type(evidence)}")

    def _validate_and_store(
        self,
        collector: Any,
        payload: Any,
        device_id: Optional[str] = None,
        execution_id: Optional[str] = None,
    ) -> None:
        """Validates collector allowlist, scoping, and data integrity."""
        if not collector:
            raise ValueError("Collector name is missing in evidence submission")

        clean_col = str(collector).strip().lower()
        if clean_col not in ALLOWED_COLLECTORS:
            raise ValueError(f"Unsupported or unauthorized collector type: '{clean_col}'")

        # Validate device scoping if configured
        if self.expected_device_id and device_id:
            if device_id.strip() != self.expected_device_id:
                raise ValueError(
                    f"Evidence device_id '{device_id}' does not match expected device '{self.expected_device_id}'"
                )

        # Validate execution scoping if configured
        if self.expected_execution_id and execution_id:
            if execution_id.strip() != self.expected_execution_id:
                raise ValueError(
                    f"Evidence execution_id '{execution_id}' does not match expected execution '{self.expected_execution_id}'"
                )

        # Enforce that payload is a dictionary (passive structured data)
        if not isinstance(payload, dict):
            raise ValueError(
                f"Evidence payload for '{clean_col}' must be a dictionary, got {type(payload).__name__}"
            )

        self._evidence_by_collector[clean_col] = payload

    def get_evidence(
        self, collector_name: str, params: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        clean_name = collector_name.strip().lower()
        if clean_name not in ALLOWED_COLLECTORS:
            raise ValueError(f"Unsupported collector type: '{collector_name}'")

        if clean_name not in self._evidence_by_collector:
            raise KeyError(
                f"No pre-collected endpoint evidence available for collector: '{clean_name}'"
            )

        return self._evidence_by_collector[clean_name]

    def collect_system(self, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        return self.get_evidence("system", params)

    def collect_processes(self, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        return self.get_evidence("processes", params)

    def collect_network(self, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        return self.get_evidence("network", params)

    def collect_files(
        self, target_path: Optional[str] = None, params: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        return self.get_evidence("files", params)

    def collect_users(self, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        return self.get_evidence("users", params)

    def collect_registry(self, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        return self.get_evidence("registry", params)

    def collect_windows_metadata(self, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        # Fallback to 'registry' if 'windows_metadata' key not explicitly given
        if "windows_metadata" in self._evidence_by_collector:
            return self.get_evidence("windows_metadata", params)
        if "registry" in self._evidence_by_collector:
            return self.get_evidence("registry", params)
        return self.get_evidence("windows_metadata", params)
