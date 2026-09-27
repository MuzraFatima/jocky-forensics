"""
JOCKY Endpoint Agent — Local Configuration & Credential Store

Safely persists and manages endpoint credentials (.jocky-agent.json):
- Central server URL
- Device ID assigned by the central manager
- Cryptographic device bearer token received during pairing
- Host platform and environment metadata
"""

import json
import os
from pathlib import Path
import platform
from typing import Any, Dict, Optional


DEFAULT_CONFIG_FILENAME = ".jocky-agent.json"


class AgentConfig:
    """
    Manages local endpoint agent settings and pairing credentials.
    """

    def __init__(
        self,
        server_url: str = "",
        device_id: str = "",
        device_token: str = "",
        hostname: Optional[str] = None,
        host_platform: Optional[str] = None,
        os_version: Optional[str] = None,
        agent_version: str = "1.0.0",
        paired_at: Optional[str] = None,
        config_path: Optional[str] = None,
    ):
        self.server_url = server_url.rstrip("/") if server_url else ""
        self.device_id = device_id.strip() if device_id else ""
        self.device_token = device_token.strip() if device_token else ""
        self.hostname = hostname or platform.node()
        self.platform = host_platform or platform.system()
        self.os_version = os_version or platform.release()
        self.agent_version = agent_version
        self.paired_at = paired_at
        self.config_path = config_path or self.get_default_config_path()

    @staticmethod
    def get_default_config_path() -> str:
        """
        Determines the default location for the agent credential file.
        Uses current directory `.jocky-agent.json` or fallback to user home directory.
        """
        local_path = Path.cwd() / DEFAULT_CONFIG_FILENAME
        return str(local_path)

    @property
    def is_paired(self) -> bool:
        """Returns True if the agent possesses complete pairing credentials."""
        return bool(self.server_url and self.device_id and self.device_token)

    def to_dict(self) -> Dict[str, Any]:
        """Serializes configuration to dictionary."""
        return {
            "server_url": self.server_url,
            "device_id": self.device_id,
            "device_token": self.device_token,
            "hostname": self.hostname,
            "platform": self.platform,
            "os_version": self.os_version,
            "agent_version": self.agent_version,
            "paired_at": self.paired_at,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any], config_path: Optional[str] = None) -> "AgentConfig":
        """Instantiates an AgentConfig from a dictionary."""
        return cls(
            server_url=data.get("server_url", ""),
            device_id=data.get("device_id", ""),
            device_token=data.get("device_token", ""),
            hostname=data.get("hostname"),
            host_platform=data.get("platform"),
            os_version=data.get("os_version"),
            agent_version=data.get("agent_version", "1.0.0"),
            paired_at=data.get("paired_at"),
            config_path=config_path,
        )

    def save(self, path: Optional[str] = None) -> str:
        """
        Atomically saves configuration to the target JSON file with secure file permissions.
        """
        target = Path(path or self.config_path)
        target.parent.mkdir(parents=True, exist_ok=True)

        temp_target = target.with_suffix(".tmp")
        payload = self.to_dict()

        with open(temp_target, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2)

        # Restrict permissions on POSIX systems (owner read/write only)
        if os.name == "posix":
            try:
                os.chmod(temp_target, 0o600)
            except OSError:
                pass

        # Atomic replace
        temp_target.replace(target)
        self.config_path = str(target)
        return str(target)

    @classmethod
    def load(cls, path: Optional[str] = None) -> "AgentConfig":
        """
        Loads configuration from the specified path or the default location.
        If the file does not exist, returns an unconfigured AgentConfig instance.
        """
        target = Path(path or cls.get_default_config_path())
        if not target.is_file():
            # Check user home directory fallback if local file doesn't exist
            home_target = Path.home() / DEFAULT_CONFIG_FILENAME
            if path is None and home_target.is_file():
                target = home_target
            else:
                return cls(config_path=str(target))

        try:
            with open(target, "r", encoding="utf-8") as f:
                data = json.load(f)
            return cls.from_dict(data, config_path=str(target))
        except (json.JSONDecodeError, OSError):
            return cls(config_path=str(target))

    def clear(self, path: Optional[str] = None) -> bool:
        """
        Removes the local credential file to unpair the device.
        """
        target = Path(path or self.config_path)
        if target.is_file():
            try:
                target.unlink()
                self.server_url = ""
                self.device_id = ""
                self.device_token = ""
                self.paired_at = None
                return True
            except OSError:
                return False
        return False
