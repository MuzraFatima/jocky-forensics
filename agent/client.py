"""
JOCKY Endpoint Agent — REST Client & Background Daemon

Handles communication with the central JOCKY backend:
- Device pairing via short-lived 8-character pairing codes
- Heartbeat presence beacons (every 15s)
- Job polling (every 2s)
- Verified evidence submission with SHA-256 integrity confirmation
- Resilient retry and reconnection handling
"""

import datetime
import logging
import platform
import threading
import time
from typing import Any, Dict, List, Optional
import requests

from .config import AgentConfig
from .runner import AgentRunner

logger = logging.getLogger("jocky.agent.client")


class EndpointAgentClient:
    """
    Client daemon connecting an authorized endpoint device to the central JOCKY server.
    """

    def __init__(
        self,
        config: Optional[AgentConfig] = None,
        runner: Optional[AgentRunner] = None,
        timeout: float = 10.0,
    ):
        self.config = config or AgentConfig.load()
        self.runner = runner or AgentRunner()
        self.timeout = timeout
        self.session = requests.Session()
        self._last_heartbeat: float = 0.0

    @property
    def is_paired(self) -> bool:
        """Returns True if valid pairing credentials exist."""
        return self.config.is_paired

    def _get_auth_headers(self) -> Dict[str, str]:
        """Constructs required authorization and device identification headers."""
        return {
            "Authorization": f"Bearer {self.config.device_token}",
            "X-Device-Id": self.config.device_id,
            "Content-Type": "application/json",
        }

    # ─── 1. Pairing ───────────────────────────────────────────────────────────

    def pair(
        self,
        server_url: str,
        pairing_code: str,
        custom_hostname: Optional[str] = None,
    ) -> bool:
        """
        Exchanges a single-use pairing code with the central backend for enrollment credentials.

        Args:
            server_url: Base URL of JOCKY server (e.g. "http://127.0.0.1:8000" or "https://app.jocky.io")
            pairing_code: 8-character alphanumeric pairing code from dashboard
            custom_hostname: Optional friendly device name

        Returns:
            True if pairing succeeded and credentials were saved, False otherwise.
        """
        clean_url = server_url.rstrip("/")
        endpoint = f"{clean_url}/api/agents/pair"

        hostname = custom_hostname or platform.node()
        payload = {
            "pairing_code": pairing_code.strip(),
            "hostname": hostname,
            "platform": f"{platform.system()} {platform.release()}".strip(),
            "agent_version": self.config.agent_version,
        }

        logger.info(f"Attempting pairing with JOCKY server at {clean_url}...")
        try:
            resp = self.session.post(endpoint, json=payload, timeout=self.timeout)
            if resp.status_code == 200:
                data = resp.json()
                self.config.server_url = clean_url
                self.config.device_id = data["device_id"]
                self.config.device_token = data["device_token"]
                self.config.hostname = data.get("hostname", hostname)
                self.config.platform = data.get("platform", platform.system())
                self.config.paired_at = data.get("paired_at", datetime.datetime.now(datetime.timezone.utc).isoformat())
                saved_path = self.config.save()
                logger.info(f"Successfully paired device '{self.config.device_id}' to {clean_url}. Config saved to {saved_path}")
                return True
            else:
                err_msg = resp.text
                try:
                    err_json = resp.json()
                    err_msg = err_json.get("detail", err_msg)
                except Exception:
                    pass
                logger.error(f"Pairing failed ({resp.status_code}): {err_msg}")
                return False
        except requests.RequestException as e:
            logger.error(f"Connection error during pairing: {e}")
            return False

    # ─── 2. Heartbeat ─────────────────────────────────────────────────────────

    def send_heartbeat(self) -> bool:
        """
        Sends an authenticated presence beacon to the central backend.
        """
        if not self.is_paired:
            logger.warning("Cannot send heartbeat: device is not paired.")
            return False

        endpoint = f"{self.config.server_url}/api/agents/heartbeat"
        payload = {
            "device_id": self.config.device_id,
            "timestamp": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "hostname": self.config.hostname,
            "platform": self.config.platform,
            "agent_version": self.config.agent_version,
        }

        try:
            resp = self.session.post(
                endpoint,
                headers=self._get_auth_headers(),
                json=payload,
                timeout=self.timeout,
            )
            if resp.status_code == 200:
                self._last_heartbeat = time.time()
                return True
            elif resp.status_code == 401:
                logger.error("Heartbeat rejected: device authentication failed or token was revoked.")
                return False
            else:
                logger.warning(f"Heartbeat received unexpected status: {resp.status_code}")
                return False
        except requests.RequestException as e:
            logger.debug(f"Heartbeat network error: {e}")
            return False

    # ─── 3. Polling Jobs ──────────────────────────────────────────────────────

    def poll_jobs(self) -> List[Dict[str, Any]]:
        """
        Queries the central backend for pending forensic collection jobs assigned to this device.
        """
        if not self.is_paired:
            return []

        endpoint = f"{self.config.server_url}/api/agents/jobs"
        params = {"device_id": self.config.device_id}

        try:
            resp = self.session.get(
                endpoint,
                headers=self._get_auth_headers(),
                params=params,
                timeout=self.timeout,
            )
            if resp.status_code == 200:
                data = resp.json()
                if isinstance(data, list):
                    return data
                if isinstance(data, dict):
                    job = data.get("job")
                    return [job] if job else []
                return []
            elif resp.status_code == 401:
                logger.error("Job polling rejected: device token unauthorized or revoked.")
                return []
            else:
                logger.warning(f"Job polling returned status: {resp.status_code}")
                return []
        except requests.RequestException as e:
            logger.debug(f"Job polling network error: {e}")
            return []

    # ─── 4. Submitting Results ────────────────────────────────────────────────

    def submit_result(self, submission: Dict[str, Any]) -> bool:
        """
        Submits an individual sealed evidence payload to the central backend.
        """
        if not self.is_paired:
            return False

        endpoint = f"{self.config.server_url}/api/agents/result"

        try:
            resp = self.session.post(
                endpoint,
                headers=self._get_auth_headers(),
                json=submission,
                timeout=self.timeout,
            )
            if resp.status_code == 200:
                logger.info(
                    f"Successfully submitted evidence for execution {submission.get('execution_id')} "
                    f"collector {submission.get('collector')}"
                )
                return True
            else:
                err_text = resp.text
                logger.error(f"Failed to submit evidence ({resp.status_code}): {err_text}")
                return False
        except requests.RequestException as e:
            logger.error(f"Network error while submitting evidence: {e}")
            return False

    # ─── 5. Execution Cycle ───────────────────────────────────────────────────

    def run_once(self) -> int:
        """
        Executes a single polling iteration:
        - Sends heartbeat if due (>15s since last heartbeat)
        - Checks for pending jobs
        - Executes all operations locally on the endpoint
        - Submits sealed evidence to the backend

        Returns:
            Number of completed jobs in this iteration.
        """
        now = time.time()
        if now - self._last_heartbeat >= 15.0:
            self.send_heartbeat()

        jobs = self.poll_jobs()
        if not jobs:
            return 0

        completed = 0
        for job in jobs:
            try:
                submissions = self.runner.execute_job(job)
                for sub in submissions:
                    success = self.submit_result(sub)
                    if not success:
                        logger.warning(f"Failed to submit evidence for job {job.get('job_id')}")
                completed += 1
            except Exception as e:
                logger.error(f"Error executing job {job.get('job_id')}: {e}", exc_info=True)

        return completed

    # ─── 6. Continuous Daemon Loop ────────────────────────────────────────────

    def run_daemon(
        self,
        poll_interval: float = 2.0,
        heartbeat_interval: float = 15.0,
        stop_event: Optional[threading.Event] = None,
        max_iterations: Optional[int] = None,
    ) -> None:
        """
        Starts the continuous polling daemon.

        Args:
            poll_interval: Interval in seconds between job polling queries (default 2.0s)
            heartbeat_interval: Interval in seconds between presence beacons (default 15.0s)
            stop_event: Optional threading.Event to signal termination
            max_iterations: Optional maximum iterations (for testing)
        """
        if not self.is_paired:
            raise RuntimeError(
                "Cannot start endpoint agent: device is not paired. "
                "Run `python jocky-agent.py pair --server <url> --code <code>` first."
            )

        logger.info(
            f"Starting JOCKY Endpoint Agent for '{self.config.hostname}' "
            f"(Device ID: {self.config.device_id}) -> Server: {self.config.server_url}"
        )

        # Initial heartbeat
        self.send_heartbeat()

        iteration = 0
        try:
            while True:
                if stop_event and stop_event.is_set():
                    logger.info("Termination signal received. Shutting down endpoint agent.")
                    break

                if max_iterations is not None and iteration >= max_iterations:
                    break

                now = time.time()
                if now - self._last_heartbeat >= heartbeat_interval:
                    self.send_heartbeat()

                self.run_once()

                iteration += 1
                time.sleep(poll_interval)

        except KeyboardInterrupt:
            logger.info("Agent stopped by user interrupt.")
