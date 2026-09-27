"""
Unit & Integration Tests for JOCKY Endpoint Agent Package (Step 6)

Tests:
1. AgentConfig: persistence, load, save, permissions, clear, and pairing state.
2. CollectorAdapter: zero-duplication execution of local collectors, strict allowlist.
3. AgentRunner: safety validation, rejection of malicious/forbidden operations, canonical SHA-256 calculation.
4. EndpointAgentClient: REST communication (pairing, heartbeat, job polling, result submission, daemon cycle).
5. CLI Runner (jocky-agent.py): parser and command dispatching.
"""

import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import MagicMock, patch

from agent.adapter import CollectorAdapter
from agent.client import EndpointAgentClient
from agent.config import AgentConfig
from agent.runner import AgentRunner, compute_canonical_sha256
from backend.app.evidence.hashing import compute_sha256


class TestAgentConfig(unittest.TestCase):
    """Tests local configuration management and credential storage."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.config_path = str(Path(self.temp_dir.name) / ".jocky-agent.json")

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_unpaired_default(self):
        config = AgentConfig(config_path=self.config_path)
        self.assertFalse(config.is_paired)
        self.assertEqual(config.server_url, "")
        self.assertEqual(config.device_id, "")
        self.assertEqual(config.device_token, "")

    def test_save_and_load_roundtrip(self):
        config = AgentConfig(
            server_url="http://127.0.0.1:8000/",
            device_id="dev_test123",
            device_token="secret_token_abc",
            hostname="forensic-box",
            host_platform="Linux",
            config_path=self.config_path,
        )
        self.assertTrue(config.is_paired)
        saved_file = config.save()
        self.assertTrue(Path(saved_file).is_file())

        # Load from disk
        loaded = AgentConfig.load(self.config_path)
        self.assertTrue(loaded.is_paired)
        self.assertEqual(loaded.server_url, "http://127.0.0.1:8000")
        self.assertEqual(loaded.device_id, "dev_test123")
        self.assertEqual(loaded.device_token, "secret_token_abc")
        self.assertEqual(loaded.hostname, "forensic-box")
        self.assertEqual(loaded.platform, "Linux")

    def test_clear_credentials(self):
        config = AgentConfig(
            server_url="http://127.0.0.1:8000",
            device_id="dev_test123",
            device_token="token_xyz",
            config_path=self.config_path,
        )
        config.save()
        self.assertTrue(Path(self.config_path).is_file())

        cleared = config.clear()
        self.assertTrue(cleared)
        self.assertFalse(Path(self.config_path).is_file())
        self.assertFalse(config.is_paired)


class TestCollectorAdapter(unittest.TestCase):
    """Tests collector adapter routing and allowlist enforcement."""

    def setUp(self):
        self.adapter = CollectorAdapter()

    def test_allowed_collectors_set(self):
        allowed = self.adapter.get_allowed_collectors()
        self.assertIn("system", allowed)
        self.assertIn("processes", allowed)
        self.assertIn("network", allowed)
        self.assertIn("files", allowed)
        self.assertIn("users", allowed)
        self.assertIn("registry", allowed)

    def test_collect_system(self):
        data = self.adapter.collect("system")
        self.assertIsInstance(data, dict)
        self.assertIn("os", data)

    def test_collect_processes(self):
        data = self.adapter.collect("processes")
        self.assertIsInstance(data, dict)
        self.assertIn("processes", data)

    def test_unauthorized_collector_rejected(self):
        for bad_collector in ["shell", "bash", "exec", "eval", "powershell", "python_eval"]:
            with self.assertRaises(ValueError) as ctx:
                self.adapter.collect(bad_collector)
            self.assertIn("Unauthorized collector", str(ctx.exception))


class TestAgentRunner(unittest.TestCase):
    """Tests safety sandboxing, allowlist enforcement, and SHA-256 digest creation."""

    def setUp(self):
        self.runner = AgentRunner()

    def test_canonical_sha256_matches_backend(self):
        sample_data = {
            "zebra": 123,
            "alpha": "test",
            "nested": {"z": 9, "a": 1},
            "array": [3, 2, 1],
        }
        agent_hash = compute_canonical_sha256(sample_data)
        backend_hash = compute_sha256(sample_data)
        self.assertEqual(agent_hash, backend_hash)
        self.assertEqual(len(agent_hash), 64)

    def test_validate_operation_allowed(self):
        op = {"collector": "system", "params": {}}
        col = self.runner.validate_operation(op)
        self.assertEqual(col, "system")

    def test_validate_operation_unauthorized_collector(self):
        op = {"collector": "arbitrary_shell"}
        with self.assertRaises(ValueError) as ctx:
            self.runner.validate_operation(op)
        self.assertIn("SECURITY VIOLATION", str(ctx.exception))

    def test_validate_operation_forbidden_param_key(self):
        forbidden_keys = ["command", "exec", "eval", "kill", "delete", "write"]
        for bad_key in forbidden_keys:
            op = {"collector": "system", "params": {bad_key: "something"}}
            with self.assertRaises(ValueError) as ctx:
                self.runner.validate_operation(op)
            self.assertIn("SECURITY VIOLATION", str(ctx.exception))

    def test_validate_operation_path_traversal_rejected(self):
        op = {"collector": "files", "params": {"target_path": "../../etc/shadow"}}
        with self.assertRaises(ValueError) as ctx:
            self.runner.validate_operation(op)
        self.assertIn("SECURITY VIOLATION", str(ctx.exception))

    def test_execute_job_produces_valid_evidence_submission(self):
        mock_adapter = MagicMock()
        mock_adapter.collect.return_value = {"status": "ok", "host": "test-host"}
        runner = AgentRunner(adapter=mock_adapter)

        job = {
            "job_id": "job_001",
            "execution_id": "exec_abc",
            "device_id": "dev_test",
            "allowed_operations": [
                {"collector": "system", "collector_version": "1.0.0"},
                {"collector": "processes", "collector_version": "1.0.0"},
            ],
        }

        submissions = runner.execute_job(job)
        self.assertEqual(len(submissions), 2)

        # Inspect first submission
        sub1 = submissions[0]
        self.assertEqual(sub1["device_id"], "dev_test")
        self.assertEqual(sub1["execution_id"], "exec_abc")
        self.assertEqual(sub1["collector"], "system")
        self.assertEqual(sub1["payload"], {"status": "ok", "host": "test-host"})
        self.assertEqual(sub1["agent_sha256"], compute_sha256(sub1["payload"]))


class TestEndpointAgentClient(unittest.TestCase):
    """Tests HTTPS REST client communication methods."""

    def setUp(self):
        self.config = AgentConfig(
            server_url="http://127.0.0.1:8000",
            device_id="dev_test",
            device_token="secret_token",
        )
        self.client = EndpointAgentClient(config=self.config)

    def test_get_auth_headers(self):
        headers = self.client._get_auth_headers()
        self.assertEqual(headers["Authorization"], "Bearer secret_token")
        self.assertEqual(headers["X-Device-Id"], "dev_test")
        self.assertEqual(headers["Content-Type"], "application/json")

    @patch("requests.Session.post")
    def test_pair_success(self, mock_post):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "device_id": "dev_enrolled_99",
            "device_token": "tok_xyz_random",
            "hostname": "test-workstation",
            "platform": "Windows",
            "paired_at": "2026-09-27T12:00:00Z",
        }
        mock_post.return_value = mock_resp

        with tempfile.TemporaryDirectory() as td:
            cfg_file = str(Path(td) / ".jocky-agent.json")
            unpaired_config = AgentConfig(config_path=cfg_file)
            client = EndpointAgentClient(config=unpaired_config)

            success = client.pair(
                server_url="http://localhost:8000",
                pairing_code="ABCDEF12",
                custom_hostname="test-workstation",
            )
            self.assertTrue(success)
            self.assertTrue(client.is_paired)
            self.assertEqual(client.config.device_id, "dev_enrolled_99")
            self.assertEqual(client.config.device_token, "tok_xyz_random")
            self.assertTrue(Path(cfg_file).is_file())

    @patch("requests.Session.post")
    def test_pair_failure(self, mock_post):
        mock_resp = MagicMock()
        mock_resp.status_code = 400
        mock_resp.text = "INVALID_PAIRING_CODE"
        mock_post.return_value = mock_resp

        client = EndpointAgentClient(config=AgentConfig())
        success = client.pair("http://localhost:8000", "WRONGCOD")
        self.assertFalse(success)

    @patch("requests.Session.post")
    def test_heartbeat_success(self, mock_post):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"status": "ok"}
        mock_post.return_value = mock_resp

        self.assertTrue(self.client.send_heartbeat())
        self.assertEqual(mock_post.call_count, 1)

    @patch("requests.Session.post")
    def test_heartbeat_revoked(self, mock_post):
        mock_resp = MagicMock()
        mock_resp.status_code = 401
        mock_resp.text = "Device revoked"
        mock_post.return_value = mock_resp

        self.assertFalse(self.client.send_heartbeat())

    @patch("requests.Session.get")
    def test_poll_jobs(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = [{"job_id": "job_1", "execution_id": "exec_1"}]
        mock_get.return_value = mock_resp

        jobs = self.client.poll_jobs()
        self.assertEqual(len(jobs), 1)
        self.assertEqual(jobs[0]["job_id"], "job_1")

    @patch("requests.Session.post")
    def test_submit_result_success(self, mock_post):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"status": "accepted"}
        mock_post.return_value = mock_resp

        submission = {
            "device_id": "dev_test",
            "execution_id": "exec_1",
            "collector": "system",
            "collector_version": "1.0.0",
            "payload": {"os": "Linux"},
            "agent_sha256": "abcdef",
        }
        self.assertTrue(self.client.submit_result(submission))

    @patch("requests.Session.post")
    @patch("requests.Session.get")
    def test_run_once_completes_jobs(self, mock_get, mock_post):
        # Mock poll_jobs
        mock_get_resp = MagicMock()
        mock_get_resp.status_code = 200
        mock_get_resp.json.return_value = [
            {
                "job_id": "job_99",
                "execution_id": "exec_99",
                "device_id": "dev_test",
                "allowed_operations": [{"collector": "system"}],
            }
        ]
        mock_get.return_value = mock_get_resp

        # Mock submit_result
        mock_post_resp = MagicMock()
        mock_post_resp.status_code = 200
        mock_post_resp.json.return_value = {"status": "ok"}
        mock_post.return_value = mock_post_resp

        mock_runner = MagicMock()
        mock_runner.execute_job.return_value = [
            {"device_id": "dev_test", "execution_id": "exec_99", "collector": "system", "payload": {}}
        ]
        self.client.runner = mock_runner

        completed = self.client.run_once()
        self.assertEqual(completed, 1)
        mock_runner.execute_job.assert_called_once()


class TestAgentCLI(unittest.TestCase):
    """Tests master jocky-agent.py CLI argument parsing and commands."""

    def test_cli_help(self):
        import subprocess
        result = subprocess.run(
            ["python", "jocky-agent.py", "--help"],
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 0)
        self.assertIn("JOCKY Forensic Endpoint Agent CLI", result.stdout)
        self.assertIn("pair", result.stdout)
        self.assertIn("start", result.stdout)
        self.assertIn("status", result.stdout)
        self.assertIn("unpair", result.stdout)

    def test_cli_status_unpaired(self):
        import subprocess
        with tempfile.TemporaryDirectory() as td:
            cfg = str(Path(td) / "nonexistent.json")
            result = subprocess.run(
                ["python", "jocky-agent.py", "--config", cfg, "status"],
                capture_output=True,
                text=True,
            )
            self.assertEqual(result.returncode, 0)
            self.assertIn("UNPAIRED", result.stdout)

    def test_cli_unpair(self):
        import subprocess
        with tempfile.TemporaryDirectory() as td:
            cfg = str(Path(td) / ".jocky-agent.json")
            config = AgentConfig(
                server_url="http://localhost:8000",
                device_id="dev_cli_test",
                device_token="tok_123",
                config_path=cfg,
            )
            config.save()
            self.assertTrue(Path(cfg).is_file())

            result = subprocess.run(
                ["python", "jocky-agent.py", "--config", cfg, "unpair"],
                capture_output=True,
                text=True,
            )
            self.assertEqual(result.returncode, 0)
            self.assertIn("unpaired", result.stdout.lower())
            self.assertFalse(Path(cfg).is_file())


if __name__ == "__main__":
    unittest.main()
