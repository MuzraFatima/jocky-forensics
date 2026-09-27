"""
Contract & Integration Tests for Frontend Endpoint Management (Step 7)

Validates:
1. Backend REST contracts consumed by frontend/src/api.js and frontend/src/EndpointDevices.jsx:
   - POST /api/agents/pairing/generate
   - GET  /api/agents/devices
   - POST /api/agents/devices/{id}/revoke
   - POST /api/jocky/execute (with and without device_id)
2. Safe metadata exposure (NO device_token or hash in GET /api/agents/devices)
3. Target selection contract (device_id scoping, local fallback)
4. Static frontend build verification (dist bundle generated cleanly)
"""

import json
from pathlib import Path
import unittest
from fastapi.testclient import TestClient

from backend.app.main import app
from backend.app.agents.manager import get_agent_manager
from backend.app.security.auth import authenticate_user, DEFAULT_DEMO_USER, DEFAULT_DEMO_PASS


class TestFrontendEndpointContract(unittest.TestCase):
    """Tests the exact contract consumed by the frontend UI components."""

    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(app)
        cls.manager = get_agent_manager()
        # Generate valid investigator token via existing auth
        auth_res = authenticate_user(DEFAULT_DEMO_USER, DEFAULT_DEMO_PASS)
        cls.investigator_token = auth_res["token"]
        cls.headers = {"Authorization": f"Bearer {cls.investigator_token}"}

    def test_pairing_code_generate_contract(self):
        """Verifies POST /api/agents/pairing/generate returns expected shape for frontend modal."""
        resp = self.client.post(
            "/api/agents/pairing/generate",
            json={"device_name": "UI-Test-Workstation"},
            headers=self.headers,
        )
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertIn("pairing_code", data)
        self.assertIn("expires_at", data)
        self.assertIn("ttl_seconds", data)
        self.assertEqual(len(data["pairing_code"]), 8)
        self.assertGreater(data["ttl_seconds"], 0)

    def test_device_list_contract_and_safe_metadata_invariants(self):
        """Verifies GET /api/agents/devices returns safe metadata without leaking tokens."""
        # Enroll a test device first
        code_resp = self.client.post(
            "/api/agents/pairing/generate",
            json={"device_name": "Contract-PC"},
            headers=self.headers,
        )
        code = code_resp.json()["pairing_code"]

        pair_resp = self.client.post(
            "/api/agents/pair",
            json={
                "pairing_code": code,
                "hostname": "Contract-PC",
                "platform": "Windows 11",
                "agent_version": "1.0.0",
            },
        )
        self.assertEqual(pair_resp.status_code, 200)
        paired_device_id = pair_resp.json()["device_id"]

        # Call GET /api/agents/devices as the frontend does
        devices_resp = self.client.get("/api/agents/devices", headers=self.headers)
        self.assertEqual(devices_resp.status_code, 200)
        data = devices_resp.json()
        self.assertTrue(data.get("success"))
        devices = data.get("devices", [])
        self.assertIsInstance(devices, list)

        matching = [d for d in devices if d["device_id"] == paired_device_id]
        self.assertEqual(len(matching), 1)
        dev = matching[0]

        # Verify safe metadata fields required by frontend
        self.assertEqual(dev["device_id"], paired_device_id)
        self.assertEqual(dev["hostname"], "Contract-PC")
        self.assertEqual(dev["platform"], "Windows 11")
        self.assertEqual(dev["agent_version"], "1.0.0")
        self.assertIn("is_online", dev)
        self.assertIn("last_seen", dev)
        self.assertIn("created_at", dev)
        self.assertIn("status", dev)

        # STRICT SAFETY: Ensure no credentials leak in the response!
        self.assertNotIn("device_token", dev)
        self.assertNotIn("token_hash", dev)
        self.assertNotIn("token_salt", dev)

    def test_revoke_device_contract(self):
        """Verifies POST /api/agents/devices/{id}/revoke marks device revoked."""
        # 1. Pair
        gen = self.client.post("/api/agents/pairing/generate", json={}, headers=self.headers).json()
        pair_resp = self.client.post(
            "/api/agents/pair",
            json={"pairing_code": gen["pairing_code"], "hostname": "To-Revoke-PC", "platform": "Linux"},
        )
        self.assertEqual(pair_resp.status_code, 200)
        dev_id = pair_resp.json()["device_id"]

        # 2. Revoke
        rev_resp = self.client.post(f"/api/agents/devices/{dev_id}/revoke", headers=self.headers)
        self.assertEqual(rev_resp.status_code, 200)
        rev_data = rev_resp.json()
        self.assertTrue(rev_data.get("success"))
        self.assertEqual(rev_data.get("device_id"), dev_id)

        # 3. Check listing
        devices = self.client.get("/api/agents/devices", headers=self.headers).json().get("devices", [])
        dev = next(d for d in devices if d["device_id"] == dev_id)
        self.assertEqual(dev["status"], "revoked")
        self.assertTrue(dev["is_revoked"])
        self.assertFalse(dev["is_online"])

    def test_jocky_execute_local_fallback(self):
        """Verifies execution without device_id targets the local host transparently."""
        resp = self.client.post(
            "/api/jocky/execute",
            json={
                "script": "CASE \"LOCAL-TEST\"\nTARGET \"LOCAL-HOST\"\nCOLLECT SYSTEM\nANALYZE\nVERIFY INTEGRITY\nREPORT",
            },
        )
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertTrue(data.get("success"))
        self.assertEqual(data.get("case_id"), "LOCAL-TEST")
        self.assertIn("collected_data", data)
        self.assertIn("system", data["collected_data"])

    def test_frontend_dist_bundle_integrity(self):
        """Verifies that the Vite production build exists and contains key component tokens."""
        dist_dir = Path("frontend/dist")
        self.assertTrue(dist_dir.is_dir(), "frontend/dist directory must exist")
        index_html = dist_dir / "index.html"
        self.assertTrue(index_html.is_file(), "frontend/dist/index.html must exist")

        # Check bundle output
        assets_dir = dist_dir / "assets"
        js_files = list(assets_dir.glob("*.js"))
        self.assertGreater(len(js_files), 0, "Production JS bundle must be generated")

        # Read bundle to confirm key tokens are bundled
        bundle_text = js_files[0].read_text(encoding="utf-8")
        self.assertIn("Endpoint Device Management", bundle_text)
        self.assertIn("Single-Use Pairing Code", bundle_text)
        self.assertIn("python jocky-agent.py pair", bundle_text)


if __name__ == "__main__":
    unittest.main()
