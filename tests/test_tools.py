import socket
import unittest
from types import SimpleNamespace

from rogueai import lab_http, lab_vault
from rogueai.core import AgentState, Plan, Step
from rogueai.lab import LabManager
from rogueai.tools import REGISTRY, invoke


def _ctx(lab):
    return SimpleNamespace(lab=lab, state=AgentState("test", 40, 12, 120))


class TestToolEngine(unittest.TestCase):
    def setUp(self):
        self.lab = LabManager()
        self.lab.spawn_all()
        self.ctx = _ctx(self.lab)

    def tearDown(self):
        self.lab.stop_all()

    def test_port_probe_lab_http(self):
        obs = invoke(self.ctx, "port_probe", {"target": "lab://http"})
        self.assertTrue(obs["ok"])
        self.assertIn("port-open", obs["evidence"])

    def test_port_probe_closed_port(self):
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        free_port = s.getsockname()[1]
        s.close()
        obs = invoke(self.ctx, "port_probe", {"target": f"127.0.0.1:{free_port}"})
        self.assertFalse(obs["ok"])
        self.assertIn("port-closed", obs["evidence"])

    def test_port_probe_vault_fixture(self):
        obs = invoke(self.ctx, "port_probe", {"target": "lab://vault"})
        self.assertTrue(obs["ok"])
        self.assertIn("fixture-present", obs["evidence"])

    def test_port_probe_external_refused(self):
        obs = invoke(self.ctx, "port_probe", {"target": "8.8.8.8"})
        self.assertFalse(obs["ok"])
        self.assertIn("refused", obs["evidence"])

    def test_dyn_sqli_extracts_db_flag(self):
        obs = invoke(self.ctx, "dyn_sqli", {"target": "lab://http"})
        self.assertTrue(obs["ok"], obs)
        self.assertEqual(obs["evidence"], lab_http.DB_SECRET)
        self.assertGreater(obs["detail"]["requests"], 0)

    def test_dyn_sqli_structured(self):
        obs = invoke(self.ctx, "dyn_sqli", {"target": "lab://http"})
        self.assertIn("ok", obs)
        self.assertIn("evidence", obs)
        self.assertIn("detail", obs)
        self.assertEqual(set(obs.keys()), {"ok", "evidence", "detail"})

    def test_xss_reflects_payload(self):
        payload = "<script>alert(1)</script>"
        obs = invoke(self.ctx, "xss", {"target": "lab://http", "payload": payload})
        self.assertTrue(obs["ok"])
        self.assertEqual(obs["evidence"], "XSS_ECHO:reflected")
        self.assertTrue(obs["detail"]["echoed"])

    def test_mqtt_subs_flag(self):
        obs = invoke(self.ctx, "mqtt_subs", {"target": "lab://mqtt", "topic": "vault/telemetry"})
        self.assertTrue(obs["ok"])
        self.assertIn("FLAG{", obs["evidence"])

    def test_cred_spray_finds_defaults(self):
        obs = invoke(self.ctx, "cred_spray", {"target": "lab://ssh"})
        self.assertTrue(obs["ok"], obs)
        self.assertIn("AUTH_SUCCESS:", obs["evidence"])
        self.assertGreaterEqual(len(obs["detail"]["matched"]), 1)
        self.assertEqual(obs["detail"]["attempts"], 24)

    def test_cred_spray_empty_users(self):
        obs = invoke(self.ctx, "cred_spray", {"target": "lab://ssh", "users": ""})
        self.assertFalse(obs["ok"])
        self.assertEqual(obs["detail"]["attempts"], 0)

    def test_vault_read_returns_flag(self):
        obs = invoke(self.ctx, "vault_read", {"target": "lab://vault"})
        self.assertTrue(obs["ok"])
        self.assertEqual(obs["evidence"], lab_vault.VAULT_FLAG)
        self.assertTrue(obs["detail"]["flag"])

    def test_write_note(self):
        obs = invoke(self.ctx, "write_note", {"note": "hello"})
        self.assertTrue(obs["ok"])
        self.assertEqual(self.ctx.state.notes, ["hello"])

    def test_read_plan(self):
        self.ctx.state.plan = Plan([Step("port_probe", {"target": "lab://http"})], "g", "rule")
        obs = invoke(self.ctx, "read_plan", {})
        self.assertTrue(obs["ok"])
        self.assertEqual(len(obs["detail"]["steps"]), 1)

    def test_query_state(self):
        obs = invoke(self.ctx, "query_state", {})
        self.assertTrue(obs["ok"])
        self.assertEqual(obs["detail"]["goal"], "test")

    def test_unknown_tool(self):
        obs = invoke(self.ctx, "no_such_tool", {})
        self.assertFalse(obs["ok"])
        self.assertEqual(obs["evidence"], "unknown-tool")


if __name__ == "__main__":
    unittest.main()