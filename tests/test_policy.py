import unittest

from rogueai import policy
from rogueai.tools import REGISTRY


class TestPolicyGate(unittest.TestCase):
    def test_auto_allows_vault_read(self):
        g = policy.gate("vault_read", "lab://vault", "auto")
        self.assertEqual(g["decision"], "allow")

    def test_auto_allows_low_risk(self):
        g = policy.gate("port_probe", "lab://http", "auto")
        self.assertEqual(g["decision"], "allow")

    def test_ask_blocks_impactful_without_approve(self):
        g = policy.gate("vault_read", "lab://vault", "ask", approved=False)
        self.assertEqual(g["decision"], "block")

    def test_ask_allows_impactful_with_approve(self):
        g = policy.gate("vault_read", "lab://vault", "ask", approved=True)
        self.assertEqual(g["decision"], "allow")

    def test_ask_allows_low_risk_without_approve(self):
        g = policy.gate("write_note", "lab://vault", "ask", approved=False)
        self.assertEqual(g["decision"], "allow")

    def test_never_blocks_blacklisted(self):
        g = policy.gate("cred_spray", "lab://ssh", "never", approved=True)
        self.assertEqual(g["decision"], "block")

    def test_never_blocks_impactful(self):
        g = policy.gate("vault_read", "lab://vault", "never", approved=True)
        self.assertEqual(g["decision"], "block")

    def test_never_allows_low_risk(self):
        g = policy.gate("port_probe", "lab://http", "never")
        self.assertEqual(g["decision"], "allow")

    def test_refuse_external_in_any_mode(self):
        for mode in policy.MODES:
            with self.subTest(mode=mode):
                g = policy.gate("port_probe", "8.8.8.8", mode)
                self.assertEqual(g["decision"], "refuse", mode)

    def test_refuse_external_even_with_approval(self):
        g = policy.gate("vault_read", "http://192.168.1.5", "auto", approved=True)
        self.assertEqual(g["decision"], "refuse")

    def test_tool_risk_levels(self):
        self.assertEqual(policy.tool_risk("cred_spray"), 3)
        self.assertEqual(policy.tool_risk("port_probe"), 1)
        self.assertEqual(policy.tool_risk("dyn_sqli"), 2)

    def test_blacklist_contents(self):
        self.assertIn("cred_spray", policy.BLACKLISTED)

    def test_all_tools_registered(self):
        for name in ("port_probe", "dyn_sqli", "xss", "mqtt_subs", "vault_read",
                     "cred_spray", "write_note", "read_plan", "query_state"):
            self.assertIn(name, REGISTRY)


if __name__ == "__main__":
    unittest.main()