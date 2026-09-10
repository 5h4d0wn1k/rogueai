import json
import os
import unittest

from rogueai import playbook
from rogueai.playbook import chain_order, list_playbooks, load, load_plan


class TestPlaybooks(unittest.TestCase):
    def test_bundled_playbooks_present(self):
        names = list_playbooks()
        self.assertGreaterEqual(len(names), 3)
        for expected in ("vault", "ssh", "web"):
            self.assertIn(expected, names)

    def test_vault_chain_order(self):
        data = load("vault")
        self.assertEqual(chain_order(data), ["port_probe", "vault_read", "write_note", "query_state"])

    def test_vault_plan_first_step(self):
        plan = load_plan("vault")
        self.assertEqual(plan.source, "playbook:vault")
        self.assertEqual(plan.steps[0].tool, "port_probe")
        self.assertEqual(plan.steps[0].args["target"], "lab://vault")

    def test_vault_plan_exploit(self):
        plan = load_plan("vault")
        self.assertEqual(plan.steps[1].tool, "vault_read")

    def test_ssh_chain_cred_spray(self):
        data = load("ssh")
        self.assertIn("cred_spray", chain_order(data))

    def test_web_chain_sqli_and_xss(self):
        data = load("web")
        order = chain_order(data)
        self.assertIn("dyn_sqli", order)
        self.assertIn("xss", order)

    def test_missing_playbook(self):
        with self.assertRaises(FileNotFoundError):
            load("does-not-exist")

    def test_playbook_files_are_json(self):
        for name in list_playbooks():
            with self.subTest(name=name):
                data = load(name)
                self.assertIn("chain", data)
                self.assertIsInstance(data["chain"], list)
                for item in data["chain"]:
                    self.assertIn("tool", item)


if __name__ == "__main__":
    unittest.main()