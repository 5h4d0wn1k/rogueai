import contextlib
import io
import json
import unittest

from rogueai import cli
from rogueai.lab import LabManager
from rogueai.lab_vault import VAULT_FLAG

VAULT_GOAL = "obtain vault flag from lab vault"


def _run_cli(argv):
    out = io.StringIO()
    err = io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = cli.main(argv)
    return code, out.getvalue(), err.getvalue()


class TestCLI(unittest.TestCase):
    def test_version(self):
        with self.assertRaises(SystemExit) as cm:
            cli.main(["--version"])
        self.assertEqual(cm.exception.code, 0)

    def test_no_command_help(self):
        code, out, _ = _run_cli([])
        self.assertEqual(code, 1)
        self.assertIn("usage", out)

    def test_demo_exit_zero(self):
        code, out, _ = _run_cli(["--demo"])
        self.assertEqual(code, 0)
        self.assertIn("GOAL_MET: True", out)
        self.assertIn("exit=0", out)

    def test_tools_list(self):
        code, out, _ = _run_cli(["tools", "list"])
        self.assertEqual(code, 0)
        for name in ("dyn_sqli", "vault_read", "cred_spray", "query_state"):
            self.assertIn(name, out)

    def test_tools_run_vault_read(self):
        lab = LabManager()
        lab.spawn_all()
        code, out, _ = _run_cli(["tools", "run", "vault_read", "--arg", "target=lab://vault"])
        lab.stop_all()
        self.assertEqual(code, 0)
        obs = json.loads(out)
        self.assertTrue(obs["ok"])
        self.assertEqual(obs["evidence"], VAULT_FLAG)

    def test_planner_rule(self):
        code, out, _ = _run_cli(["planner", "--goal", VAULT_GOAL, "--planner", "rule"])
        self.assertEqual(code, 0)
        self.assertIn("port_probe", out)
        self.assertIn("vault_read", out)

    def test_planner_llm_real_guidance(self):
        code, out, err = _run_cli(["planner", "--goal", VAULT_GOAL, "--planner", "llm"])
        self.assertEqual(code, 1)
        self.assertIn("ROGUEAI_LLM_BASE", err)

    def test_planner_llm_dry_run_prints_steps(self):
        code, out, _ = _run_cli(["planner", "--goal", VAULT_GOAL, "--planner", "llm", "--dry-run"])
        self.assertEqual(code, 0)
        self.assertIn("PLANNED_STEPS:", out)

    def test_op_dry_run_llm_no_side_effects(self):
        lab = LabManager()
        lab.spawn_all()
        before = lab.request_count()
        code, out, _ = _run_cli(["op", "--goal", VAULT_GOAL, "--planner", "llm", "--dry-run"])
        after = lab.request_count()
        lab.stop_all()
        self.assertEqual(code, 0)
        self.assertIn("PLANNED_STEPS:", out)
        self.assertEqual(before, after)

    def test_op_auto_goal_met(self):
        code, out, _ = _run_cli(["op", "--goal", VAULT_GOAL, "--planner", "rule", "--approve", "auto"])
        self.assertEqual(code, 0)
        self.assertIn("GOAL_MET: True", out)

    def test_op_ask_blocks_without_approve(self):
        code, out, _ = _run_cli(["op", "--goal", VAULT_GOAL])
        self.assertEqual(code, 3)
        self.assertIn("GOAL_MET: False", out)
        self.assertIn("BLOCKED: True", out)

    def test_op_ask_succeeds_with_approve(self):
        code, out, _ = _run_cli(["op", "--goal", VAULT_GOAL, "--approve"])
        self.assertEqual(code, 0)
        self.assertIn("GOAL_MET: True", out)

    def test_op_scope_refuse_exit_2(self):
        code, out, _ = _run_cli(["op", "--goal", "probe 8.8.8.8 on lab", "--approve", "auto"])
        self.assertEqual(code, 2)
        self.assertIn("REFUSED: True", out)

    def test_overseer_gate_refuses_external(self):
        code, out, _ = _run_cli(["overseer", "gate", "--tool", "port_probe",
                              "--target", "8.8.8.8", "--mode", "auto"])
        self.assertEqual(code, 0)
        decision = json.loads(out)
        self.assertEqual(decision["decision"], "refuse")

    def test_overseer_status(self):
        code, out, _ = _run_cli(["overseer", "status"])
        self.assertEqual(code, 0)
        self.assertIn("allowlist", out)

    def test_judge_cli(self):
        code, out, _ = _run_cli(["judge", "--goal", VAULT_GOAL, "--evidence", VAULT_FLAG])
        self.assertEqual(code, 0)
        data = json.loads(out)
        self.assertTrue(data["met"])

    def test_playbook_list(self):
        code, out, _ = _run_cli(["playbook", "list"])
        self.assertEqual(code, 0)
        self.assertIn("vault", out)

    def test_playbook_run(self):
        code, out, _ = _run_cli(["playbook", "run", "vault", "--approve", "auto"])
        self.assertEqual(code, 0)
        self.assertIn("GOAL_MET: True", out)

    def test_report_latest(self):
        _run_cli(["op", "--goal", VAULT_GOAL, "--approve", "auto"])
        code, out, _ = _run_cli(["report", "--latest"])
        self.assertEqual(code, 0)
        self.assertIn("GOAL_MET: True", out)
        self.assertIn("report.md", out)

    def test_lab_background_lifecycle(self):
        code, out, _ = _run_cli(["lab", "spawn", "--background"])
        self.assertEqual(code, 0)
        state = json.loads(out)
        self.assertIn("http", state["endpoints"])
        try:
            code2, out2, _ = _run_cli(["lab", "status"])
            self.assertEqual(code2, 0)
            self.assertIn("pid", out2)
        finally:
            _run_cli(["lab", "stop"])
        code3, out3, _ = _run_cli(["lab", "status"])
        self.assertEqual(code3, 0)
        self.assertIn("not started", out3)


if __name__ == "__main__":
    unittest.main()