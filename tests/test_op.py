import json
import os
import unittest

from rogueai.lab import LabManager
from rogueai.op import run_campaign
from rogueai.playbook import load_plan
from rogueai.report import LATEST_FILE, read_audit
from rogueai.lab_vault import VAULT_FLAG

VAULT_GOAL = "obtain vault flag from lab vault"


class _Base(unittest.TestCase):
    def setUp(self):
        self.lab = LabManager()
        self.lab.spawn_all()

    def tearDown(self):
        self.lab.stop_all()


class TestVaultCampaign(_Base):
    def test_goal_met_end_to_end(self):
        result = run_campaign(VAULT_GOAL, planner_name="rule", mode="auto", approved=True, lab=self.lab)
        self.assertTrue(result["goal_met"])
        self.assertEqual(result["iters_used"], 2)
        self.assertIn(VAULT_FLAG, " ".join(result["findings"]))
        self.assertFalse(result["refused"])
        self.assertFalse(result["blocked"])

    def test_loop_terminates_budget_respected(self):
        result = run_campaign(VAULT_GOAL, mode="auto", lab=self.lab)
        self.assertLessEqual(result["iters_used"], result["max_iters"])
        self.assertLessEqual(result["budget_used"], result["budget"])

    def test_goal_met_deterministic(self):
        r1 = run_campaign(VAULT_GOAL, mode="auto", lab=self.lab)
        r2 = run_campaign(VAULT_GOAL, mode="auto", lab=self.lab)
        self.assertEqual(r1["goal_met"], r2["goal_met"])
        self.assertTrue(r1["goal_met"])

    def test_audit_full_chain(self):
        result = run_campaign(VAULT_GOAL, mode="auto", lab=self.lab)
        rows = read_audit(result["run_dir"])
        steps = [r for r in rows if r["kind"] == "step"]
        self.assertEqual(len(steps), result["iters_used"])
        tools = {s["tool"] for s in steps}
        self.assertTrue({"port_probe", "vault_read"}.issubset(tools))
        for s in steps:
            self.assertIn("tool", s)
            self.assertIn("args", s)
            self.assertIn("obs", s)
            self.assertIn("verdict", s)
            self.assertIn("target", s)

    def test_audit_summary_row(self):
        result = run_campaign(VAULT_GOAL, mode="auto", lab=self.lab)
        rows = read_audit(result["run_dir"])
        self.assertTrue(any(r["kind"] == "summary" for r in rows))
        self.assertTrue(any(r["kind"] == "info" for r in rows))

    def test_evidence_files_written(self):
        result = run_campaign(VAULT_GOAL, mode="auto", lab=self.lab)
        evidence_dir = os.path.join(result["run_dir"], "evidence")
        files = [f for f in os.listdir(evidence_dir) if f.endswith(".txt")]
        self.assertEqual(len(files), result["iters_used"])
        blob = open(os.path.join(evidence_dir, files[-1])).read()
        self.assertIn("FLAG{", blob)

    def test_report_files_written(self):
        result = run_campaign(VAULT_GOAL, mode="auto", lab=self.lab)
        self.assertTrue(os.path.isfile(os.path.join(result["run_dir"], "report.json")))
        self.assertTrue(os.path.isfile(os.path.join(result["run_dir"], "report.md")))
        self.assertTrue(os.path.isfile(os.path.join(result["run_dir"], "result.json")))
        with open(LATEST_FILE) as f:
            self.assertEqual(f.read(), result["run_id"])

    def test_report_json_content(self):
        result = run_campaign(VAULT_GOAL, mode="auto", lab=self.lab)
        with open(os.path.join(result["run_dir"], "report.json")) as f:
            report = json.load(f)
        self.assertTrue(report["goal_met"])
        self.assertIn("mitre_mapping_stub", report)
        self.assertTrue(report["mitre_mapping_stub"]["vault_read"])

    def test_plan_written(self):
        result = run_campaign(VAULT_GOAL, mode="auto", lab=self.lab)
        with open(os.path.join(result["run_dir"], "plan.json")) as f:
            plan = json.load(f)
        self.assertEqual(plan["source"], "rule")
        self.assertEqual(plan["n"], 5)


class TestScopeRefusal(_Base):
    def test_external_goal_hard_refused(self):
        result = run_campaign("probe 8.8.8.8 on lab", mode="auto", lab=self.lab)
        self.assertTrue(result["refused"])
        self.assertFalse(result["goal_met"])
        self.assertEqual(result["iters_used"], 0)
        rows = read_audit(result["run_dir"])
        self.assertTrue(any(r["kind"] == "refuse" for r in rows))


class TestApprovalModes(_Base):
    def test_ask_without_approve_blocks(self):
        result = run_campaign(VAULT_GOAL, mode="ask", approved=False, lab=self.lab)
        self.assertTrue(result["blocked"])
        self.assertFalse(result["goal_met"])
        rows = read_audit(result["run_dir"])
        self.assertTrue(any(r["kind"] == "block" for r in rows))

    def test_ask_with_approve_succeeds(self):
        result = run_campaign(VAULT_GOAL, mode="ask", approved=True, lab=self.lab)
        self.assertFalse(result["blocked"])
        self.assertTrue(result["goal_met"])

    def test_never_blocks_blacklisted_tool(self):
        result = run_campaign("validate default credentials on lab ssh", mode="never", approved=True, lab=self.lab)
        self.assertTrue(result["blocked"])
        self.assertFalse(result["goal_met"])


class TestBudgetsAndIterations(_Base):
    def test_budget_respected(self):
        result = run_campaign(VAULT_GOAL, mode="auto", budget=1, lab=self.lab)
        self.assertEqual(result["budget_used"], 1)
        self.assertFalse(result["goal_met"])

    def test_max_iters_respected(self):
        result = run_campaign(VAULT_GOAL, mode="auto", max_iters=1, lab=self.lab)
        self.assertEqual(result["iters_used"], 1)
        self.assertFalse(result["goal_met"])


class TestDryRun(_Base):
    def test_llm_dry_run_plans_steps(self):
        result = run_campaign(VAULT_GOAL, planner_name="llm", dry_run=True, lab=self.lab)
        self.assertTrue(result["dry_run"])
        self.assertGreaterEqual(result["n"], 1)
        self.assertIn("fallback", result["source"])
        self.assertIsNone(result.get("goal_met"))

    def test_rule_dry_run_plans_steps(self):
        result = run_campaign(VAULT_GOAL, planner_name="rule", dry_run=True, lab=self.lab)
        self.assertTrue(result["dry_run"])
        self.assertEqual(result["n"], 5)
        self.assertEqual(result["steps"][0]["tool"], "port_probe")

    def test_dry_run_no_lab_side_effects(self):
        before = self.lab.request_count()
        run_campaign(VAULT_GOAL, planner_name="llm", dry_run=True, lab=self.lab)
        after = self.lab.request_count()
        self.assertEqual(before, after)


class TestPlaybookPreset(_Base):
    def test_vault_playbook_goal_met(self):
        plan = load_plan("vault")
        result = run_campaign(
            plan.goal, planner_name="playbook", preset_plan=plan, mode="auto", lab=self.lab
        )
        self.assertTrue(result["goal_met"])
        self.assertIn(VAULT_FLAG, " ".join(result["findings"]))


if __name__ == "__main__":
    unittest.main()