import os
import unittest

from rogueai.planner import LLMPlanner, PlannerConfigError, RulePlanner, detect_host_targets, goal_words


class TestGoalAnalysis(unittest.TestCase):
    def test_goal_words_filters_stopwords(self):
        words = goal_words("obtain vault flag from lab vault")
        self.assertIn("vault", words)
        self.assertIn("flag", words)
        self.assertNotIn("from", words)
        self.assertNotIn("lab", words)

    def test_host_detection(self):
        self.assertEqual(detect_host_targets("probe 8.8.8.8 now"), ["8.8.8.8"])
        self.assertEqual(detect_host_targets("obtain vault flag"), [])

    def test_host_detection_ignores_lab(self):
        self.assertEqual(detect_host_targets("scan lab://mqtt"), [])


class TestRulePlanner(unittest.TestCase):
    def test_vault_goal_first_step(self):
        plan = RulePlanner("obtain vault flag from lab vault").to_plan()
        self.assertEqual(plan.steps[0].tool, "port_probe")
        self.assertEqual(plan.steps[0].args["target"], "lab://vault")

    def test_vault_goal_exploit_step(self):
        plan = RulePlanner("obtain vault flag from lab vault").to_plan()
        tools = [s.tool for s in plan.steps]
        self.assertIn("vault_read", tools)
        self.assertIn("write_note", tools)
        self.assertIn("query_state", tools)

    def test_vault_goal_order(self):
        plan = RulePlanner("obtain vault flag from lab vault").to_plan()
        tools = [s.tool for s in plan.steps]
        self.assertEqual(tools.index("port_probe"), 0)
        self.assertLess(tools.index("vault_read"), tools.index("write_note"))

    def test_ssh_goal_expected_chain(self):
        plan = RulePlanner("validate default credentials on lab ssh").to_plan()
        tools = [(s.tool, s.args.get("target")) for s in plan.steps]
        self.assertEqual(tools[0], ("port_probe", "lab://ssh"))
        self.assertEqual(tools[1], ("cred_spray", "lab://ssh"))

    def test_sqli_goal_prefers_dyn_sqli(self):
        plan = RulePlanner("extract the database flag with sqli").to_plan()
        tools = [s.tool for s in plan.steps]
        self.assertEqual(tools[0], "port_probe")
        self.assertEqual(tools[1], "dyn_sqli")

    def test_external_host_goal_plans_probe(self):
        plan = RulePlanner("probe 8.8.8.8 on lab").to_plan()
        self.assertEqual(plan.steps[0].tool, "port_probe")
        self.assertEqual(plan.steps[0].args["target"], "8.8.8.8")

    def test_plan_source_and_note(self):
        plan = RulePlanner("obtain vault flag from lab vault").to_plan()
        self.assertEqual(plan.source, "rule")
        self.assertTrue(plan.note)
        self.assertEqual(plan.to_dict()["n"], len(plan.steps))

    def test_next_step_consumes_plan(self):
        planner = RulePlanner("obtain vault flag from lab vault")
        first = planner.next_step()
        self.assertEqual(first.tool, "port_probe")
        second = planner.next_step()
        self.assertEqual(second.tool, "vault_read")

    def test_reflect_returns_note(self):
        planner = RulePlanner("obtain vault flag from lab vault")
        note = planner.reflect({"ok": True, "evidence": "FLAG{x}"})
        self.assertIn("reflection", note)


class TestLLMPlanner(unittest.TestCase):
    def setUp(self):
        self.saved_base = os.environ.pop("ROGUEAI_LLM_BASE", None)
        self.saved_key = os.environ.pop("ROGUEAI_LLM_KEY", None)

    def tearDown(self):
        if self.saved_base is not None:
            os.environ["ROGUEAI_LLM_BASE"] = self.saved_base
        if self.saved_key is not None:
            os.environ["ROGUEAI_LLM_KEY"] = self.saved_key

    def test_unavailable_raises_guidance(self):
        with self.assertRaises(PlannerConfigError) as cm:
            LLMPlanner(dry_run=False).plan("obtain vault flag")
        self.assertIn("ROGUEAI_LLM_BASE", str(cm.exception))
        self.assertIn("--planner rule", str(cm.exception))

    def test_unavailable_dry_run_falls_back(self):
        plan = LLMPlanner(dry_run=True).plan("obtain vault flag from lab vault")
        self.assertEqual(plan.source, "llm:dry-run(fallback=rule)")
        self.assertGreaterEqual(plan.to_dict()["n"], 1)
        self.assertIn("rule", plan.note)

    def test_available_flag(self):
        self.assertFalse(LLMPlanner().available)


if __name__ == "__main__":
    unittest.main()