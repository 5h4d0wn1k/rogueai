import contextlib
import io
import unittest

from rogueai import cli
from rogueai.op import demo_result


class TestDemo(unittest.TestCase):
    def test_demo_result_goal_met(self):
        result = demo_result()
        self.assertTrue(result["goal_met"])
        self.assertEqual(result["planner"], "rule")
        self.assertLessEqual(result["budget_used"], result["budget"])

    def test_demo_cli_exits_zero(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = cli.main(["--demo"])
        self.assertEqual(code, 0)
        text = out.getvalue()
        self.assertIn("ROGUEAI_DEMO ran", text)
        self.assertIn("GOAL_MET: True", text)
        self.assertIn("REPORT:", text)
        self.assertIn("exit=0", text)

    def test_demo_works_without_llm_env(self):
        import os

        for key in ("ROGUEAI_LLM_BASE", "ROGUEAI_LLM_KEY"):
            os.environ.pop(key, None)
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = cli.main(["--demo"])
        self.assertEqual(code, 0)


if __name__ == "__main__":
    unittest.main()