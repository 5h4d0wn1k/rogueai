import os
import unittest

from rogueai import mitre
from rogueai.op import run_campaign
from rogueai.report import LATEST_FILE, latest_run_id, read_audit, write_latest, render_report

VAULT_GOAL = "obtain vault flag from lab vault"


class TestReports(unittest.TestCase):
    def setUp(self):
        self.result = run_campaign(VAULT_GOAL, mode="auto", approved=True)
        self.run_dir = self.result["run_dir"]

    def test_markdown_written(self):
        self.assertTrue(os.path.isfile(os.path.join(self.run_dir, "report.md")))
        md = open(os.path.join(self.run_dir, "report.md")).read()
        self.assertIn("## Summary", md)
        self.assertIn("## MITRE-style Mapping (stub)", md)
        self.assertIn("## Step Chain", md)
        self.assertIn("## Evidence", md)

    def test_json_written(self):
        import json

        with open(os.path.join(self.run_dir, "report.json")) as f:
            report = json.load(f)
        self.assertTrue(report["goal_met"])
        self.assertEqual(report["budget_used"], 2)
        self.assertIn("mitre_mapping_stub", report)

    def test_mitre_mapping_stub(self):
        self.assertIn("T1190", mitre.technique_for("dyn_sqli"))
        self.assertTrue(mitre.technique_for("port_probe"))
        self.assertEqual(mitre.technique_for("vault_read"), "T1552.001 Credentials in Files")

    def test_audit_readable(self):
        rows = read_audit(self.run_dir)
        self.assertGreaterEqual(len(rows), 3)
        kinds = {r["kind"] for r in rows}
        self.assertTrue({"info", "step", "summary"}.issubset(kinds))

    def test_latest_pointer(self):
        run_id = latest_run_id()
        self.assertEqual(run_id, self.result["run_id"])
        with open(LATEST_FILE) as f:
            self.assertEqual(f.read(), run_id)

    def test_render_report_idempotent(self):
        from rogueai.op import RUNS_DIR, _run_id
        import json

        with open(os.path.join(self.run_dir, "result.json")) as f:
            existing = json.load(f)
        seed_dir = os.path.join(RUNS_DIR, _run_id())
        os.makedirs(seed_dir, exist_ok=True)
        run_dir2 = os.path.join(RUNS_DIR, "re-render-temp")
        os.makedirs(run_dir2, exist_ok=True)
        render_report(run_dir2, existing, None)
        self.assertTrue(os.path.isfile(os.path.join(run_dir2, "report.md")))
        self.assertTrue(os.path.isfile(os.path.join(run_dir2, "report.json")))


if __name__ == "__main__":
    unittest.main()