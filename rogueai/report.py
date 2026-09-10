import json
import os

from . import mitre

LATEST_FILE = os.path.join("reports", ".latest_run")
RUNS_DIR = os.path.join("reports", "runs")


def _load_json(path):
    if not os.path.isfile(path):
        return None
    with open(path) as f:
        return json.load(f)


def read_audit(run_dir):
    rows = []
    path = os.path.join(run_dir, "audit.jsonl")
    if not os.path.isfile(path):
        return rows
    with open(path) as f:
        for line in f:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    return rows


def write_latest(run_id):
    os.makedirs(os.path.dirname(LATEST_FILE), exist_ok=True)
    with open(LATEST_FILE, "w") as f:
        f.write(run_id)


def latest_run_id():
    if not os.path.isfile(LATEST_FILE):
        return None
    with open(LATEST_FILE) as f:
        return f.read().strip() or None


def render_report(run_dir, result, plan):
    mitre_map = {tool: mitre.technique_for(tool) for tool in sorted(mitre.MAPPING)}
    report = {
        "tool": "rogueai",
        "version": "1.0.0",
        "goal": result.get("goal"),
        "planner": result.get("planner"),
        "approval_mode": result.get("mode"),
        "goal_met": result.get("goal_met"),
        "refused": result.get("refused"),
        "blocked": result.get("blocked"),
        "iters_used": result.get("iters_used"),
        "budget_used": result.get("budget_used"),
        "budget": result.get("budget"),
        "notes": result.get("notes", []),
        "findings": result.get("findings", []),
        "mitre_mapping_stub": mitre_map,
        "audit": "audit.jsonl",
        "run_dir": run_dir,
    }
    json_path = os.path.join(run_dir, "report.json")
    with open(json_path, "w") as f:
        json.dump(report, f, indent=2)

    rows = read_audit(run_dir)
    lines = []
    lines.append("# rogueai Campaign Report")
    lines.append("")
    lines.append("> Authorized lab testing only. See README 'IMPORTANT: Read before use'.")
    lines.append("")
    lines.append("## Summary")
    lines.append("")
    lines.append(f"- Goal: {result.get('goal')}")
    lines.append(f"- Planner: {result.get('planner')}")
    lines.append(f"- Approval mode: {result.get('mode')}")
    lines.append(f"- Goal met: {result.get('goal_met')}")
    lines.append(f"- Steps taken: {result.get('iters_used')}")
    lines.append(f"- Budget used: {result.get('budget_used')} / {result.get('budget')}")
    lines.append(f"- Scope refusal: {result.get('refused')}")
    lines.append(f"- Approval block: {result.get('blocked')}")
    lines.append("")
    lines.append("## Step Chain")
    lines.append("")
    lines.append("| iter | tool | target | verdict | evidence |")
    lines.append("| --- | --- | --- | --- | --- |")
    for row in rows:
        if row.get("kind") == "step":
            verdict = row.get("verdict", {})
            evidence = str(row.get("obs", {}).get("evidence", ""))[:80]
            lines.append(
                f"| {row.get('iter')} | {row.get('tool')} | {row.get('target')} | "
                f"{'ok' if verdict.get('ok') else 'FAIL'} | {evidence} |"
            )
        elif row.get("kind") == "refuse":
            lines.append(f"| - | {row.get('tool')} | {row.get('target')} | REFUSED | {row.get('reason')} |")
        elif row.get("kind") == "block":
            lines.append(f"| - | {row.get('tool')} | {row.get('target')} | BLOCKED | {row.get('reason')} |")
    lines.append("")
    lines.append("## Findings")
    lines.append("")
    if result.get("findings"):
        for finding in result["findings"]:
            lines.append(f"- `{finding}`")
    else:
        lines.append("- (none)")
    lines.append("")
    lines.append("## MITRE-style Mapping (stub)")
    lines.append("")
    lines.append("| tool | technique |")
    lines.append("| --- | --- |")
    for tool, technique in sorted(mitre_map.items()):
        lines.append(f"| {tool} | {technique} |")
    lines.append("")
    lines.append("## Evidence")
    lines.append("")
    lines.append("Attached under `evidence/` (one file per executed step) and in the JSONL audit trail.")
    md_path = os.path.join(run_dir, "report.md")
    with open(md_path, "w") as f:
        f.write("\n".join(lines) + "\n")
    return json_path, md_path