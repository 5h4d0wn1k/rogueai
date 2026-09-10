import argparse
import json
import os
import subprocess
import sys
import time
from types import SimpleNamespace

from . import __version__, lab as labmod, policy
from .core import AgentState, Step
from .judge import Judge, rule_met
from .op import run_campaign
from .planner import LLMPlanner, PlannerConfigError, RulePlanner
from .playbook import list_playbooks, load, load_plan
from .tools import REGISTRY, invoke
from .report import latest_run_id


def _approval(args):
    mode = args.approve if args.approve else "ask"
    return mode, bool(args.approve)


def _summary_code(result):
    if result.get("refused"):
        return 2
    if result.get("blocked"):
        return 3
    return 0


def _print_result(result):
    if result.get("dry_run"):
        print(f"DRY_RUN: yes")
        print(f"PLANNER: {result.get('planner')} (source {result.get('source')})")
        if result.get("note"):
            print(f"NOTE: {result.get('note')}")
        print(f"PLANNED_STEPS: {result.get('n')}")
        for i, step in enumerate(result["steps"], 1):
            print(f"  {i}. {step['tool']} {step['args']}")
        return
    print(f"RUN: {result.get('run_id')}")
    print(f"PLANNER: {result.get('planner')}")
    print(f"ITERS: {result.get('iters_used')}")
    print(f"BUDGET: {result.get('budget_used')}/{result.get('budget')}")
    print(f"GOAL_MET: {result.get('goal_met')}")
    print(f"REFUSED: {result.get('refused')}")
    print(f"BLOCKED: {result.get('blocked')}")
    print(f"REPORT: reports/runs/{result.get('run_id')}/report.md")
    for finding in result.get("findings", []):
        print(f"FINDING: {finding}")


def cmd_lab(args):
    if args.action == "spawn":
        if args.background:
            child = subprocess.Popen(
                [sys.executable, "-m", "rogueai", "lab", "serve"],
                cwd=os.getcwd(),
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            state = None
            for _ in range(60):
                if child.poll() is not None:
                    break
                state = labmod.read_state()
                if state:
                    break
                time.sleep(0.1)
            if not state:
                print("lab failed to become ready", file=sys.stderr)
                return 1
            print(json.dumps({"pid": state.get("pid"), "endpoints": state.get("endpoints")}, indent=2))
            return 0
        mgr = labmod.LabManager()
        mgr.spawn_all()
        print(json.dumps(mgr.endpoints(), indent=2))
        print("lab running; Ctrl-C to stop")
        try:
            while True:
                time.sleep(3600)
        except KeyboardInterrupt:
            pass
        finally:
            mgr.stop_all()
        return 0
    if args.action == "serve":
        mgr = labmod.LabManager()
        mgr.spawn_all()
        labmod.write_state(mgr.endpoints(), os.getpid())
        print(json.dumps(mgr.endpoints(), indent=2))
        print("lab serving; Ctrl-C to stop")
        try:
            while True:
                time.sleep(3600)
        except KeyboardInterrupt:
            pass
        finally:
            mgr.stop_all()
        return 0
    if args.action == "status":
        state = labmod.read_state()
        if not state:
            print("lab not started")
            return 0
        print(json.dumps(state, indent=2))
        return 0
    if args.action == "stop":
        state = labmod.read_state()
        if not state:
            print("lab not started")
            return 0
        labmod.stop_pid(state.get("pid"))
        labmod.clear_state()
        print("lab stopped")
        return 0
    return 1


def cmd_planner(args):
    if args.planner == "rule":
        plan = RulePlanner(args.goal).to_plan()
    else:
        try:
            plan = LLMPlanner(dry_run=args.dry_run).plan(args.goal)
        except PlannerConfigError as e:
            if args.dry_run:
                plan = RulePlanner(args.goal).to_plan()
                print(f"NOTE: {e}")
            else:
                print(str(e), file=sys.stderr)
                return 1
    print(f"PLANNER: {args.planner}")
    print(f"SOURCE: {plan.source}")
    if plan.note:
        print(f"NOTE: {plan.note}")
    print(f"PLANNED_STEPS: {len(plan.steps)}")
    for i, step in enumerate(plan.steps, 1):
        print(f"  {i}. {step.tool} {step.args}")
    return 0


def cmd_tools(args):
    if args.action == "list":
        for name, spec in REGISTRY.items():
            print(f"{name:12s} risk={spec.risk} yield={spec.yield_} meta={spec.meta} intents={','.join(sorted(spec.intents))}")
        return 0
    if args.action == "run":
        if args.tool not in REGISTRY:
            print(f"unknown tool {args.tool!r}; try 'rogueai tools list'", file=sys.stderr)
            return 1
        tool_args = {}
        for item in args.arg or []:
            k, sep, v = item.partition("=")
            if not sep:
                k, v = item, "true"
            tool_args[k] = v
        mgr = labmod.LabManager()
        mgr.spawn_all()
        state = AgentState(f"tools run {args.tool}", 1, 1, 60)
        ctx = SimpleNamespace(lab=mgr, state=state)
        try:
            obs = invoke(ctx, args.tool, tool_args)
        finally:
            mgr.stop_all()
        print(json.dumps(obs, indent=2, default=str))
        return 0
    return 1


def cmd_judge(args):
    obs = {"ok": args.ok, "evidence": args.evidence, "detail": {}}
    if args.tool:
        verdict = Judge().verdict(args.goal, Step(args.tool, {}), obs)
        print(json.dumps({"step": args.tool, "ok": verdict["ok"], "met_goal": verdict["met_goal"], "using": verdict["using"]}, indent=2))
        return 0
    met = rule_met(args.goal, [obs])
    print(json.dumps({"goal": args.goal, "met": met, "using": "rule"}, indent=2))
    return 0


def cmd_overseer(args):
    if args.action == "status":
        print("SAFETY POLICY")
        print("- target scope allowlist: loopback (127.0.0.1/8, ::1, localhost) + lab:// fixtures only; anything else = hard refuse")
        print("- approval modes: auto (policy allows), ask (impactful steps need --approve), never (impactful steps hard-blocked)")
        print(f"- blacklist: {sorted(policy.BLACKLISTED)}")
        print("- budgets: per-step action budget, max loop iterations, wall-clock timeout")
        return 0
    if args.action == "gate":
        decision = policy.gate(args.tool, args.target, args.mode, approved=args.approved)
        print(json.dumps(decision, indent=2))
        return 0
    return 1


def cmd_op(args):
    mode, approved = _approval(args)
    try:
        result = run_campaign(
            args.goal,
            planner_name=args.planner,
            mode=mode,
            approved=approved,
            dry_run=args.dry_run,
            max_iters=args.max_iters,
            budget=args.budget,
            timeout=args.timeout,
        )
    except PlannerConfigError as e:
        print(str(e), file=sys.stderr)
        return 1
    _print_result(result)
    return _summary_code(result)


def cmd_playbook(args):
    if args.action == "list":
        for name in list_playbooks():
            print(name)
        return 0
    if args.action == "run":
        try:
            data = load(args.name)
            plan = load_plan(args.name)
        except FileNotFoundError as e:
            print(str(e), file=sys.stderr)
            return 1
        mode, approved = _approval(args)
        result = run_campaign(
            data.get("goal", f"playbook:{args.name}"),
            planner_name="playbook",
            preset_plan=plan,
            mode=mode,
            approved=approved,
        )
        _print_result(result)
        return _summary_code(result)
    return 1


def cmd_report(args):
    run_id = args.run_id
    if not run_id and args.latest:
        run_id = latest_run_id()
    if not run_id:
        print("no campaign report found; run 'rogueai op' first", file=sys.stderr)
        return 1
    run_dir = os.path.join("reports", "runs", run_id)
    result_path = os.path.join(run_dir, "result.json")
    if not os.path.isfile(result_path):
        print(f"no report for run {run_id}", file=sys.stderr)
        return 1
    with open(result_path) as f:
        result = json.load(f)
    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print(f"RUN: {run_id}")
        print(f"GOAL: {result.get('goal')}")
        print(f"GOAL_MET: {result.get('goal_met')}")
        print(f"ITERS: {result.get('iters_used')}")
        print(f"BUDGET: {result.get('budget_used')}/{result.get('budget')}")
        print(f"REFUSED: {result.get('refused')}")
        print(f"BLOCKED: {result.get('blocked')}")
        print(f"REPORT: {os.path.join(run_dir, 'report.md')}")
    return 0


def cmd_demo():
    print("rogueai --demo (offline, authorized lab only)")
    result = run_campaign(
        "obtain vault flag from lab vault",
        planner_name="rule",
        mode="auto",
        approved=True,
        max_iters=12,
        budget=40,
        timeout=120,
    )
    print(f"ROGUEAI_DEMO goal={result['goal']}")
    print(f"ROGUEAI_DEMO chain={result['planner']}: port_probe(lab://vault) -> vault_read(lab://vault) -> write_note -> query_state")
    print(f"ROGUEAI_DEMO planner={result['planner']} mode=auto")
    print(f"ROGUEAI_DEMO scope=ok (loopback + lab:// fixtures only)")
    print(f"ROGUEAI_DEMO ran {result['iters_used']} iters")
    print(f"ROGUEAI_DEMO budget {result['budget_used']}/{result['budget']}")
    print(f"ROGUEAI_DEMO GOAL_MET: {result['goal_met']}")
    print(f"ROGUEAI_DEMO REPORT: reports/runs/{result['run_id']}/report.md")
    print("ROGUEAI_DEMO exit=0")
    return 0


def build_parser():
    parser = argparse.ArgumentParser(
        prog="rogueai",
        description="Agentic AI red-team & adversarial agent orchestration framework (authorized testing only).",
    )
    parser.add_argument("--version", action="version", version=f"rogueai {__version__}")
    parser.add_argument("--demo", action="store_true", help="run the offline end-to-end lab demo and exit 0")
    sub = parser.add_subparsers(dest="cmd")

    p_lab = sub.add_parser("lab", help="spawn/stop/status the built-in lab targets")
    p_lab.add_argument("action", choices=["spawn", "stop", "status", "serve"])
    p_lab.add_argument("--background", action="store_true", help="spawn the lab as a background process")
    p_lab.set_defaults(func=cmd_lab)

    p_planner = sub.add_parser("planner", help="print a plan for a goal (no execution)")
    p_planner.add_argument("--goal", required=True)
    p_planner.add_argument("--planner", choices=["rule", "llm"], default="rule")
    p_planner.add_argument("--dry-run", action="store_true")
    p_planner.set_defaults(func=cmd_planner)

    p_tools = sub.add_parser("tools", help="inspect and invoke agent tools")
    p_tools.add_argument("action", choices=["list", "run"])
    p_tools.add_argument("tool", nargs="?")
    p_tools.add_argument("--arg", action="append", metavar="K=V")
    p_tools.set_defaults(func=cmd_tools)

    p_judge = sub.add_parser("judge", help="evaluate whether evidence achieved a goal")
    p_judge.add_argument("--goal", required=True)
    p_judge.add_argument("--evidence", required=True)
    p_judge.add_argument("--tool")
    p_judge.add_argument("--ok", action="store_true", default=True)
    p_judge.set_defaults(func=cmd_judge)

    p_ov = sub.add_parser("overseer", help="inspect approval gates and policy")
    p_ov.add_argument("action", choices=["status", "gate"])
    p_ov.add_argument("--tool")
    p_ov.add_argument("--target")
    p_ov.add_argument("--mode", choices=policy.MODES, default="ask")
    p_ov.add_argument("--approved", action="store_true")
    p_ov.set_defaults(func=cmd_overseer)

    p_op = sub.add_parser("op", help="orchestrate a full autonomous campaign")
    p_op.add_argument("--goal", required=True)
    p_op.add_argument("--planner", choices=["rule", "llm"], default="rule")
    p_op.add_argument("--approve", nargs="?", const="ask", choices=policy.MODES)
    p_op.add_argument("--dry-run", action="store_true")
    p_op.add_argument("--max-iters", type=int, default=12)
    p_op.add_argument("--budget", type=int, default=40)
    p_op.add_argument("--timeout", type=float, default=300.0)
    p_op.set_defaults(func=cmd_op)

    p_pb = sub.add_parser("playbook", help="list or run attack playbooks")
    p_pb.add_argument("action", choices=["list", "run"])
    p_pb.add_argument("name", nargs="?")
    p_pb.add_argument("--approve", nargs="?", const="ask", choices=policy.MODES)
    p_pb.set_defaults(func=cmd_playbook)

    p_rep = sub.add_parser("report", help="show a campaign report")
    p_rep.add_argument("--run-id")
    p_rep.add_argument("--latest", action="store_true")
    p_rep.add_argument("--json", action="store_true")
    p_rep.set_defaults(func=cmd_report)

    return parser


def main(argv=None):
    if argv is None:
        argv = sys.argv[1:]
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.demo:
        return cmd_demo()
    if not getattr(args, "cmd", None):
        parser.print_help()
        return 1
    return args.func(args)