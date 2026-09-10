import json
import os
import time
from types import SimpleNamespace

from . import core, policy
from .core import Plan, Step, observation
from .judge import Judge
from .lab import LabManager
from .planner import LLMPlanner, PlannerConfigError, PresetPlanner, RulePlanner
from .report import render_report, write_latest
from .tools import REGISTRY, invoke

RUNS_DIR = os.path.join("reports", "runs")


def _run_id():
    return time.strftime("%Y%m%d-%H%M%S") + f"-{os.getpid()}"


class AuditWriter:
    def __init__(self, run_dir):
        self.path = os.path.join(run_dir, "audit.jsonl")
        self._f = open(self.path, "a", encoding="utf-8")

    def _row(self, kind, **fields):
        row = {"ts": time.time(), "kind": kind}
        row.update(fields)
        self._f.write(json.dumps(row) + "\n")
        self._f.flush()

    def info(self, **fields):
        self._row("info", **fields)

    def step(self, iters, step, target, gate, obs, verdict):
        self._row(
            "step",
            iter=iters,
            tool=step.tool,
            args=step.args,
            target=target,
            gate=gate,
            obs=obs,
            verdict=verdict,
        )

    def refuse(self, step, target, g):
        self._row("refuse", tool=step.tool, target=target, reason=g.get("reason"))

    def block(self, step, target, g):
        self._row("block", tool=step.tool, target=target, reason=g.get("reason"))

    def finish(self, result, plan):
        self._row("summary", result=result, plan_source=plan.source if plan else None)

    def close(self):
        self._f.close()


def _target_for(step):
    if step.args.get("target"):
        return step.args["target"]
    hint = REGISTRY[step.tool].hint if step.tool in REGISTRY else None
    return f"lab://{hint}" if hint else "lab://all"


def _plan_from(planner_name, goal, preset_plan):
    if planner_name == "rule":
        return RulePlanner(goal).to_plan()
    if planner_name == "llm":
        return LLMPlanner(dry_run=False).plan(goal)
    if planner_name == "playbook":
        return preset_plan
    raise PlannerConfigError(f"unknown planner {planner_name!r}")


def _planner_instance(planner_name, goal, preset_plan):
    if planner_name == "rule":
        return RulePlanner(goal)
    if planner_name == "llm":
        return LLMPlanner(dry_run=False)
    if planner_name == "playbook":
        return PresetPlanner(preset_plan)
    raise PlannerConfigError(f"unknown planner {planner_name!r}")


def run_campaign(goal, planner_name="rule", mode="ask", approved=False, dry_run=False,
                 max_iters=12, budget=40, timeout=300, run_id=None, lab=None, preset_plan=None):
    run_id = run_id or _run_id()
    run_dir = os.path.join(RUNS_DIR, run_id)
    evidence_dir = os.path.join(run_dir, "evidence")
    os.makedirs(evidence_dir, exist_ok=True)

    if dry_run:
        if planner_name == "llm":
            planner = LLMPlanner(dry_run=True)
            maybe_plan = planner.plan(goal)
        else:
            maybe_plan = RulePlanner(goal).to_plan()
        with open(os.path.join(run_dir, "plan.json"), "w") as f:
            json.dump(maybe_plan.to_dict(), f, indent=2)
        return {
            "dry_run": True,
            "goal": goal,
            "planner": planner_name,
            "source": maybe_plan.source,
            "note": maybe_plan.note,
            "n": len(maybe_plan.steps),
            "steps": [s.to_dict() for s in maybe_plan.steps],
            "run_id": run_id,
            "run_dir": run_dir,
        }

    plan = _plan_from(planner_name, goal, preset_plan)
    planner = _planner_instance(planner_name, goal, preset_plan)
    state = core.AgentState(goal, budget, max_iters, timeout)
    state.plan = plan

    lab = lab or LabManager()
    if not lab.spawned:
        lab.spawn_all()
    ctx = SimpleNamespace(lab=lab, state=state)

    audit = AuditWriter(run_dir)
    audit.info(goal=goal, planner=plan.source, mode=mode, approved=approved,
               budget=budget, max_iters=max_iters, timeout=timeout,
               plan=[s.to_dict() for s in plan.steps])

    started = time.time()
    result = {
        "goal": goal,
        "planner": plan.source,
        "mode": mode,
        "goal_met": False,
        "refused": False,
        "blocked": False,
        "timed_out": False,
        "iters_used": 0,
        "budget": budget,
        "budget_used": 0,
        "max_iters": max_iters,
    }

    iters = 0
    while True:
        elapsed = time.time() - started
        if elapsed > timeout:
            result["timed_out"] = True
            break
        if iters >= max_iters:
            break
        if state.budget_used() >= budget:
            break
        step = planner.next_step(state)
        if step is None:
            break
        target = _target_for(step)
        g = policy.gate(step.tool, target, mode, approved)
        if g["decision"] == "refuse":
            result["refused"] = True
            audit.refuse(step, target, g)
            break
        if g["decision"] == "block":
            result["blocked"] = True
            audit.block(step, target, g)
            break
        try:
            obs = invoke(ctx, step.tool, step.args)
        except Exception as e:
            obs = observation(False, f"tool-error:{e}")
        state.record(obs)
        verdict = Judge().verdict(goal, step, obs)
        state.verdicts.append(verdict)
        planner.observe(step, obs)
        audit.step(iters, step, target, g, obs, verdict)
        iters += 1
        with open(os.path.join(evidence_dir, f"step-{iters:02d}-{step.tool}.txt"), "w") as f:
            f.write(str(obs.get("evidence", "")))
            f.write("\n")
            f.write(json.dumps(obs.get("detail", {})))
        if Judge().met(goal, state.observations):
            result["goal_met"] = True
            break

    result["iters_used"] = iters
    result["budget_used"] = state.budget_used()
    result["notes"] = list(state.notes)
    result["findings"] = [str(o.get("evidence", "")) for o in state.observations if o.get("ok")]
    result["run_id"] = run_id
    result["run_dir"] = run_dir
    audit.finish(result, plan)
    audit.close()

    with open(os.path.join(run_dir, "result.json"), "w") as f:
        json.dump(result, f, indent=2)
    with open(os.path.join(run_dir, "plan.json"), "w") as f:
        json.dump(plan.to_dict(), f, indent=2)

    render_report(run_dir, result, plan)
    write_latest(run_id)
    return result


def demo_result():
    return run_campaign(
        "obtain vault flag from lab vault",
        planner_name="rule",
        mode="auto",
        approved=True,
        max_iters=12,
        budget=40,
        timeout=120,
    )