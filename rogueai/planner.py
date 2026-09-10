import json
import os
import re
import urllib.parse
import urllib.request

from .core import PROGRESS_MARKERS, RISK_LOW, Plan, Step
from .tools import REGISTRY

STOPWORDS = {
    "the", "a", "an", "and", "or", "of", "to", "in", "on", "for", "with",
    "from", "at", "by", "is", "are", "be", "was", "were", "have", "has",
    "this", "that", "their", "our", "you", "your", "my", "me", "we", "via",
    "own", "owned", "authorized", "authorisation", "authorization", "testing",
    "against", "full", "please", "get", "obtain", "read", "find", "list",
    "lab", "default", "use", "only", "now", "into", "such", "any",
}

HOST_RE = re.compile(
    r"(?<![\w@])(?:(?:\d{1,3}\.){3}\d{1,3}|"
    r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+)"
    r"(?::\d+)?",
    re.I,
)

LAB_HINT_RE = re.compile(r"lab(?:://)?([a-z-]+)", re.I)


def goal_words(goal):
    tokens = re.findall(r"[a-zA-Z0-9]+", str(goal or "").lower())
    return {t for t in tokens if len(t) > 1 and t not in STOPWORDS}


def detect_host_targets(goal):
    seen = []
    for m in HOST_RE.finditer(str(goal or "")):
        host = m.group(0)
        low = host.lower()
        if low.startswith("lab://") or low.startswith("lab."):
            continue
        if low not in seen:
            seen.append(low)
    return seen


def detect_lab_hint(goal):
    m = LAB_HINT_RE.search(str(goal or ""))
    if not m:
        return None
    name = m.group(1)
    if name in ("http", "ssh", "mqtt", "vault"):
        return name
    return None


def matched_tools(goal):
    words = goal_words(goal)
    return [
        name for name, spec in REGISTRY.items()
        if spec.intents and (spec.intents & words) and not spec.meta
    ]


class RulePlanner:
    def __init__(self, goal):
        self.goal = goal
        self.steps = self._build()
        self._cursor = 0
        self.attempted = set()
        self.exhausted = set()
        self.last_obs = None

    def to_plan(self):
        return Plan(self.steps, self.goal, "rule", note="deterministic intent-matched plan")

    def _key_for_goal(self, name):
        spec = REGISTRY[name]
        words = goal_words(self.goal)
        score = len(spec.intents & words)
        return (-score, -spec.yield_, name)

    def _build(self):
        steps = []
        for host in detect_host_targets(self.goal):
            steps.append(Step("port_probe", {"target": host}, RISK_LOW))
        matched = matched_tools(self.goal)
        matched.sort(key=self._key_for_goal)
        done_recon = set()
        for name in matched:
            spec = REGISTRY[name]
            for prereq in spec.prereqs:
                if prereq not in done_recon and prereq.startswith("port_probe:"):
                    steps.append(Step("port_probe", {"target": prereq.split(":", 1)[1]}, RISK_LOW))
                    done_recon.add(prereq)
            hint = spec.hint
            args = {"target": f"lab://{hint}"} if hint else {}
            steps.append(Step(name, args, spec.risk))
        if not steps:
            steps.append(Step("port_probe", {"target": "lab://all"}, RISK_LOW))
        steps.append(Step("write_note", {"note": f"goal: {self.goal}"}, RISK_LOW))
        steps.append(Step("read_plan", {}, RISK_LOW))
        steps.append(Step("query_state", {}, RISK_LOW))
        return steps

    def next_step(self, state=None):
        while self._cursor < len(self.steps):
            step = self.steps[self._cursor]
            self._cursor += 1
            if step.key() in self.attempted or step.tool in self.exhausted:
                continue
            return step
        return self.best_candidate()

    def best_candidate(self):
        words = goal_words(self.goal)
        candidates = [
            name for name, spec in REGISTRY.items()
            if spec.intents and (spec.intents & words) and not spec.meta
            and name not in self.exhausted
        ]
        candidates.sort(key=self._key_for_goal)
        if candidates:
            name = candidates[0]
            args = {"target": f"lab://{REGISTRY[name].hint}"} if REGISTRY[name].hint else {}
            return Step(name, args, REGISTRY[name].risk)
        return Step("query_state", {}, RISK_LOW)

    def observe(self, step, obs):
        self.attempted.add(step.key())
        self.last_obs = obs
        if any(marker in str(obs.get("evidence", "")) for marker in PROGRESS_MARKERS if obs.get("ok")):
            self.exhausted.add(step.tool)

    def reflect(self, obs=None):
        obs = obs or self.last_obs or {}
        ok = bool(obs.get("ok"))
        evidence = str(obs.get("evidence", ""))
        if ok and any(marker in evidence for marker in PROGRESS_MARKERS):
            return "reflection: progress marker observed, outcome strengthens plan"
        if not ok:
            return "reflection: step did not succeed, alternate candidates considered"
        return "reflection: step completed without new progress markers"


class PlannerConfigError(Exception):
    pass


class LLMPlanner:
    def __init__(self, dry_run=False):
        self.base = os.environ.get("ROGUEAI_LLM_BASE", "").strip().rstrip("/")
        self.key = os.environ.get("ROGUEAI_LLM_KEY", "").strip()
        self.dry_run = bool(dry_run)
        self.available = bool(self.base and self.key)

    def _fallback(self, goal):
        return RulePlanner(goal).to_plan()

    def plan(self, goal):
        if not self.available:
            if self.dry_run:
                fb = self._fallback(goal)
                return Plan(
                    fb.steps, goal, "llm:dry-run(fallback=rule)",
                    note="ROGUEAI_LLM_BASE/ROGUEAI_LLM_KEY unset; deterministic rule planner used (no LLM, no execution).",
                )
            raise PlannerConfigError(
                "rogueai --planner llm requires ROGUEAI_LLM_BASE and ROGUEAI_LLM_KEY env vars "
                "pointing at an OpenAI-compatible endpoint. Set them and retry, "
                "or use --planner rule for the fully-offline deterministic planner."
            )
        prompt = (
            "You are the planning module of an authorized red-team agent. "
            "Targets are hard-limited to the local lab (127.0.0.1 and lab:// fixtures). "
            "Choose steps only from this toolbox and only for the local lab:\n"
            + "\n".join(f"- {name}: {spec.blurb}" for name, spec in REGISTRY.items())
            + "\nRespond with ONLY JSON of the form "
            '{"steps":[{"tool":"<name>","args":{...}}]} using exactly one of the listed tools per step.'
        )
        payload = json.dumps({
            "model": os.environ.get("ROGUEAI_LLM_MODEL", "gpt-4o-mini"),
            "messages": [
                {"role": "system", "content": prompt},
                {"role": "user", "content": f"goal: {goal}\nShip a short plan for the local lab."},
            ],
            "temperature": 0.0,
        }).encode("utf-8")
        req = urllib.request.Request(
            f"{self.base}/chat/completions", data=payload,
            headers={"Content-Type": "application/json", "Authorization": f"Bearer {self.key}"},
        )
        try:
            with urllib.request.urlopen(req, timeout=30) as r:
                data = json.loads(r.read().decode("utf-8"))
        except Exception as e:
            raise PlannerConfigError(f"LLM planner request failed: {e}")
        content = data["choices"][0]["message"]["content"]
        steps_json = json.loads(content)
        steps = []
        for item in steps_json["steps"]:
            tool = item.get("tool")
            if tool not in REGISTRY:
                raise PlannerConfigError(f"LLM planner produced unknown tool {tool!r}")
            args = dict(item.get("args") or {})
            steps.append(Step(tool, args, REGISTRY[tool].risk))
        if not steps:
            raise PlannerConfigError("LLM planner produced an empty plan")
        return Plan(steps, goal, "llm", note="LLM-generated plan")


class PresetPlanner:
    def __init__(self, plan):
        self.plan = plan
        self._i = 0

    def next_step(self, state=None):
        while self._i < len(self.plan.steps):
            step = self.plan.steps[self._i]
            self._i += 1
            return step
        return None

    def observe(self, step, obs):
        pass

    def reflect(self, obs=None):
        return "reflection: preset playbook, planner mirrors supplied chain"