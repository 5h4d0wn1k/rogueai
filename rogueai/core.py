RISK_LOW = 1
RISK_MEDIUM = 2
RISK_HIGH = 3

PROGRESS_MARKERS = ("FLAG{", "AUTH_SUCCESS", "XSS_ECHO", "ITEM_FOUND", "KNOCK_OK", "fixture-present")


def observation(ok, evidence, detail=None):
    return {"ok": bool(ok), "evidence": str(evidence), "detail": dict(detail or {})}


def has_progress(obs):
    return bool(obs.get("ok")) and any(marker in str(obs.get("evidence", "")) for marker in PROGRESS_MARKERS)


class Step:
    def __init__(self, tool, args=None, risk=RISK_MEDIUM):
        self.tool = tool
        self.args = dict(args or {})
        self.risk = int(risk)

    def key(self):
        return (self.tool, str(sorted(self.args.items())))

    def to_dict(self):
        return {"tool": self.tool, "args": self.args, "risk": self.risk}


class Plan:
    def __init__(self, steps, goal, source, note=""):
        self.steps = list(steps)
        self.goal = goal
        self.source = source
        self.note = note

    def to_dict(self):
        return {
            "goal": self.goal,
            "source": self.source,
            "note": self.note,
            "n": len(self.steps),
            "steps": [s.to_dict() for s in self.steps],
        }


class AgentState:
    def __init__(self, goal, budget, max_iters, timeout):
        self.goal = goal
        self.budget = int(budget)
        self.max_iters = int(max_iters)
        self.timeout = int(timeout)
        self.notes = []
        self.observations = []
        self.verdicts = []
        self.plan = None

    def record(self, obs):
        self.observations.append(obs)

    def add_note(self, text):
        self.notes.append(str(text))

    def budget_used(self):
        return len(self.observations)

    def to_dict(self):
        return {
            "goal": self.goal,
            "budget": self.budget,
            "max_iters": self.max_iters,
            "timeout": self.timeout,
            "notes": list(self.notes),
            "iters": len(self.observations),
            "budget_used": self.budget_used(),
        }