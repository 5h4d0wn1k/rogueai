import os
import json

from .core import RISK_MEDIUM, Plan, Step
from .tools import REGISTRY

PLAYBOOKS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "playbooks")


def list_playbooks():
    names = []
    for entry in sorted(os.listdir(PLAYBOOKS_DIR)):
        if entry.endswith(".json"):
            names.append(entry[:-5])
    return names


def load(name):
    path = os.path.join(PLAYBOOKS_DIR, f"{name}.json")
    if not os.path.isfile(path):
        raise FileNotFoundError(f"playbook {name!r} not found; available: {', '.join(list_playbooks())}")
    with open(path) as f:
        return json.load(f)


def load_plan(name):
    data = load(name)
    steps = []
    for item in data["chain"]:
        tool = item["tool"]
        args = dict(item.get("args") or {})
        risk = REGISTRY[tool].risk if tool in REGISTRY else RISK_MEDIUM
        steps.append(Step(tool, args, risk))
    goal = data.get("goal", f"playbook:{name}")
    return Plan(steps, goal, f"playbook:{name}", note=data.get("note", ""))


def chain_order(data):
    return [item["tool"] for item in data["chain"]]