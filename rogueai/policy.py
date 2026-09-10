from .core import RISK_MEDIUM
from .tools import REGISTRY
from . import scope

MODES = ("auto", "ask", "never")

BLACKLISTED = {"cred_spray"}


def tool_risk(name):
    spec = REGISTRY.get(name)
    return spec.risk if spec else RISK_MEDIUM


def _allow(tool):
    return {"decision": "allow", "tool": tool, "reason": "policy allows"}


def gate(tool, target, mode, approved=False):
    if not scope.safe(target):
        return {
            "decision": "refuse",
            "tool": tool,
            "reason": f"target [{target}] is outside the lab allowlist (loopback + lab:// fixtures only)",
        }
    mode = mode if mode in MODES else "ask"
    risk = tool_risk(tool)
    impactful = risk >= RISK_MEDIUM or tool in BLACKLISTED
    if mode == "never":
        if tool in BLACKLISTED or impactful:
            return {
                "decision": "block",
                "tool": tool,
                "reason": f"tool {tool} blocked by approval mode 'never'",
            }
        return _allow(tool)
    if mode == "auto":
        return _allow(tool)
    if impactful and not approved:
        return {
            "decision": "block",
            "tool": tool,
            "reason": f"approval required for {tool} (risk={risk}); rerun with --approve",
        }
    return _allow(tool)


def describe(mode):
    if mode == "auto":
        return "auto: actions allowed within policy allowlist"
    if mode == "never":
        return "never: impactful actions are hard-blocked"
    return "ask: impactful actions require explicit --approve"