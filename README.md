> **⚠️ EDUCATIONAL USE ONLY — AUTHORIZED TESTING ONLY.**
> This project exists for education, research, and **defense of systems you own
> or hold explicit written authorization to assess**. Unauthorized use is
> prohibited and may be illegal. Read [ETHICS.md](ETHICS.md) and
> [SCOPE.md](SCOPE.md) before use. Use at your own risk; **AS IS**, no warranty.
# rogueai
![tests](https://github.com/5h4d0wn1k/rogueai/actions/workflows/ci.yml/badge.svg) ![MIT](https://img.shields.io/badge/license-MIT-blue.svg)

Agentic AI red-team & adversarial agent orchestration framework. **Authorized lab testing only.**

RogueAI runs an autonomous planning loop — decide, execute, observe, reflect,
iterate — against **built-in lab targets** that you spawn on your own machine
(loopback only, ephemeral ports). It ships with a deterministic rule planner so
it works fully offline with zero dependencies; an OpenAI-compatible LLM planner
and judge are optional and guarded behind environment variables.

> Every impactful action passes through a human-in-the-loop safety gate.
> Non-loopback targets are **hard-refused** no matter what.

## IMPORTANT: Read before use.

This is an **authorized security testing and education** tool. It is designed to be
used exclusively against systems, networks, and hardware that **you own** or for which
you have **explicit written authorization** to test.

### Authorization Requirements

- Only test targets you own, your own accounts, or systems you have written permission
  to assess (scope, duration, and limits in writing).
- This tool defaults to **offline / simulation mode**. Any action that could affect a
  real system, emit radio signals, or contact a real network requires an explicit
  confirmation flag **and** membership of the configured LAB allowlist.
- The demo/harness functionality runs entirely on localhost, fixtures, or your own lab.

### Legal Framework

Unauthorized security testing is a crime in most jurisdictions, including:

- **Computer Fraud and Abuse Act (CFAA), 18 U.S.C. § 1030** (US) — unauthorized
  access to computers is a federal crime, punishable by up to 20 years imprisonment.
- **Wiretap Act (18 U.S.C. § 2511)** (US) — intercepting electronic communications
  without consent is illegal.
- **EU Directive 2013/40/EU on attacks against information systems** — criminalises
  illegal access and interference.
- **State / local computer-crime statutes** — nearly all jurisdictions criminalise
  unauthorised access, data theft, or network disruption.
- **RF regulatory law** — transmitting on ISM bands without the appropriate
  authorisation may violate terms of your licence/regulatory regime in your country.

### Acceptable Use

- Learning and coursework in a controlled lab environment.
- Authorised penetration testing and red/blue-team exercises with written scope.
- Security research on systems you own.
- Building defensive detections and hardening your own infrastructure.

### Prohibited Use

- **Any** unauthorised access, interception, or disruption.
- Use against third-party networks, devices, or accounts at any time.
- Removing or weakening the safety gates, allowlists, or legal notices.
- Any activity that violates applicable law.

### No Warranty

This software is provided "AS IS", without warranty of any kind, express or
implied, including but not limited to the warranties of merchantability, fitness
for a particular purpose, and non-infringement. **In no event shall the authors or
copyright holders be liable** for any claim, damages or other liability arising
from, out of, or in connection with the software or the use or other dealings in
the software. **You are solely responsible for how you use this tool.**

### Responsible Disclosure

If you discover real vulnerabilities while learning with this tool, follow
responsible disclosure:

1. Report privately to the affected vendor/owner.
2. Give a reasonable remediation window.
3. Do not exploit beyond proof of concept.
4. Only publish with the vendor's consent.

---

## Quickstart

Zero dependencies. Python 3.9+.

```bash
# from the repo root
python3 -m pip install -e .        # optional; exposes the `rogueai` console script
python3 -m rogueai --help
python3 -m rogueai --demo           # offline, exits 0, real proof output
python3 -m unittest discover -s tests
```

Equivalently, after `pip install -e .` the `rogueai` console script works:

```bash
rogueai --demo
rogueai lab status
```

## Architecture

| module | role |
| --- | --- |
| `rogueai/lab*.py` | built-in lab targets (vuln HTTP app, SSH/knock sim, open MQTT broker, fixture vault) |
| `rogueai/tools.py` | agent toolkit bound to real engines (`dyn_sqli`, `xss`, `port_probe`, `mqtt_subs`, `vault_read`, `cred_spray` + meta tools). Every tool returns a structured observation `{ok, evidence, detail}` |
| `rogueai/planner.py` | planning loop core — `rule` (deterministic, offline) and `llm` (optional, env-guarded) |
| `rogueai/judge.py` | per-step verdict + final goal-met (rule-based; LLM judge optional-guarded) |
| `rogueai/policy.py`, `rogueai/scope.py` | the overseer: target scope allowlist, tool blacklist, approval modes, budgets |
| `rogueai/op.py` | orchestrates a full autonomous campaign, writes JSONL audit + JSON/Markdown report |
| `rogueai/playbooks/`, `rogueai/playbook.py` | attack playbooks (recon→enum→exploit→exfil chains) |

Every campaign lands in `reports/runs/<id>/`: `audit.jsonl` (every step: tool,
args, observation, verdict), `plan.json`, `result.json`, `report.json`,
`report.md` (includes a MITRE-style mapping stub), and `evidence/`.

## Safety gates (overseer)

1. **Target scope allowlist** — only `127.0.0.1/8`, `::1`, `localhost` and
   `lab://*` fixtures. Any other target = **hard refuse** (exit 2), even with
   `--approve`. Enforcement happens twice: policy gate **and** the tool engine.
2. **Approval modes** (`--approve auto|ask|never`): `auto` follows the policy
   allowlist; `ask` requires an explicit `--approve` for every impactful step
   (blocked = exit 3); `never` hard-blocks impactful and blacklisted tools.
3. **Tool blacklist** — `cred_spray` is always considered impactful.
4. **Action budget** — max tool executions per campaign (default 40).
5. **Loop bound** — max iterations (default 12) and a wall-clock timeout.
6. Blacklisted/impactful tooling only ever runs against the lab fixtures.

## CLI

```bash
rogueai lab spawn|stop|status            # built-in lab targets on loopback
rogueai planner --goal G --planner rule  # print a plan, no execution
rogueai planner --goal G --planner llm --dry-run
rogueai tools list
rogueai tools run <tool> --arg k=v --arg k2=v2
rogueai judge --goal G --evidence "..."
rogueai overseer status
rogueai overseer gate --tool T --target H --mode auto
rogueai op --goal "G" --planner rule --approve auto
rogueai op --goal "G" --planner llm --dry-run   # prints n planned steps, no side effects
rogueai playbook list
rogueai playbook run vault --approve auto
rogueai report --latest
rogueai --demo
```

Example campaign (auto-run, offline):

```bash
rogueai op --goal "obtain vault flag from lab vault" --planner rule --approve auto
```

The agent autonomously walks recon → vault → flag (2 iterations), writes the
JSONL audit, and renders the final report under `reports/runs/<id>/`.

## Live Lab Test Plan

Against your **own lab only**. Spawn the built-in fixtures, then run the agent.

```bash
python3 -m rogueai lab spawn --background
python3 -m rogueai op --goal "obtain vault flag from lab vault" --planner rule --approve auto
python3 -m rogueai report --latest
python3 -m rogueai lab stop
```

Expected proof output for this repo's fixture vault:

```
RUN: <id>
PLANNER: rule
ITERS: 2
BUDGET: 2/40
GOAL_MET: True
REFUSED: False
BLOCKED: False
REPORT: reports/runs/<id>/report.md
FINDING: FLAG{vault-rogueai-5h4d0wn1k}
```

You can extend to the other fixtures, e.g. with `--goal "validate default
credentials on lab ssh"`, `--goal "extract the database flag with sqli"`, or
`--goal "read open mqtt flag from the lab broker"` (use `--approve auto`).

## Metrics

See [METRICS.md](METRICS.md) for measured runs (iterations, budget, goal-met,
test counts, timings).

## Development

- Stdlib only. `python3 -m py_compile` on every changed file.
- Tests: `python3 -m unittest discover -s tests` (currently 132 green).
- Never weaken the safety gates, scope allowlist, or legal text. Placeholders only.
- See `CONTRIBUTING.md` (DCO sign-off `git commit -s`) and `SECURITY.md`.

## License

MIT — see LICENSE. This project ships a legal kit (`SECURITY.md`,
`CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, `AUTHORS`). Authorized-use only.

## Contributing
See [CONTRIBUTING.md](CONTRIBUTING.md).
