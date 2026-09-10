# Metrics

Measured on Linux (Python 3.13), repo root, offline, single run each.

## Automated campaign (`rogueai op` / `--demo`)

Goal: `obtain vault flag from lab vault`, planner `rule`, mode `auto`.

| metric | value |
| --- | --- |
| iterations run | 2 |
| budget used | 2 / 40 |
| goal met | True |
| scope refusal | False |
| approval block | False |
| wall time (demo) | ~0.40 s |
| report written | `reports/runs/<id>/report.md` + `report.json` |
| evidence files | 2 |

Chain (deterministic): `port_probe(lab://vault)` → `vault_read(lab://vault)`
→ `write_note` → `query_state`. Flag recovered: `FLAG{vault-rogueai-5h4d0wn1k}`.

## Safety-gate checks (real assertions)

| gate | result |
| --- | --- |
| target `8.8.8.8` | hard refused (exit 2), zero steps executed |
| approval mode `ask` without `--approve` | blocked (exit 3), goal not met |
| approval mode `ask` with `--approve` | goal met |
| mode `never` on `cred_spray` | blocked |
| budget=1 | stops after 1 execution, not met |
| max_iters=1 | stops after 1 execution |
| LLM dry-run (`--planner llm --dry-run`) | prints n planned steps, 0 HTTP requests, fallback to rule planner when env unset |

## Tests

| metric | value |
| --- | --- |
| test methods | 132 |
| suite result | all green |
| suite wall time | ~40 s |
| test files | 10 |
| coverage areas | scope allowlist, policy/approval, lab fixtures, tool engine, planners, judge, orchestrator (op), playbook, report, CLI, demo |

## Toolset

| tool | risk | engine |
| --- | --- | --- |
| port_probe | low | TCP connect + banner |
| dyn_sqli | medium | boolean extraction, ~150 HTTP oracle requests for the 24-char fixture flag |
| xss | medium | payload echo detect |
| mqtt_subs | medium | minimal MQTT 3.1.1 client, bad-subscribe proof |
| cred_spray | high (blacklisted/impactful) | rate-limited, 24 attempts / 6 per fixture |
| vault_read | medium | fixture read + honeytoken trip |
| write_note / read_plan / query_state | low | meta |

(updated as features land — measured numbers only. Test counts & timings are
re-measured on every change and must stay green.)