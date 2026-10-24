# WARDEN Sentinel Network

[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/Python-3.12-3776AB.svg?logo=python&logoColor=white)](pyproject.toml)
[![uAgents](https://img.shields.io/badge/uAgents-0.26.1-FFD000.svg)](https://fetch.ai)
[![Protocol](https://img.shields.io/badge/Protocol-AgentChatProtocol_v0.3.0-blueviolet.svg)](https://fetch.ai)
[![ASI:One Cards](https://img.shields.io/badge/ASI:One_Cards-Protocol_v1-4E79A7.svg)](docs/INTERACTIVE_CARDS.md)

A security-control layer for AI-agent file actions, reachable through ASI:One once it is deployed.
Every request goes through one fixed chain:

```
User (ASI:One chat) → Intent Agent → Risk Analyst → Policy Guard → approval (card or text)
                    → Restricted Executor → Auditor → verified result (text + result card)
```

- **Intent Agent** turns the message into validated, versioned action proposals. It has no authority.
- **Risk Analyst** assesses each exact action (destructive impact, protected or sensitive targets,
  scope, ambiguity, traversal, symlinks, overwrite, injected instructions) and returns signed,
  advisory evidence. It never authorizes or blocks anything.
- **Policy Guard** (deterministic rules) is the only authority: `ALLOW`, `BLOCK` or `REQUIRE_APPROVAL`.
- **Approval** is bound to the action id, the canonical action digest, the target state, an expiry,
  the requester and the permitted approvers. Card clicks and typed commands take the same path.
- **Restricted Executor** runs only the exact authorized operation inside the synthetic workspace.
- **Auditor** independently checks the real outcome; `VERIFIED` needs positive evidence, anything
  else is `UNVERIFIED` or `FAILED`.

Outcomes are reported as `VERIFIED`, `UNVERIFIED`, `FAILED`, `BLOCKED`, `AWAITING_APPROVAL`,
`REJECTED` or `EXPIRED`, with a per-stage workflow trace.

## Fetch-A-Thon 3.0 Submission Deliverables

| Deliverable | Location / Status | Description |
|---|---|---|
| **Problem & Architecture** | [Problem & Architecture](#problem--architecture) | Deterministic policy containment, exact-action cryptographic binding, and independent outcome auditing for AI file operations |
| **Public GitHub Repository** | `https://github.com/<username>/WARDEN` (pending publication) | Clean, Apache-2.0 open-source candidate with 650+ automated tests |
| **Agentverse Public Agent** | Registered as `warden-verification-agent` (pending live registration) | Hosted agent with ACP v0.3.0 and Interactive Cards v1 |
| **ASI:One Interaction Transcript** | `https://asi1.ai/...` (captured after live deployment) | End-to-end conversation showing harmless read, card approval, and blocked target |
| **Demo Walkthrough Video** | `https://...` (pending final link) | 12-scenario security demonstration and ASI:One interactive review card workflow |


## Status (2026-10-24, branch `integration/sentinel-final`)

| | |
|---|---|
| Implemented and locally tested | Everything above; durable approval state and restart recovery; independent-approver mode; hash-chained audit log; hosted entry point with health route; Interactive Cards; presentation layer (badges, reports, traces). The automated suite passes, the security demo passes, and a live multi-process test runs WARDEN, a Risk Analyst agent and an Auditor agent over real uAgents envelopes on loopback. |
| Not verified | Container build (no Docker on the development machine), any external deployment, Agentverse registration, any real ASI:One conversation, card rendering and button behaviour in ASI:One, the sender identity ASI:One uses. |

See [docs/DEPLOYMENT_READINESS.md](docs/DEPLOYMENT_READINESS.md) for the handoff checklist and residual risks.

## Quick start (Windows PowerShell)

Requires Python 3.10+ (3.12 recommended). No accounts or API keys are needed for local use.

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\setup.ps1   # venv, dependencies, .env, local identity, tests, doctor
.\scripts\demo.ps1                                              # offline security demonstration (12 independent checks)
.\scripts\test.ps1                                              # full test suite
.\scripts\doctor.ps1                                            # configuration and readiness diagnostics
.\scripts\run.ps1                                               # local agent on 127.0.0.1
```

Any platform, manually:

```
python -m venv .venv && .venv/bin/python -m pip install -e ".[dev]"      # Windows: .venv\Scripts\python.exe
.venv/bin/python -m pytest
.venv/bin/python demo/run_demo.py
.venv/bin/python -m warden.doctor
```

Hosted mode (`python -m warden.hosting.server`), Agentverse registration and the container image
are described in [docs/HOSTING.md](docs/HOSTING.md).

## Configuration

Settings come from the environment, with the repository-root `.env` merged in (real environment
variables win). `.env.example` documents every variable; the most important:

| Variable | Default | Purpose |
|---|---|---|
| `AGENT_SEED` | none (required to run) | WARDEN's identity. Secret; never commit it |
| `WARDEN_WORKSPACE_ROOT` | `./temp_workspace` | The only directory actions may touch |
| `WARDEN_APPROVAL_MODE` | `self` (hosted: must be set) | `independent`: only a configured approver other than the requester may approve |
| `WARDEN_APPROVER_ADDRESSES` | empty | Agent addresses allowed to approve |
| `WARDEN_STATE_DB` | unset = in memory (hosted: required) | Durable approvals, their one-time consumption, outcomes, processed message ids |
| `WARDEN_AUDIT_LOG` | `./logs/audit.jsonl` | Hash-chained audit trail |
| `WARDEN_APPROVAL_TTL_SECONDS` | `300` | Approval window |
| `WARDEN_RISK_ANALYST` | `local` | `local`, `remote` (separate agent) or `off` |
| `WARDEN_RISK_REQUIRED` | `false` | Without a valid assessment, changes need approval (`WDN-006`) |
| `WARDEN_REMOTE_AUDITOR` | `false` | Also require a signed attestation from the Auditor agent |
| `WARDEN_INTERACTIVE_CARDS` | off (hosted: on) | ASI:One Interactive Cards (presentation only) |

## Policy rules

| Id | Rule |
|---|---|
| `WDN-001` | Unsupported operation, or rename without destination: BLOCK |
| `WDN-002` | Invalid path or outside the workspace (traversal, absolute, symlink escape): BLOCK |
| `WDN-003` | Protected resource (`.env`, `production.env`, `secrets.json`, `credentials.json`, the demo marker): reading or changing it is BLOCKED |
| `WDN-004` | DELETE and RENAME: REQUIRE_APPROVAL |
| `WDN-005` | WRITE over an existing file: REQUIRE_APPROVAL; RENAME onto an existing file: BLOCK |
| `WDN-006` | With `WARDEN_RISK_REQUIRED`, a change without a valid risk assessment: REQUIRE_APPROVAL |
| `WDN-000` | Everything else that passed the checks (READ, CREATE of a new file): ALLOW |

## Documentation

- [docs/SENTINEL_NETWORK.md](docs/SENTINEL_NETWORK.md) — agents, contracts, communication, correlation, failure handling
- [docs/INTERACTIVE_CARDS.md](docs/INTERACTIVE_CARDS.md) — card protocol, security contract, implementation selection
- [docs/UIUX_INTEGRATION.md](docs/UIUX_INTEGRATION.md) — presentation layer and how the UI/UX workstream was integrated
- [docs/PERSISTENCE.md](docs/PERSISTENCE.md) — durable state, restart recovery, audit chain
- [docs/HOSTING.md](docs/HOSTING.md) — hosted architecture, endpoint exposure, container, registration, rollback
- [docs/DEPLOYMENT_READINESS.md](docs/DEPLOYMENT_READINESS.md) — verification evidence, residual risks, remaining steps
- [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md), [docs/SECURITY_HARDENING.md](docs/SECURITY_HARDENING.md) — threats and controls
- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md), [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md), [docs/INTEGRATION.md](docs/INTEGRATION.md)

Older audit records (`INITIAL_AUDIT`, `PHASE1_AUDIT`, `LOCAL_READINESS_AUDIT`,
`IDENTITY_AND_ENDPOINT_AUDIT`, `REQUIREMENTS_TRACEABILITY`) describe earlier states and are kept for history.

## Troubleshooting

| Symptom | Fix |
|---|---|
| `running scripts is disabled on this system` | `powershell -ExecutionPolicy Bypass -File .\scripts\setup.ps1` |
| `AGENT_SEED ... not configured` | `.\scripts\setup.ps1` (or `python -m warden.identity init`) |
| Hosted start: `WARDEN_APPROVAL_MODE must be set explicitly` | Set `independent` (with `WARDEN_APPROVER_ADDRESSES`) or `self` |
| Hosted start: `WARDEN_STATE_DB is required` | Point it at a file on persistent storage |
| `State database ... failed its integrity check` | WARDEN refuses to run with damaged approval state; restore or move the file |
| Doctor: `Audit log hash chain ... was modified` | The audit log was edited or truncated; investigate before continuing |
| Doctor: `Port 8000 ... in use` | Another process owns it; use `.\scripts\run.ps1 -Port 8001` |

## License

Apache License 2.0.
