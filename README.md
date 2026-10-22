# WARDEN: Autonomous Action-Verification System

> **Fetch-A-Thon 3.0** — *ASI:One Agent Challenge: From Intent to Action*

[![Python](https://img.shields.io/badge/Python-3.10%20%7C%203.11%20%7C%203.12-blue.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/License-Apache_2.0-green.svg)](LICENSE)
[![Tests](https://img.shields.io/badge/Tests-184%20Passed-success.svg)](tests/)
[![Protocol](https://img.shields.io/badge/Protocol-AgentChatProtocol%20v0.3.0-purple.svg)](https://uagents.fetch.ai/)

---

## 1. Executive Summary

Autonomous AI agents capable of understanding intent and taking actions represent the next evolution of intelligent systems. However, giving an LLM direct access to tools, APIs, and operating system primitives creates critical safety hazards: **agents execute destructive, unauthorized, or compromised actions merely because a probabilistic language model emits an instruction.**

**WARDEN** solves this fundamental flaw by decoupling action proposal from execution through a deterministic four-stage lifecycle:
1. **Proposal:** Untrusted agent or LLM (e.g., ASI:One `asi1-mini`) proposes structured actions.
2. **Deterministic Authorization:** Strict policy rules and canonical boundary enforcement grant or deny access independent of LLM claims.
3. **Controlled Execution:** A sandboxed executor enforces unforgeable cryptographic tokens (HMAC-SHA256) within a disposable workspace.
4. **Independent Outcome Verification:** An external auditor inspects actual physical environment state (e.g., cryptographic disk hashes) before and after execution to confirm ground truth.

---

## 2. Target Users & Real-World Impact

- **Enterprise AI Deployments:** Organizations delegating workspace management, CI/CD remediation, and autonomous operations to AI agents without risking system compromise.
- **ASI:One & Agentverse Users:** Individuals interacting with autonomous agents in conversational workflows who require verifiable boundaries against prompt injection and unauthorized modifications.
- **Developers & Security Teams:** Engineers seeking an auditable, fail-closed runtime security envelope for tool-augmented LLMs.

---

## 3. System Architecture & Lifecycle Pipeline

```
                    [ User / ASI:One Conversation ]
                                  │
                                  ▼
                [ Stage 1: Proposal (ASI:One Intent Engine) ]
                                  │
                                  ▼
      ┌────────────────────────────────────────────────────────┐
      │       Stage 2: Deterministic Policy Engine             │
      │  - Operation validation (READ/CREATE/WRITE/DELETE/...) │
      │  - Canonical path containment (no '..', drives, UNC)   │
      │  - Protected files (.env, secrets.json shielded)       │
      │  - Human-in-the-Loop pending approval for destructive   │
      └───────────────────────────┬────────────────────────────┘
                     ALLOW        │         BLOCK / AWAITING
            ┌─────────────────────┴──────────────────┐
            ▼                                        ▼
  [ Issue Cryptographic Token ]            [ Reject / Await Approval ]
            │
            ▼
┌────────────────────────────────────────────────────────┐
│         Stage 3: Restricted Sandbox Executor           │
│  - Validates HMAC-SHA256 authorization signature       │
│  - Executes file mutation inside disposable workspace  │
│  - Fail-closed error handling                          │
└───────────────────────────┬────────────────────────────┘
                            │
                            ▼
┌────────────────────────────────────────────────────────┐
│       Stage 4: Independent Outcome Verification        │
│  - Inspects physical disk state independently          │
│  - Validates file existence, deletion, and SHA256 hash │
│  - Structured immutable multi-state audit log          │
└────────────────────────────────────────────────────────┘
```

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for full architectural specifications.

---

## 4. Quick Start (Windows PowerShell)

Requires Python 3.10+ (3.12 recommended) and Git. No accounts or API keys are needed.

```powershell
git clone https://github.com/Zynx095/WARDEN.git
cd WARDEN
powershell -ExecutionPolicy Bypass -File .\scripts\setup.ps1   # venv, dependencies, .env, identity, tests, doctor
.\scripts\demo.ps1                                              # offline security demonstration
.\scripts\run.ps1                                               # start the local agent (127.0.0.1 only)
```

`setup.ps1` is safe to rerun: it never overwrites an existing `.env`, identity or workspace.

| Command | Purpose |
|---|---|
| `.\scripts\setup.ps1` | Create `.venv`, install from `pyproject.toml`, create `.env` from the template if missing, generate an agent identity if none exists, run tests and diagnostics (`-SkipTests`, `-NoOptional`) |
| `.\scripts\doctor.ps1` | Diagnose config, identity, dependencies, Git secret hygiene, workspace, port, integration readiness (`-Tests` also runs pytest). Never prints secrets |
| `.\scripts\test.ps1` | Compile everything and run pytest; extra arguments pass through (`-k acp -x`) |
| `.\scripts\demo.ps1` | Run the deterministic demo in `temp_demo_workspace`; exits non-zero if any independent check fails |
| `.\scripts\run.ps1` | Start the agent. `-ShowAddress` prints the public address and exits; `-Port 8001`; `-Mailbox` opts in to mailbox mode |

Manual equivalents with the project interpreter: `.\.venv\Scripts\python.exe -m pytest`, `-m warden.doctor`,
`-m warden.identity address`, `demo\run_demo.py`, `-m warden.agents.run_agent`.

### What the demo shows

Everything happens in a disposable workspace of synthetic files, offline, through the normal pipeline:
workspace inspection; a "clean up temporary files" request; deterministic policy evaluation (`WDN-004`);
a safe `CREATE` that is authorized, executed and verified; human approval of the held deletions; an
attempt to delete a protected config file blocked by `WDN-003` before execution (even with a
prompt-injection reason); independent verification with plain `os`/`hashlib`; and a persisted JSONL
audit record. 12 checks must pass.

---

## 5. Implementation Status

Three levels are kept apart on purpose.

**Implemented and locally tested** (automated tests, mocks for external services; 184 tests):

- Deterministic policy engine, canonical workspace containment, protected files (`WDN-001..004`).
- HMAC-SHA256 authorization tokens bound to action, target, workspace and expiry; fresh random key per process (persistence is not needed, see Configuration).
- Restricted executor, independent outcome auditor, JSONL audit trail.
- Approval workflow: destructive actions wait for approval; only the requester (or a configured approver) can approve; replays fail.
- Agent Chat Protocol 0.3.0 handlers: errors contained, messages capped at 4000 characters, workspace paths scrubbed from replies.
- Stable agent identity: the same `AGENT_SEED` gives the same address on every start, verified equal to the installed uAgents derivation.
- Repo-root `.env` loading independent of the working directory; strict validation; placeholder and weak secrets rejected.
- Local-only runtime bound to `127.0.0.1`; one-command Windows setup, diagnostics and demo.

**Implemented, not verified** (needs an Agentverse account; nothing below has been run):

- Mailbox mode (`-Mailbox`), external endpoint mode (`--endpoint`), ASI:One LLM intent parsing (`ASI_ONE_API_KEY`).

**Not done** (external): Agentverse mailbox provisioning, agent registration and discovery, any live ASI:One conversation, shared chat URL, demo video. See [docs/INTEGRATION.md](docs/INTEGRATION.md) for the exact steps and the distinction between local-only, mailbox, endpoint, discovery and ASI:One.

---

## 6. Configuration

Settings are read from the process environment, with the repository-root `.env` merged in by the runner,
doctor and scripts (real environment variables win; `WARDEN_ENV_FILE` selects another file). Relative
paths are resolved against the repository root. `.env.example` documents every variable.

| Variable | Required | Default | Notes |
|---|---|---|---|
| `AGENT_SEED` | **Yes** (to run the agent) | none | Secret. 16+ chars, not a placeholder. Generated by setup; never replaced once set |
| `WARDEN_WORKSPACE_ROOT` | No | `./temp_workspace` | Disposable directory. Repo root, home, drive roots and Git directories are refused for cleanup |
| `WARDEN_AUDIT_LOG` | No | `./logs/audit.jsonl` | Empty value disables persistence |
| `WARDEN_LOG_LEVEL` | No | `INFO` | `DEBUG` to `CRITICAL` |
| `WARDEN_AGENT_PORT` | No | `8000` | Loopback port |
| `WARDEN_SECRET_KEY` | No | random per process | Token signing key. If set: 32+ chars, not a placeholder. Not needed across restarts: tokens and approvals are in-memory and expire in 5 minutes |
| `WARDEN_APPROVER_ADDRESSES` | No | empty | Comma-separated senders allowed to approve actions requested by others |
| `WARDEN_USE_MAILBOX` | No | `false` | Opt in to mailbox mode; connects nothing by itself |
| `WARDEN_ENFORCE_WORKSPACE_CONTAINMENT`, `WARDEN_REQUIRE_APPROVAL_FOR_DESTRUCTIVE` | No | `true` | Always enforced; `false` is rejected |
| `ASI_ONE_API_KEY`, `ASI_ONE_BASE_URL`, `ASI_ONE_MODEL` | No | unset | Optional LLM intent parsing; otherwise a deterministic rule-based parser is used |
| `AGENTVERSE_AGENT_NAME` | No | `warden-verification-agent` | Display name only; does not affect the address |

### Identity and secrets

- Inspect the public address without touching the seed: `.\scripts\run.ps1 -ShowAddress`.
- The seed lives only in `.env` (ignored by Git). Back it up privately: losing it changes the agent address, sharing it lets someone impersonate the agent.
- To rotate, edit `.env` yourself on purpose. WARDEN will not replace an existing seed, and `--seed` on the command line is discouraged because it ends up in shell history.
- Do not commit `.env`, `logs/`, `private_keys.json` or workspaces. `doctor.ps1` checks the Git exclusions.

### Troubleshooting

| Symptom | Fix |
|---|---|
| `running scripts is disabled on this system` | `powershell -ExecutionPolicy Bypass -File .\scripts\setup.ps1` |
| `AGENT_SEED still contains a template placeholder` or `not configured` | `.\scripts\setup.ps1` (or `.\.venv\Scripts\python.exe -m warden.identity init`) |
| `AGENT_SEED is already configured. Refusing to replace` | Intended. Edit `.env` manually if you really want a new identity |
| `Project virtual environment not found` | Run `.\scripts\setup.ps1` |
| Doctor: `Port 8000 ... in use` | Another process owns it; use `.\scripts\run.ps1 -Port 8001` |
| `Refusing to delete workspace contents` | `WARDEN_WORKSPACE_ROOT` points at a repo, home or drive root; choose a dedicated folder |
| `... must be one of true/false/...` or `cannot be disabled` | Fix the named variable in `.env` |
| Windows Firewall prompt on first run | The agent binds loopback only; you can decline network access |
| Agent logs `No endpoints provided. Skipping registration` | Expected in local-only mode |

---

## 7. Project Documentation Directory

- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) — Architectural specification, trust boundaries, and protocol details.
- [docs/INTEGRATION.md](docs/INTEGRATION.md) — Local-only vs mailbox vs endpoint vs discovery vs ASI:One; verified SDK behaviour; next steps.
- [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) — Threat model, attack vectors, mitigations, and residual risks.
- [docs/LOCAL_READINESS_AUDIT.md](docs/LOCAL_READINESS_AUDIT.md) — Local setup audit: findings and their resolution.
- [docs/IDENTITY_AND_ENDPOINT_AUDIT.md](docs/IDENTITY_AND_ENDPOINT_AUDIT.md) — Agent identity hardening and endpoint connectivity audit.
- [docs/REQUIREMENTS_TRACEABILITY.md](docs/REQUIREMENTS_TRACEABILITY.md) — Challenge requirement mapping and verification evidence.
- [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md) — Developer setup, testing guidelines, and contribution rules.
- [docs/INITIAL_AUDIT.md](docs/INITIAL_AUDIT.md) — Baseline engineering and security audit findings.
- [docs/PHASE1_AUDIT.md](docs/PHASE1_AUDIT.md) — Phase 1 ACP & Agentverse integration audit.

---

## 8. License

This project is licensed under the Apache License 2.0. See the LICENSE file for details.
