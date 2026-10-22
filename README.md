# WARDEN: Autonomous Action-Verification System

> **Fetch-A-Thon 3.0** — *ASI:One Agent Challenge: From Intent to Action*

[![Python](https://img.shields.io/badge/Python-3.10%20%7C%203.11%20%7C%203.12-blue.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/License-Apache_2.0-green.svg)](LICENSE)
[![Tests](https://img.shields.io/badge/Tests-80%20Passed-success.svg)](tests/)
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

## 4. Implementation Status

### ✅ Implemented & Locally Verified (Phase 0 + Phase 1)
- **Agent Chat Protocol (ACP v0.3.0):** Native integration using `uagents_core.contrib.protocols.chat`. Implements full interaction cycle: `ChatMessage` -> `ChatAcknowledgement` -> Conversational Pipeline Response.
- **ASI:One Intent Engine (`src/warden/agents/intent_engine.py`):** Structured intent interpretation using the ASI:One API (`asi1-mini` via OpenAI-compatible endpoint) with automatic deterministic fallback for offline tests.
- **Agentverse Runner (`src/warden/agents/run_agent.py`):** Configures and launches a live `uagents.Agent` with deterministic address generation and Agentverse Mailbox bridging.
- **Deterministic Policy Engine (`src/warden/security/policy.py`):** Evaluates `ALLOW`, `BLOCK`, and `REQUIRE_APPROVAL` deterministically. Protected resources (`.env`, `production.env`, `secrets.json`, `credentials.json`) cannot be modified or deleted (`WDN-003`).
- **Canonical Workspace Boundary Enforcement (`src/warden/security/path_validation.py`):** Resolves canonical paths and strictly enforces containment. Rejects parent directory traversal (`..`), absolute paths, Windows drive paths (`C:`), UNC paths (`\\share`), device names (`CON`, `NUL`), Alternate Data Streams (`:`), and symlink breakouts (`WDN-002`).
- **Cryptographic Authorization Manager (`src/warden/security/authorization.py`):** Issues and verifies HMAC-SHA256 authorization tokens bound to action parameters, workspace root, and time-to-live. LLMs cannot fabricate authorization.
- **Human-in-the-Loop Pending Approvals:** Destructive actions (`DELETE`, `RENAME`) pause execution in `AWAITING_APPROVAL` until explicit human approval (`APPROVE <action_id>`) is provided via conversation.
- **Controlled Sandbox Executor (`src/warden/execution/executor.py`):** Rejects unauthorized requests, validates parameters independently, and executes operations safely within `Workspace`.
- **Independent Outcome Auditor (`src/warden/audit/auditor.py`):** Validates actual disk state post-execution; never relies on self-reported tool success flags.
- **Structured Audit Logging (`src/warden/audit/events.py`):** Multi-state lifecycle tracking (`PROPOSED`, `AUTHORIZED`, `BLOCKED`, `AWAITING_APPROVAL`, `EXECUTED`, `VERIFIED`, `FAILED`).
- **Adversarial Resilience (`tests/security/test_adversarial.py`):** Tested against prompt injections in reason strings and file contents, forged authorization tokens, and simulated fake execution claims.
- **Automated Test Suite:** 80 tests collected, 80 passed, 0 failed in ~5 seconds.

### 🔄 External Deployment Readiness
- **Agentverse Mailbox Key:** Set `AGENTVERSE_MAILBOX_KEY` in `.env` to connect to Agentverse without public port forwarding.
- **ASI:One Discoverability:** With mailbox connected, the agent is registered on the Almanac and discoverable at `https://asi1.ai`.

---

## 5. Quickstart & Installation

### 5.1 Installation
```bash
git clone https://github.com/Zynx095/WARDEN.git
cd WARDEN

# Virtual environment setup
python -m venv .venv

# On Windows:
.\.venv\Scripts\Activate.ps1
# On Linux/macOS:
source .venv/bin/activate

# Install dependencies in editable mode
pip install -e ".[dev,fetch]"

# Configuration template
cp .env.example .env
```

### 5.2 Running the Interactive Demo
```bash
python demo/run_demo.py
```
Demonstrates all 5 scenarios including safe file operations, prompt injection shielding, workspace containment, approval gating, and native ACP conversational cleanup.

### 5.3 Running the Automated Test Suite
```bash
python -m pytest -v
```

### 5.4 Starting the Live WARDEN Agent (uAgents / Agentverse)
```bash
python src/warden/agents/run_agent.py
```
Starts the agent, prints its unique Fetch.ai address (`agent1q...`), attaches the `AgentChatProtocol`, and begins listening for incoming messages.

---

## 6. Project Documentation Directory

- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) — Architectural specification, trust boundaries, and protocol details.
- [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) — Threat model, attack vectors, mitigations, and residual risks.
- [docs/REQUIREMENTS_TRACEABILITY.md](docs/REQUIREMENTS_TRACEABILITY.md) — Challenge requirement mapping and verification evidence.
- [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md) — Developer setup, testing guidelines, and contribution rules.
- [docs/INITIAL_AUDIT.md](docs/INITIAL_AUDIT.md) — Baseline engineering and security audit findings.
- [docs/PHASE1_AUDIT.md](docs/PHASE1_AUDIT.md) — Phase 1 ACP & Agentverse integration audit.

---

## 7. License

This project is licensed under the Apache License 2.0. See the LICENSE file for details.
