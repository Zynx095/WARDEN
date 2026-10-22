# WARDEN: Autonomous Action-Verification System

> **Fetch-A-Thon 3.0** — *ASI:One Agent Challenge: From Intent to Action*

[![Python](https://img.shields.io/badge/Python-3.10%20%7C%203.11%20%7C%203.12-blue.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/License-Apache_2.0-green.svg)](LICENSE)
[![Tests](https://img.shields.io/badge/Tests-64%20Passed%20%7C%201%20Skipped-success.svg)](tests/)

---

## 1. Executive Summary

Autonomous AI agents capable of understanding intent and taking actions represent the next evolution of intelligent systems. However, giving an LLM direct access to tools, APIs, and operating system primitives creates critical safety hazards: **agents execute destructive, unauthorized, or compromised actions merely because a probabilistic language model emits an instruction.**

**WARDEN** solves this fundamental flaw by decoupling action proposal from execution through a deterministic four-stage lifecycle:
1. **Proposal:** Untrusted agent or LLM proposes a structured action.
2. **Deterministic Authorization:** Strict policy rules and canonical boundary enforcement grant or deny access independent of LLM claims.
3. **Controlled Execution:** A sandboxed executor enforces unforgeable cryptographic tokens within a disposable workspace.
4. **Independent Outcome Verification:** An external auditor inspects actual physical environment state (e.g., cryptographic disk hashes) before and after execution to confirm ground truth.

---

## 2. Target Users & Real-World Impact

- **Enterprise AI Deployments:** Organizations delegating workspace management, CI/CD remediation, and autonomous operations to AI agents without risking system compromise.
- **ASI:One & Agentverse Users:** Individuals interacting with autonomous agents in conversational workflows who require verifiable boundaries against prompt injection and unauthorized modifications.
- **Developers & Security Teams:** Engineers seeking an auditable, fail-closed runtime security envelope for tool-augmented LLMs.

---

## 3. High-Level Architecture

```
                    [ User / ASI:One Conversation ]
                                  │
                                  ▼
                [ Stage 1: Proposal (Untrusted Agent) ]
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

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for full details.

---

## 4. Current Implementation Status

### ✅ Implemented & Locally Verified (Phase 0 Foundation)
- **Deterministic Policy Engine (`src/warden/security/policy.py`):** Evaluates `ALLOW`, `BLOCK`, and `REQUIRE_APPROVAL` deterministically. Protected resources (`.env`, `production.env`, `secrets.json`, `credentials.json`) cannot be modified or deleted (`WDN-003`).
- **Canonical Workspace Boundary Enforcement (`src/warden/security/path_validation.py`):** Resolves canonical paths and strictly enforces containment. Rejects parent directory traversal (`..`), absolute paths, Windows drive paths (`C:`), UNC paths (`\\share`), device names (`CON`, `NUL`), Alternate Data Streams (`:`), and symlink breakouts (`WDN-002`).
- **Cryptographic Authorization Manager (`src/warden/security/authorization.py`):** Issues and verifies HMAC-SHA256 authorization tokens bound to action parameters, workspace root, and time-to-live. LLMs cannot fabricate authorization.
- **Human-in-the-Loop Pending Approvals:** Destructive actions (`DELETE`, `RENAME`) pause execution in `AWAITING_APPROVAL` until an explicit human approval is supplied.
- **Controlled Sandbox Executor (`src/warden/execution/executor.py`):** Rejects unauthorized requests, validates parameters independently, and executes operations safely within `Workspace`.
- **Independent Outcome Auditor (`src/warden/audit/auditor.py`):** Validates actual disk state post-execution; never relies on self-reported tool success flags.
- **Structured Audit Logging (`src/warden/audit/events.py`):** Multi-state lifecycle tracking (`PROPOSED`, `AUTHORIZED`, `BLOCKED`, `AWAITING_APPROVAL`, `EXECUTED`, `VERIFIED`, `FAILED`).
- **Adversarial Resilience (`tests/security/test_adversarial.py`):** Tested against prompt injections in reason strings and file contents, forged authorization tokens, and simulated fake execution claims.
- **Full Automated Test Suite:** 65 tests collected, 64 passed, 1 skipped (Windows unprivileged symlink), 0 failed.

### 🔄 Planned & Integration Ready (Phase 1)
- **Agentverse Registration:** Deploying WARDEN agent on Agentverse with registered Agent Profile and Mailbox.
- **Agent Chat Protocol (ACP):** Models defined in `src/warden/integrations/fetch_acp.py`; live ACP loop planned.
- **ASI:One Integration:** Discoverable via `asi1.ai` for conversational workflow execution.
- **ASI Interactive Cards:** Interactive UI cards for human-in-the-loop approvals inside ASI:One.

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

# Install dependencies
pip install -e ".[dev,fetch]"

# Configuration template
cp .env.example .env
```

### 5.2 Running the Interactive Demo
```bash
python demo/run_demo.py
```
This demonstrates the four-stage verification pipeline against safe operations, prompt injection attacks on `.env`, workspace traversal attempts, and human-in-the-loop approval workflows.

### 5.3 Running the Automated Test Suite
```bash
python -m pytest -v
```

---

## 6. Project Documentation Directory

- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) — Comprehensive architectural specification and trust boundaries.
- [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) — Assets, threat actors, attack vectors, mitigations, and residual risks.
- [docs/REQUIREMENTS_TRACEABILITY.md](docs/REQUIREMENTS_TRACEABILITY.md) — Challenge requirement mapping and verification evidence.
- [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md) — Developer setup, testing guidelines, and contribution rules.
- [docs/INITIAL_AUDIT.md](docs/INITIAL_AUDIT.md) — Baseline engineering and security audit findings.

---

## 7. Known Limitations

- **Single-Agent Concurrency:** In Phase 0, workspaces are executed synchronously per agent. Concurrent multi-agent shared workspace access requires file-level locking.
- **Windows Symlinks:** Symbolic link creation on Windows requires Developer Mode or elevated privileges. WARDEN handles this gracefully by enforcing path containment and skipping unprivileged symlink creation during automated testing.

---

## 8. License

This project is licensed under the Apache License 2.0. See the LICENSE file for details.
