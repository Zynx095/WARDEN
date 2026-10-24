# WARDEN — Development & Testing Guide

This guide details how to set up the development environment, execute automated test suites, run the interactive demonstration, and contribute to the WARDEN codebase.

---

## 1. Prerequisites

- **Python:** 3.10, 3.11, or 3.12 (Python 3.12 recommended)
- **Git:** Version 2.30+
- **Platform:** Windows, Linux, or macOS

---

## 2. Environment Setup

### 2.1 Clone Repository & Activate Virtual Environment

**Windows PowerShell:**
```powershell
git clone <repo-url>
cd WARDEN

# Create virtual environment if not present
python -m venv .venv

# Activate virtual environment
.\.venv\Scripts\Activate.ps1
```

**Linux / macOS:**
```bash
git clone <repo-url>
cd WARDEN
python3 -m venv .venv
source .venv/bin/activate
```

### 2.0 One-command setup (recommended)

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\setup.ps1
```
Creates `.venv` if missing, installs from `pyproject.toml`, creates `.env` from `.env.example` only if absent,
generates `AGENT_SEED` only if none is configured, prepares the workspace, runs the tests and the doctor.
It is safe to rerun. The remaining subsections describe what it automates.

### 2.2 Install Dependencies

Install the core, development, and Fetch ecosystem dependencies in editable mode:
```powershell
python -m pip install --upgrade pip
python -m pip install -e ".[dev,fetch]"
```

### 2.3 Environment Configuration

`setup.ps1` handles this. Manually: `Copy-Item .env.example .env`, then `.\.venv\Scripts\python.exe -m warden.identity init`
to generate `AGENT_SEED` (the seed is written to `.env` and never printed; an existing seed is never replaced).
Inspect the public address with `.\scripts\run.ps1 -ShowAddress`.

`.env` is loaded from the repository root by entry points only (runner, doctor, identity CLI, scripts). Library code and
tests never read it implicitly; `tests/conftest.py` strips API keys and `AGENT_SEED` from the environment so the suite is
hermetic. Every variable is documented in `.env.example`, and a test fails if the code reads an undocumented one.
*(No cloud keys or external credentials are required to run the tests, the demo or the local agent.)*

### 2.4 Diagnostics

```powershell
.\scripts\doctor.ps1          # configuration, identity, dependencies, Git hygiene, workspace, port, integration readiness
.\scripts\doctor.ps1 -Tests   # additionally runs pytest
```
Output is secret-free by construction (tests assert it). PASS/WARN/FAIL; only FAIL gives a non-zero exit code.

---

## 3. Running Automated Tests

WARDEN uses `pytest` with automatic discovery configured in `pyproject.toml`.

### 3.1 Execute Full Test Suite
```powershell
.\scripts\test.ps1            # compileall + pytest with the project .venv
.\.venv\Scripts\python.exe -m pytest -v
```

Expected result (2026-10-24, Windows 11, Python 3.12): **652 passed, 0 failed**, about 95 s. Tests that need PowerShell
(script parsing) are skipped if neither `pwsh` nor `powershell` is on PATH. No test touches an external network or a real
credential; the live tests exchange real uAgents envelopes on loopback only.

### 3.2 Execute Targeted Test Suites

**Unit Tests (Policy, Path Validation, Authorization, Digest, Cards, Config, Agent):**
```powershell
python -m pytest tests/unit/ -v
```

**Integration Tests (Executor, Approval Binding, Interactive Cards, Remote Auditor, Sentinel Network):**
```powershell
python -m pytest tests/integration/ -v
```

**Risk Analyst (Contract, Analysis, Authority Boundaries):**
```powershell
python -m pytest tests/risk/ -v
```

**Auditor Agent, Hosting, Presentation, Acceptance:**
```powershell
python -m pytest tests/auditor/ tests/hosting/ tests/presentation/ tests/acceptance/ -v
```

**Adversarial Security Tests (Prompt Injection, Forged Tokens, Fake Success):**
```powershell
python -m pytest tests/security/ -v
```

**Regression Suite (Original 5 Baseline Policy Tests):**
```powershell
python -m pytest tests/test_policy.py -v
```

### 3.3 Bytecode Compilation Check
Verify there are no syntax errors or corrupted imports across the repository:
```powershell
python -m compileall -q src tests demo scripts
```

---

## 4. Running the Demonstration

```powershell
.\scripts\demo.ps1
```

Runs offline in `temp_demo_workspace/` on synthetic files (`session_cache.tmp`, `debug_output.log`,
`build_artifacts.cache`, a dummy `production.env`, ...), wiping that directory first so reruns are identical. It:
1. inspects the workspace and performs a verified `READ`;
2. handles "Clean up temporary files" over the Agent Chat Protocol; every deletion is held for approval (`WDN-004`) and nothing is deleted yet;
3. runs a safe `CREATE` end to end (token, executor, verification);
4. approves the held deletions as the requesting sender;
5. attempts to delete the protected file with a prompt-injection reason and is blocked by `WDN-003`;
6. re-checks the real filesystem with plain `os`/`hashlib` (not WARDEN's auditor) and confirms the protected file is byte-identical;
7. reads back `logs/demo_audit.jsonl` and checks it recorded the blocks and verifications without file contents.

Any failed expectation raises `DemoFailure` and a non-zero exit code. The intent parser is forced offline, so an
`ASI_ONE_API_KEY` in your environment cannot make the demo call the network (tested).

---

## 5. Coding & Security Guidelines

1. **Deterministic Decisions:** Never consult an LLM to decide if an operation is safe. All policy rules must reside in `src/warden/security/`.
2. **Fail Closed:** If any path check, signature check, or filesystem call raises an exception, the system must fail closed and record `ExecutionStatus.FAILED`.
3. **Workspace Isolation:** Never permit operations outside the configured disposable `workspace_root`. Always resolve canonical paths.
4. **Git Hygiene:** Commit early, granularly, and logically. Never commit `.env` or real API credentials.
5. **Entry points load `.env`; libraries do not.** Anything under `src/warden` must take its configuration from `WardenConfig`/arguments. Add new variables to `.env.example` (a test enforces this).
6. **Identity changes are deliberate.** Never add a default seed, never auto-replace one, never print or log it. Use `warden.identity` for derivation so diagnostics and runtime agree.
7. **Tests that load `.env`-style files** must isolate `os.environ` (see `isolated_env` in `tests/unit/test_doctor.py`), because `python-dotenv` writes to the real process environment.
