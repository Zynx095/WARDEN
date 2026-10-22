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

### 2.2 Install Dependencies

Install the core, development, and Fetch ecosystem dependencies in editable mode:
```powershell
python -m pip install --upgrade pip
python -m pip install -e ".[dev,fetch]"
```

### 2.3 Environment Configuration

Copy the example configuration file:
```powershell
Copy-Item .env.example .env
```
*(No cloud keys or external credentials are required to run the local test suite or demonstration.)*

---

## 3. Running Automated Tests

WARDEN uses `pytest` with automatic discovery configured in `pyproject.toml`.

### 3.1 Execute Full Test Suite
```powershell
python -m pytest -v
```

Expected result:
- **Total Tests Collected:** 88
- **Passed:** 88
- **Failed:** 0
- **Execution Time:** ~5.5s

### 3.2 Execute Targeted Test Suites

**Unit Tests (Policy, Path Validation, Authorization, Audit, Agent):**
```powershell
python -m pytest tests/unit/ -v
```

**Integration Tests (Restricted Executor & Workspace Containment):**
```powershell
python -m pytest tests/integration/ -v
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
python -m compileall src tests demo
```

---

## 4. Running the Interactive Demonstration

To observe the four-stage action verification pipeline in action:
```powershell
python demo/run_demo.py
```

The script demonstrates:
1. **Scenario 1:** Safe file creation (`CREATE`) independently verified on disk.
2. **Scenario 2:** Injected prompt attempting to overwrite protected `.env` deterministically blocked (`WDN-003`).
3. **Scenario 3:** Directory traversal attempt (`../../`) blocked at workspace boundary (`WDN-002`).
4. **Scenario 4:** Destructive deletion (`DELETE`) requiring explicit human-in-the-loop approval (`WDN-004`), followed by approval, execution, and verified disk deletion.
5. **Audit Log:** Complete event sequence review.

---

## 5. Coding & Security Guidelines

1. **Deterministic Decisions:** Never consult an LLM to decide if an operation is safe. All policy rules must reside in `src/warden/security/`.
2. **Fail Closed:** If any path check, signature check, or filesystem call raises an exception, the system must fail closed and record `ExecutionStatus.FAILED`.
3. **Workspace Isolation:** Never permit operations outside the configured disposable `workspace_root`. Always resolve canonical paths.
4. **Git Hygiene:** Commit early, granularly, and logically. Never commit `.env` or real API credentials.
