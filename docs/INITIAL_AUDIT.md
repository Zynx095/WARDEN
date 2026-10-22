# WARDEN — Initial Repository Audit & Baseline Findings

**Date:** 2026-10-22  
**Auditor:** Senior Software Engineer (AI Pair Programmer)  
**Branch:** master  
**Initial Commit:** `cbf3edf` ("feat: implement initial deterministic action policies")

---

## 1. Executive Summary

WARDEN is an autonomous action-verification system designed for the Fetch-A-Thon 3.0 (ASI:One Agent Challenge — From Intent to Action). Its goal is to separate action proposal, deterministic authorization, controlled execution, and independent outcome verification.

An audit of the initial repository state reveals an early proof-of-concept with a basic string-matching policy engine and 5 passing unit tests. However, it lacks robust package structure, production path canonicalization, workspace containment boundaries, an execution engine, outcome verification, structured audit events, documentation, and Fetch.ai integration preparation.

---

## 2. Repository Inventory & Inspection

### 2.1 File Tree (Pre-Audit)
```
WARDEN/
├── .gitignore
├── .env (empty)
├── src/
│   └── security/
│       └── policy.py
└── tests/
    └── test_policy.py
```
*(Plus `.venv/` containing pre-installed packages and `.pytest_cache/`.)*

### 2.2 Git State
- **Branch:** `master`
- **Working Tree:** Clean
- **Tracked Files:** `.gitignore`, `src/security/policy.py`, `tests/test_policy.py`
- **History:** 1 commit (`cbf3edf`)

### 2.3 Dependency Environment
Inspected active `.venv` (Python 3.12.0 on win32):
- **Core libraries present:** `uagents` (0.26.1), `uagents-core` (0.4.12), `pydantic` (2.14.1), `pytest` (9.1.1), `python-dotenv` (1.2.4), `httpx` (0.28.1), `openai` (3.36.1), `uvicorn` (0.54.0), `cosmpy` (0.12.2).
- **Packaging:** No `pyproject.toml` or `setup.py` exists yet.
- **Environment variables:** `.env` exists but is empty; no `.env.example` exists.

### 2.4 Baseline Test Execution
Executed `pytest -v` against `tests/test_policy.py`:
- 5 tests collected, 5 passed in 0.12s.
- Existing tests:
  1. `test_safe_read_is_allowed` -> PASS
  2. `test_protected_file_cannot_be_deleted` -> PASS
  3. `test_path_traversal_is_blocked` -> PASS
  4. `test_unknown_operation_is_blocked` -> PASS
  5. `test_destructive_operation_requires_approval` -> PASS

---

## 3. Vulnerability & Architecture Deficiencies Identified

### 3.1 Path Traversal & Normalization Weaknesses
In `src/security/policy.py`:
- Checks rely solely on string manipulation:
  ```python
  target = action.target.replace("\\", "/")
  if target.startswith("/") or ".." in target.split("/") or ":" in target:
      return PolicyResult(Decision.BLOCK, "WDN-002", "Path is outside the permitted workspace.")
  ```
- **Vulnerabilities / Gaps:**
  - UNC paths (e.g. `\\host\share` or `//host/share`) are not properly blocked on all platforms.
  - Case-insensitive bypasses or alternate data streams on Windows (e.g., `file.txt:stream`).
  - Trailing dots or spaces (`file.txt. `) which Windows strips at filesystem level.
  - Symlinks or directory junctions pointing outside the workspace boundary are not resolved or validated against the workspace root.
  - Rename destination paths are completely unrepresented in `Action` (only `target` exists), leaving the destination unvalidated.
  - No workspace root binding or canonical containment verification (`os.path.realpath` / `pathlib.Path.resolve`).

### 3.2 Incomplete Action and Decision Models
- `Action` only has `operation`, `target`, and `reason`.
- Lacks support for destination path (essential for `RENAME`), action ID, trace/correlation ID, timestamp, actor/origin, and proposed payload/content for `CREATE` and `WRITE`.
- `PolicyResult` lacks structured authorization tokens, timestamp, context, and bound parameters.

### 3.3 Missing Execution Boundary & Separation of Concerns
- No execution engine exists.
- No mechanism to ensure execution can only proceed with a valid, cryptographically or structurally unforgeable, unexpired authorization token bound to the exact action and workspace.
- No pending-approval workflow to prevent `REQUIRE_APPROVAL` from executing.

### 3.4 Missing Outcome Verification & Audit Subsystem
- No event log or structured audit trail (`PROPOSED`, `VERIFYING`, `AUTHORIZED`, `BLOCKED`, `AWAITING_APPROVAL`, `EXECUTED`, `VERIFIED`, `FAILED`).
- No independent verification of filesystem changes (e.g. verifying file exists with expected content on CREATE/WRITE, verifying absence on DELETE, verifying destination exists and source absent on RENAME).

### 3.5 Package Layout & Imports
- Code is currently in `src/security/`, rather than `src/warden/...`.
- Need backward-compatible re-exports so existing tests and external references continue to work seamlessly.

---

## 4. Phase 0 Remediation Plan

1. **Packaging & Configuration:**
   - Establish `pyproject.toml` with standard build metadata and pytest configuration.
   - Establish `.env.example` with documented configuration parameters.
   - Update `.gitignore` to ensure coverage of temporary files, test outputs, and sensitive materials.

2. **Package Layout & Data Models:**
   - Build `src/warden/` package with `models.py`, `config.py`.
   - Provide typed models for `ActionType`, `Decision`, `ActionRequest`, `PolicyDecision`, `ExecutionRequest`, `ExecutionResult`, `VerificationResult`, `AuditEvent`.
   - Maintain backward compatibility with `src/security/policy.py`.

3. **Security Engine Enhancement:**
   - Implement canonical path validation in `src/warden/security/path_validation.py` handling symlinks, junctions, Windows drives, UNC paths, and normalization.
   - Upgrade policy engine to evaluate source and destination targets, bound to workspace.
   - Implement `authorization.py` generating signed or structurally verified authorization tokens.

4. **Safe Filesystem Executor:**
   - Implement `src/warden/execution/workspace.py` and `src/warden/execution/executor.py`.
   - Require explicit authorization tokens; refuse execution without matching, unexpired, authorized tokens.
   - Enforce fail-closed behavior on any filesystem error.

5. **Audit Subsystem & Independent Outcome Verification:**
   - Implement `src/warden/audit/events.py` and `src/warden/audit/auditor.py`.
   - Implement independent verification verifying before/after filesystem state.

6. **Comprehensive Automated Testing:**
   - Unit tests for security policy and path validation.
   - Integration tests for executor in isolated temporary workspaces.
   - Adversarial security tests (prompt injection in files, fabricated authorization tokens, symlink escapes).
   - Preserve and verify existing regression tests.

7. **Documentation & Traceability:**
   - Write `README.md`, `docs/ARCHITECTURE.md`, `docs/THREAT_MODEL.md`, `docs/REQUIREMENTS_TRACEABILITY.md`, and `docs/DEVELOPMENT.md`.
