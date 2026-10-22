# WARDEN — Local Readiness Audit

**Date:** 2026-10-23
**Branch:** master (50 commits at audit time)
**Environment:** Windows 11, Python 3.12.0, `uagents` 0.26.1, `uagents-core` 0.4.12, pydantic 2.14.1
**Scope:** What stands between the existing implementation and a one-command local workflow.
This complements, and does not repeat, `INITIAL_AUDIT.md`, `PHASE1_AUDIT.md` and
`IDENTITY_AND_ENDPOINT_AUDIT.md`.

## 1. Baseline (measured, not reported)

| Check | Result |
|---|---|
| `python -m pytest -q` (venv) | 88 passed, 1 warning |
| Warning | `DeprecationWarning: There is no current event loop` raised inside `uagents/agent.py:373` when `Agent()` is built outside a running loop |
| Working tree | only `scripts/` untracked (contains `initialize_identity.py`, user work, preserved) |

## 2. Findings

Severity: **H** breaks the stated goal or weakens security, **M** correctness/usability, **L** polish.

| # | Sev | Finding | Evidence |
|---|---|---|---|
| F1 | H | **`.env` is never loaded by the runtime.** Nothing calls `load_dotenv`; `python-dotenv` is a declared dependency but only the helper script reads it. `AGENT_SEED`, `WARDEN_WORKSPACE_ROOT`, etc. only work if exported in the shell. | `grep load_dotenv src` → no hits |
| F2 | H | **The `.env.example` placeholder seed is accepted as a real identity.** `build_warden_agent` only rejects an empty seed. Copying `.env.example` to `.env` yields an agent whose key is derived from the publicly known string `your_secure_agent_seed_phrase_here`, which is the exact predictable-seed class the Phase 2A work set out to remove. | `run_agent.py:62-68` |
| F3 | H | **`scripts/initialize_identity.py` does not run against the installed SDK.** It reads `identity.signing_key`, which does not exist on `uagents.crypto.Identity` (private state is `_sk`, public accessor `private_key`). Even if it ran, it prints the address of the *generated* key while the runtime derives from the seed via `Identity.from_seed(seed, 0)`, which is a different key, so the printed address would not match the running agent. | reproduced: `AttributeError: 'Identity' object has no attribute 'signing_key'` |
| F4 | M | Paths are CWD-relative. `WARDEN_WORKSPACE_ROOT=./temp_workspace` and the demo's `./temp_demo_workspace` resolve against wherever the process was started. | `config.py:16`, `run_agent.py:82`, `demo/run_demo.py` |
| F5 | M | `WARDEN_SECRET_KEY` is read nowhere in the docs/`.env.example`; when unset a random key is created per process. Weak or placeholder values are accepted when it is set. See §3 for whether persistence is needed. | `config.py:24` |
| F6 | M | Any chat sender can `APPROVE <id>` any pending action, including actions proposed by a different sender. Approval is not bound to the requester. | `acp_adapter.py` approval branch, `AuthorizationManager.approve_pending_action` |
| F7 | M | `process_chat_message` has no error containment. An exception in intent parsing or the pipeline propagates into the uAgents handler and no reply is sent; there is also no cap on message size. | `acp_adapter.py` |
| F8 | M | Docs reference `run_agent.py --dry-run`, which does not exist (`--show-address` does). | `IDENTITY_AND_ENDPOINT_AUDIT.md` §4 |
| F9 | M | `README`/`DEVELOPMENT` use `cp .env.example .env` (not valid in PowerShell) and instruct passing `--seed "..."` on the command line, which leaks the seed into shell history and process listings. | `README.md` §5.1, §5.4 |
| F10 | M | The demo uses `.env`/`production.env` as *targets* (blocked by policy, so no harm), starts from `workspace.clean()` on a CWD-relative directory, and exercises none of: the "inspect workspace" step, the temp-file cleanup via the safe path, or an audit trail. Its approval scenario deletes via approval but uses `production.env` in an ACP prompt that is only incidentally blocked. | `demo/run_demo.py` |
| F11 | M | `Workspace.clean()` deletes everything under whatever root it is given. There is no guard against pointing it at the repository root, a drive root or the home directory. | `workspace.py:26` |
| F12 | L | `AuditLogger` is memory-only by default; audit records vanish when the process exits. | `audit/events.py` |
| F13 | L | `pip install -e ".[dev,fetch]"` pulls `openai` and `httpx`, but `uagents` is declared with `>=0.12.0` although code uses `uagents_core.contrib.protocols.chat`, which needs the installed 0.26-era SDK. There is no lock/constraint of the verified versions. | `pyproject.toml` |
| F14 | L | `src/security/policy.py` is a compatibility shim duplicating `warden.security.policy`. Retained (tests import it). | `tests/test_policy.py` |
| F15 | L | The `DeprecationWarning` from `uagents` is caused by building `Agent` without a loop on 3.12. | baseline run |

## 3. `WARDEN_SECRET_KEY` — does it need to persist?

Inspection of `authorization.py` and `warden_agent.py`:

* Tokens are HMAC-signed, issued and verified inside the same `WardenAgent` instance, live 300 s, and are never written to disk or sent to a client in the ACP reply.
* Pending approvals live in `AuthorizationManager._pending_approvals` (in-memory dict). After a restart they are gone regardless of the key.

Therefore persistence is **not required**: a fresh per-process random key is the safest default (a compromised key from a previous run cannot forge tokens). It becomes relevant only if a future change persists tokens or approvals or runs several processes sharing tokens. The key is kept **optional**; when supplied it must be strong (≥ 32 chars, not a placeholder). This is covered by tests and documented in the configuration reference.

## 4. SDK facts verified on the installed version

* `Agent(name, seed, port)` address equals `Identity.from_seed(seed, 0).address`, independent of agent name and port. Same seed → same address across instances.
* `Agent(...)` with a seed and no `endpoint`/`mailbox` has `_endpoints == []` and `_use_mailbox == False`; it creates no files in the working directory.
* `Identity` exposes `.address`, `.pub_key`, `.private_key`; there is no `signing_key` attribute.

## 5. Remediation plan (executed in the commits that follow)

Config/env loading (F1, F4, F5) → identity module and placeholder rejection (F2, F3, F8) → runner uses both (F1, F2) → ACP hardening (F6, F7) → workspace guard (F11) → PowerShell automation → deterministic demo with persisted audit (F10, F12) → tests → docs (F8, F9, F13).

## 6. Resolution (end of the local readiness phase)

| # | Status | Resolution |
|---|---|---|
| F1 | Fixed | `config.load_environment()` loads the repo-root `.env` (or `WARDEN_ENV_FILE`) in the runner, doctor, identity CLI and scripts; real environment variables win. Library code stays side-effect free. |
| F2 | Fixed | `warden.identity.validate_seed` rejects empty, placeholder and short seeds; the template ships `AGENT_SEED=` empty. |
| F3 | Fixed | `scripts/initialize_identity.py` delegates to `warden.identity`; the printed address is derived exactly as at runtime. Verified against `Agent(...).address`. |
| F4 | Fixed | Relative paths resolve against the repository root. Test: CWD-independent. |
| F5 | Fixed, documented | Optional key, validated when set, random per process otherwise (persistence not required, see §3). Documented in `.env.example` and the README. |
| F6 | Fixed | Approvals are bound to the requesting sender plus `WARDEN_APPROVER_ADDRESSES`. |
| F7 | Fixed | Errors contained, 4000 character cap, paths scrubbed. |
| F8 | Fixed | `--dry-run` never existed; documentation points to `--show-address` / `.\scripts\run.ps1 -ShowAddress`. |
| F9 | Fixed | PowerShell-native instructions; the seed never needs to be typed. |
| F10 | Fixed | New synthetic, self-checking, offline demo (`warden.demo`), run by tests twice to prove repeatability. |
| F11 | Fixed | `Workspace.clean/teardown` refuse repo/home/drive roots and Git directories. |
| F12 | Fixed | `WARDEN_AUDIT_LOG` JSONL persistence (default `logs/audit.jsonl`, ignored by Git). |
| F13 | Fixed | `uagents>=0.26.1,<0.27` is a core dependency; unused `httpx` dropped; `openai` stays optional. |
| F14 | Left as is | Compatibility shim still imported by an existing test. |
| F15 | Fixed | The runner passes an explicit event loop; the suite runs with zero warnings. |

### Additional findings discovered while implementing

| # | Finding | Resolution |
|---|---|---|
| F16 | `AGENTVERSE_MAILBOX_KEY` is not consumed by uAgents 0.26.1 (`parse_agentverse_config` discards it). The previous log line also printed part of it. | Treated as a deprecated mode switch with a warning; nothing is printed. |
| F17 | `WARDEN_ENFORCE_WORKSPACE_CONTAINMENT` and `WARDEN_REQUIRE_APPROVAL_FOR_DESTRUCTIVE` were parsed but never read; `ture` parsed as false. | Strict parsing; `false` is rejected as these controls are always enforced. |
| F18 | `IntentEngine` fell back to `OPENAI_API_KEY` and sent it to `api.asi1.ai`. | Removed; added `offline=True`. |
| F19 | The SDK binds `0.0.0.0` and always posts an "active" status to the Almanac API, even with no endpoint. | Loopback binding enforced by the runner; the status call is documented, not hidden. |
| F20 | A replayed `APPROVE` raised an uncaught `AuthorizationError`. | Returns a failed result. |

### Not resolved here (needs external accounts or is out of scope)

Agentverse mailbox provisioning, registration, discovery and ASI:One conversations were not attempted or verified. See `docs/INTEGRATION.md`.
