# Auditor uAgent Feature Specification & Integration Guide

## Overview

The **Auditor uAgent** is an optional, decoupled verification agent for the WARDEN system. It operates on an independent uAgent protocol (`WardenAuditorProtocol`), independently inspects the physical filesystem post-execution, verifies action digests to prevent in-flight tampering, detects collateral mutations outside the authorized scope, and issues structured attestations.

The feature is **disabled by default**, preserving WARDEN's existing local `OutcomeAuditor` verification path unless explicitly opted into via `WARDEN_AUDITOR_UAGENT_ENABLED=true`.

---

## Architecture & Responsibilities

```
                                      +------------------------+
                                      |      ActionRequest     |
                                      +------------------------+
                                                  |
                                                  v
                                      +------------------------+
                                      |  Policy Engine (Core)  |
                                      |      [WDN-001..004]    |
                                      +------------------------+
                                                  |
                                                  v
                                      +------------------------+
                                      | RestrictedExecutor (Core)
                                      +------------------------+
                                                  |
                                                  v (exec_result)
+-----------------------------------------------------------------------------------------+
| WARDEN Coordinator (WardenAgent)                                                        |
|   |                                                                                     |
|   | 1. Capture Pre-State Manifest                                                       |
|   | 2. Compute ActionDigest(action, workspace_root)                                     |
|   | 3. Dispatch AuditRequest                                                            |
|   v                                                                                     |
| +-------------------------------------------------------------------------------------+ |
| | AuditorUAgentVerifier (Fail-Closed Adapter)                                          | |
| +-------------------------------------------------------------------------------------+ |
+-----------------------------------------------------------------------------------------+
                                 |                          ^
                     AuditRequest|                          | AuditAttestation
                     (Digest,    |                          | (Verdict,
                      Manifest)  v                          |  Evidence)
+-----------------------------------------------------------------------------------------+
| Auditor uAgent (Isolated Process / Protocol Service)                                    |
|   - Recomputes & Verifies ActionDigest (Rejects mismatches as UNVERIFIED)               |
|   - Inspects Physical Disk via ReadOnlyWorkspaceView                                    |
|   - Scans for Collateral Mutations (Unexpected deletions/modifications)                |
|   - Evaluates Post-State independently of Executor claims                               |
|   - Emits Signed / Structured AuditAttestation                                          |
+-----------------------------------------------------------------------------------------+
```

### Core Invariants & Boundaries

1. **No Authorization Authority:** The Auditor does not evaluate policies (`WDN-001` through `WDN-004`), grant approvals, or authorize actions.
2. **Zero Trust in Executor:** The Auditor completely ignores `executor_claimed_success` when establishing physical state. A claimed success with missing or incorrect disk state produces `verdict = FAILED`.
3. **Fail-Closed Semantics:** Any timeout, network failure, malformed attestation, or `UNVERIFIED` verdict immediately causes the coordinator verifier to fail closed (`ExecutionStatus.FAILED, verified=False`).
4. **Action Digest Binding:** The action parameters (`action_id`, `operation`, normalized `target`, `destination`, `content_sha256`, `workspace_root`) are bound into an unforgeable SHA-256 digest. If the request is tampered with, the Auditor returns `UNVERIFIED`.
5. **Collateral Damage Detection:** The Auditor compares the pre-execution workspace file manifest against post-execution disk state. If an extra file outside the permitted target was deleted or altered, it produces `verdict = FAILED` with specific collateral evidence.
6. **API Read-Only vs. OS Isolation:** The `ReadOnlyWorkspaceView` enforces API-level read-only access (no mutation methods). It does **not** provide OS kernel privilege isolation; OS-level isolation requires separate user accounts, containers, or jail boundaries.

---

## Configuration Reference

| Environment Variable | Type | Default | Description |
|---|---|---|---|
| `WARDEN_AUDITOR_UAGENT_ENABLED` | bool | `false` | Enable the Auditor uAgent verification path |
| `WARDEN_AUDITOR_PORT` | int | `8001` | Port for the standalone Auditor uAgent |
| `WARDEN_AUDITOR_TIMEOUT_SECONDS` | float | `5.0` | Timeout before failing closed |
| `WARDEN_AUDITOR_SEED` | string | `(random 256-bit)` | Secret seed for the Auditor agent identity |

---

## Integration Guide for Claude (Core Security Owner)

To preserve strict separation of ownership, **zero existing core security files were modified** on this feature branch:
- [`src/warden/security/policy.py`](file:///D:/AI/WARDEN/src/warden/security/policy.py) (Untouched)
- [`src/warden/security/authorization.py`](file:///D:/AI/WARDEN/src/warden/security/authorization.py) (Untouched)
- [`src/warden/security/path_validation.py`](file:///D:/AI/WARDEN/src/warden/security/path_validation.py) (Untouched)
- [`src/warden/execution/executor.py`](file:///D:/AI/WARDEN/src/warden/execution/executor.py) (Untouched)

### Optional 2-Line Integration Hook in `WardenAgent`

If Claude wishes to wire `AuditorUAgentVerifier` into `WardenAgent` by default:

```python
# In src/warden/agents/warden_agent.py
from warden.auditor.verifier import AuditorUAgentVerifier

# Inside WardenAgent.__init__:
self.auditor = AuditorUAgentVerifier(self.workspace, path_validator=self.path_validator)
```

Because `AuditorUAgentVerifier.enabled` is `False` by default, this is a 100% transparent drop-in replacement that delegates to `OutcomeAuditor` unless `WARDEN_AUDITOR_UAGENT_ENABLED=true`.
