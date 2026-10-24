# Durable state, restart recovery and audit integrity

## Approval and delivery state (`WARDEN_STATE_DB`)

SQLite (standard library), `warden.security.state_store.StateStore`. Unset means in memory (local
default); hosted mode refuses to start without it.

| Table | Content | Never contains |
|---|---|---|
| `pending` | the exact action (including content to be written), policy result, action digest, target-state digest, created/expires timestamps, permitted approvers, requester, independent-approval flag, advisory risk outcome | tokens, signing keys, seeds |
| `resolved` | outcome (`APPROVED`, `REJECTED`, `EXPIRED`, `INVALIDATED`), who decided, when, the final status of an approved action | file contents read by the executor |
| `replies` | `(sender, msg_id)` of processed chat messages, with a fixed notice | the original reply (it may contain read output) |

Writes are synchronous (`synchronous=FULL`, WAL). Resolution and removal of the live entry happen
in one transaction. Retention: the latest 5000 resolved records and 2000 message ids.

## Restart behaviour

| Before the restart | After the restart |
|---|---|
| pending, still within its window | still pending; approval re-checks digest, approver, policy and the current target state |
| pending, window passed | `EXPIRED`; never executable |
| rejected / invalidated | final; a later approval is refused |
| approved and finished | final; replay refused ("already been approved") |
| approved, outcome not recorded (process stopped mid-run) | marked `INTERRUPTED` on start; never run again; reported as not completed, no success claimed |
| chat message already processed | a redelivery gets a notice; nothing is processed again |
| target changed while down | the approval is invalidated on first use |

Approval consumption is written before the authorization token exists, so an approval can never
be used twice, even if the process dies right after approving. The HMAC signing key is per
process; tokens are issued at approval time and used immediately, so nothing token-related needs
to survive a restart.

A database that cannot be opened, fails `PRAGMA quick_check` or has an unknown schema version
raises `StateStoreError` and startup is refused (`doctor` reports it). There is no automatic
repair: restore the file from backup or move it aside deliberately (which forgets pending
approvals; consumed approvals then can no longer be distinguished, so also clear the workspace).

## Audit log (`WARDEN_AUDIT_LOG`)

JSONL, one event per line, each with `chain.prev` and `chain.hash` (SHA-256 over the previous hash
and the canonical event JSON). A restarted process continues the chain.
`warden.audit.events.verify_audit_chain(path)` and `python -m warden.doctor` report the first
edited, inserted, reordered or removed line. Limits: a consistent rewrite of the whole file by
someone with write access is not detected; ship the log or its latest hash off the host for that.
Audit events carry ids, operations, workspace-relative or as-requested targets, digests, policy
ids, approver addresses and verification evidence (hashes and sizes), never file contents or keys.

Tests: `tests/security/test_approval_identity_overwrite_persistence.py`,
`tests/unit/test_audit_chain.py`, `tests/acceptance/test_acceptance.py::test_14_15_*`.
