# Remote Auditor (optional)

Status: implemented and tested locally (in-process loopback and a real uAgents sync
exchange over `127.0.0.1`). Not deployed, not registered on Agentverse, and not tested
with any external agent.

## What it does

When `WARDEN_REMOTE_AUDITOR=true`, WARDEN still runs its local check. For a mutating
action (CREATE, WRITE, DELETE, RENAME) it also sends an `AuditRequest` to one trusted
Auditor agent and reports **VERIFIED only if both agree**:

1. the local check passes, and
2. a response arrives in time that is signed by `WARDEN_AUDITOR_ADDRESS`, is bound to this
   request (`request_id`, `nonce`, `action_digest`, `workspace_id`), is inside the request
   window, says VERIFIED, lists no unexpected changes, and describes the same target
   post-state WARDEN observed locally.

Anything else is **UNVERIFIED** (executed, but not independently confirmed: timeout,
unreachable Auditor, malformed/unsigned/forged/replayed/mismatched attestation) or
**FAILED** (the Auditor reports a mismatch or collateral change). A local failure is final;
a remote VERIFIED cannot rescue it.

Contracts: schemas and `check_attestation` in `warden/audit/attestation.py`, digests in
`warden/security/digest.py`, request building in `warden/audit/request_builder.py`,
verification in `warden/audit/remote.py`, transport in `warden/audit/transport.py`.
See `docs/MULTI_AGENT_INTERFACE.md`.

## Running it

WARDEN side (`.env`): `WARDEN_REMOTE_AUDITOR=true`, `WARDEN_AUDITOR_ADDRESS=<auditor agent address>`,
optionally `WARDEN_AUDITOR_TIMEOUT_SECONDS`. Enabling without an address fails at startup, and
the Auditor address may not be WARDEN's own.

Auditor side: `python -m warden.auditor` with its **own** `WARDEN_AUDITOR_SEED` (must differ
from `AGENT_SEED`; the process refuses to start otherwise), `WARDEN_AUDITOR_ALLOWED_REQUESTER`
(WARDEN's agent address; required) and optionally `WARDEN_AUDITOR_WORKSPACE_ROOT` /
`WARDEN_AUDITOR_PORT`. It binds to loopback only. **This repository does not create the
Auditor identity**: generate and record that seed yourself.

## Auditor behavior

- Ignores (does not answer) senders outside the allow-list and malformed requests.
- Recomputes the action digest from the request fields, checks the workspace id, expiry
  and path containment, observes the real post-state itself, and diffs the touched
  directories against WARDEN's pre-execution snapshots.
- Caches by `(sender, request_id)`: redelivery returns the same attestation; reusing an id
  with a different nonce is UNVERIFIED.
- Has no policy, token, executor or signing-key access and no mutating filesystem calls
  (enforced by a source-level test).

## Limitations

- A separate agent address is a separate identity, **not privilege isolation**. By default
  both agents run as the same OS user on the same machine; a compromised host defeats both.
- WARDEN's request is sent while the agent's event loop is blocked, for at most the timeout.
- Collateral detection covers the touched files' directories only. Paths are case-folded,
  which suits Windows and would need revisiting for case-sensitive filesystems.
- The request carries the workspace-relative target, hashes and directory listings (names,
  sizes, mtimes), not file content.
