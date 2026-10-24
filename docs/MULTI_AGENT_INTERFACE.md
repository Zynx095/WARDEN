# Multi-agent interface and ownership

Status: **contract only**. No Auditor agent exists yet. Everything below describes what
is implemented in `warden.audit.attestation` / `warden.security.digest` (implemented and
unit-tested) and what a future opt-in Auditor must satisfy (proposed).

## File ownership

| Owner | Paths |
|---|---|
| Core (security owner) | everything under `src/warden/` except the Auditor-agent package, `tests/` except `tests/auditor_agent/`, `demo/`, `scripts/`, existing `docs/` |
| Auditor feature branch | `src/warden/auditor_agent/**`, `tests/auditor_agent/**`, `docs/AUDITOR_AGENT.md`, `scripts/run_auditor.ps1` (new files only) |

The Auditor branch must not edit core files. If it needs a core change (a schema field,
a config knob, an import), request it from the core owner first; the core owner changes
the contract and announces it. Integration into core happens only after review of the
full diff and commit history.

The Auditor package may import only the pure helpers `warden.audit.attestation` and
`warden.security.digest`. It must not import the policy engine, authorization manager,
executor or `WardenAgent`: it holds no signing key, no token, and no write capability.

## Messages (v1)

Defined in `src/warden/audit/attestation.py`. All timestamps are ISO-8601 UTC strings.

- `AuditRequest` (WARDEN to Auditor): `request_id`, `nonce`, `action_digest`, `operation`,
  workspace-relative `target`/`destination`, `expected_content_sha256`, `workspace_id`,
  `pre_state` (what WARDEN observed before execution), `pre_snapshots` (directory listings),
  `issued_at`, `expires_at`. It never contains the Executor's success message or output.
- `AuditAttestation` (Auditor to WARDEN): echoes `request_id`, `nonce`, `action_digest`,
  `workspace_id`; adds `auditor_address`, `verdict` (`VERIFIED|FAILED|UNVERIFIED`),
  `post_state`, `post_snapshots`, `unexpected_changes`, `details`, `observed_at`
  and `signature`.
- Signature: `uagents.crypto.Identity.sign_digest(signing_digest(attestation))`, where
  `signing_digest` is SHA-256 of the canonical JSON of every field except `signature`.

## How WARDEN treats the result

`check_attestation(request, attestation, trusted_auditor_address)` returns
`valid=False, verdict=UNVERIFIED` for a missing, malformed, unsigned, mis-signed,
untrusted-signer, mismatched, expired or out-of-window attestation. `VERIFIED` plus
`unexpected_changes` is `FAILED`. WARDEN reports VERIFIED only when the local check
passes **and** (when the remote Auditor is enabled) the attestation is valid and says
VERIFIED. The local check is never skipped.

## Auditor behavior requirements

1. Read-only against the workspace; derive `post_state` and `post_parent_snapshot`
   itself using `describe_path_state` and a directory listing.
2. Compare to `pre_state`/`pre_parent_snapshot` and the expected post-condition for the
   operation; report any other change under `unexpected_changes`.
3. Echo the binding fields exactly; sign only after the content is final.
4. Own distinct identity. Creating it needs explicit authorization from the user and
   must never reuse or replace WARDEN's `AGENT_SEED`.
5. Separate uAgent address does not mean privilege isolation: both agents run under the
   same OS user unless deployed otherwise. Do not claim otherwise in docs or demos.
