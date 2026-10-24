# Multi-agent interface and ownership

Status: **implemented and tested locally.** The contract lives in `warden.audit.attestation` /
`warden.security.digest`; the opt-in Auditor agent that satisfies it is `warden.auditor`
(`python -m warden.auditor`, see `docs/AUDITOR_UAGENT.md`). It has run over real uAgents
envelopes on loopback only; it is not deployed. The Risk Analyst peer follows the same pattern
with its own contract (`warden.risk.contract`, see `docs/SENTINEL_NETWORK.md`).

## File ownership

| Owner | Paths |
|---|---|
| Core (security owner) | everything under `src/warden/` except `src/warden/auditor/`, `tests/` except `tests/auditor/`, `demo/`, `scripts/`, `docs/` |
| Auditor agent | `src/warden/auditor/**`, `tests/auditor/**`, `docs/AUDITOR_UAGENT.md` |

The Auditor package must not require edits to core files. A core change it needs (a schema
field, a config knob, an import) goes through the core owner, who changes the contract and
announces it.

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

1. Read-only against the workspace; derive `post_state` and `post_snapshots`
   itself using `describe_path_state` and directory listings.
2. Compare to `pre_state`/`pre_snapshots` and the expected post-condition for the
   operation; report any other change under `unexpected_changes`.
3. Echo the binding fields exactly; sign only after the content is final.
4. Own distinct identity. Creating it needs explicit authorization from the user and
   must never reuse or replace WARDEN's `AGENT_SEED`.
5. Separate uAgent address does not mean privilege isolation: both agents run under the
   same OS user unless deployed otherwise. Do not claim otherwise in docs or demos.
