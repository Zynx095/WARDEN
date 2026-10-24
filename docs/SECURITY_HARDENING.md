# Security hardening log

What changed after the architecture review, what is tested, and what remains open.
Everything here is implemented and covered by tests in this repository unless marked
"open".

## Implemented

| Control | Where | Tests |
|---|---|---|
| Canonical action digest (operation, canonical target/destination, content hash, workspace) | `security/digest.py` | `unit/test_digest.py` |
| Tokens signed over the digest and the observed target state; the executor recomputes both | `security/authorization.py`, `execution/executor.py` | `unit/test_token_binding.py` |
| Approval prompt shows operation, target, destination, content hash, full digest and expiry; chat approval must echo the digest | `integrations/acp_adapter.py` | `integration/test_approval_binding.py` |
| Approval expiry (`WARDEN_APPROVAL_TTL_SECONDS`) and bounded pending queue (`WARDEN_MAX_PENDING_APPROVALS`), fail closed when full | `security/authorization.py`, `config.py` | `integration/test_approval_binding.py` |
| Approval invalidated if the target state changed after it was requested; token re-checked at execution | `agents/warden_agent.py`, `execution/executor.py` | `integration/test_approval_binding.py` |
| Pre-execution state capture; DELETE/CREATE/WRITE/RENAME verified against it, including collateral-change detection and exact byte hashes | `audit/auditor.py`, `execution/executor.py` | `unit/test_audit_strength.py` |
| Deduplication scoped to `(sender, msg_id)` | `integrations/acp_adapter.py` | `integration/test_dedup_scoping.py` |
| Advisory text (`reason`) cannot relax a block or skip approval | `security/policy.py` | `security/test_advisory_text_has_no_authority.py` |
| Wire contract and fail-closed checker for a future out-of-process Auditor | `audit/attestation.py`, `docs/MULTI_AGENT_INTERFACE.md` | `unit/test_attestation.py` |
| Opt-in remote Auditor (`WARDEN_REMOTE_AUDITOR`, off by default): VERIFIED needs local pass AND a valid signed attestation; timeout/forgery/replay/mismatch/unreachable give UNVERIFIED | `audit/remote.py`, `audit/request_builder.py`, `audit/transport.py`, `auditor/` | `integration/test_remote_auditor.py`, `integration/test_remote_auditor_live.py`, `auditor/` |

## Open (not addressed)

- Policy, executor and auditor still share one process, OS user and signing key. The
  local auditor is an additional check, not an isolated boundary.
- The requester may approve their own request unless `WARDEN_APPROVER_ADDRESSES` is set.
- WRITE to an existing non-protected file is still auto-allowed by policy (overwrite is
  destructive); changing that alters the demo flow and needs a decision.
- Collateral detection covers the directories of the touched paths, not the whole
  workspace tree.
- Pending approvals, the dedup cache and the signing key are in memory only; the audit
  log is not tamper-evident.
- Filenames and user text still reach the LLM intent prompt without provenance tagging.
- Not production ready. There is no OS-level privilege isolation anywhere: WARDEN and the
  Auditor are separate uAgent identities, but by default run as the same OS user on one
  machine. External routing (Almanac/mailbox/remote endpoints), multi-host deployment and
  third-party agents are untested.
- Remote verification blocks WARDEN's event loop for up to `WARDEN_AUDITOR_TIMEOUT_SECONDS`
  (default 10 s) per mutating action; the wait is bounded, not asynchronous.
- Paths are case-folded for digests and snapshots (verified on Windows, where lookups are
  case-insensitive); case-sensitive filesystems are unsupported for remote mode.
- Test hermeticity: the suite clears the security-relevant `WARDEN_*` variables per test;
  `7fb3ec2` is an intermediate commit whose remote tests do not collect (the Auditor package
  is adapted in the next commit), so use `fdfc42c` or `8cbda4a` and later as checkpoints.
- The remote Auditor is tested only on loopback with throwaway identities; see
  `docs/AUDITOR_UAGENT.md` for its limits. Nothing here claims a tested integration with
  Claude Code or any external agent.
