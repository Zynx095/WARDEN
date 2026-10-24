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
- No Auditor agent exists. Nothing in this repository claims a tested integration with
  Claude Code or any external agent.
