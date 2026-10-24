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
| Authorized approvers bound into each pending record and enforced by the authorization manager for every channel; explicit REJECTED and EXPIRED outcomes; approval, rejection, expiry and post-approval failure audited | `security/authorization.py`, `agents/warden_agent.py` | `integration/test_decisions.py` |
| Hosted entry point on a marked synthetic workspace (refuses real-data locations), https-only endpoint, health route without paths or secrets | `hosting/` | `hosting/` |
| Interactive cards are presentation only; clicks go through the single decision path | `integrations/cards.py`, `integrations/acp_adapter.py` | `unit/test_cards.py`, `integration/test_interactive_cards.py`, `hosting/test_hosted_live.py` |

## Added on `integration/sentinel-final`

| Control | Where | Tests |
|---|---|---|
| Independent-approver mode (`WARDEN_APPROVAL_MODE=independent`): requester can reject but never approve; bound in the pending record for every channel; hosted mode requires an explicit choice | `security/authorization.py`, `integrations/acp_adapter.py`, `hosting/config.py` | `security/test_approval_identity_overwrite_persistence.py`, `acceptance/` |
| WRITE over an existing file needs approval; RENAME onto an existing file is blocked (`WDN-005`) | `security/policy.py` | same, `unit/test_audit_strength.py` |
| Policy re-evaluated at approval; a request policy now blocks is cancelled | `agents/warden_agent.py` | same |
| Durable approvals, one-time consumption before the token exists, INTERRUPTED outcomes, recovery of expired/rejected/consumed state, dedup across restarts; corrupt store refuses startup | `security/state_store.py`, `security/authorization.py` | same, `acceptance/` |
| Executor revalidates path and refuses symlink substitution just before mutating; exclusive CREATE; atomic WRITE; RENAME never replaces | `execution/executor.py` | `security/test_executor_hardening.py` |
| Hash-chained audit log, verified by doctor | `audit/events.py`, `doctor.py` | `unit/test_audit_chain.py` |
| Risk Analyst (advisory, signed, request-bound); optional `WARDEN_RISK_REQUIRED` | `risk/`, `risk_analyst/` | `risk/`, `integration/test_sentinel_network_live.py` |
| Intent proposals validated and versioned; parser output untrusted | `agents/intent_agent.py` | `unit/test_intent_agent.py` |
| SDK inspector routes disabled when hosted; request body cap | `hosting/server.py`, `agents/run_agent.py` | `hosting/` |

## Open (not addressed)

- Policy, executor and auditor share one process, OS user and signing key. The local auditor is
  an additional check, not an isolated boundary. No OS-level sandbox.
- `self` approval mode (local default; must be chosen explicitly when hosted) lets a requester
  approve their own request.
- Whether ASI:One gives each user a distinct sender address is unverified; approver identity
  rests on it.
- Collateral detection covers the directories of the touched paths, not the whole workspace tree.
- The audit chain detects edits, not a consistent rewrite by someone with write access.
- A small window remains between the final revalidation and the filesystem call (same-user
  attacker on the host); no file locking.
- Slow-client / connection-level DoS protection is left to the hosting proxy; disk quotas are not
  enforced beyond the 100000-character content limit per proposal.
- Filenames and user text still reach the LLM intent prompt without provenance tagging.
- Not production ready. There is no OS-level privilege isolation anywhere: WARDEN and the
  Auditor are separate uAgent identities, but by default run as the same OS user on one
  machine. External routing (Almanac/mailbox/remote endpoints), multi-host deployment and
  third-party agents are untested.
- Remote verification blocks WARDEN's event loop for up to `WARDEN_AUDITOR_TIMEOUT_SECONDS`
  (default 10 s) per mutating action; the wait is bounded, not asynchronous.
- A remote Risk Analyst likewise blocks for up to `WARDEN_RISK_ANALYST_TIMEOUT_SECONDS` (5 s).
- Paths are case-folded for digests and snapshots (verified on Windows, where lookups are
  case-insensitive); case-sensitive filesystems are unsupported for remote mode. The container
  image is Linux (case-sensitive): keep `WARDEN_REMOTE_AUDITOR` off there until this is fixed.
- The test suite has been run on Windows only. Linux (the container platform) is untested.
- Test hermeticity: the suite clears the security-relevant `WARDEN_*` variables per test;
  `7fb3ec2` is an intermediate commit whose remote tests do not collect (the Auditor package
  is adapted in the next commit), so use `fdfc42c` or `8cbda4a` and later as checkpoints.
- The remote Auditor is tested only on loopback with throwaway identities; see
  `docs/AUDITOR_UAGENT.md` for its limits. Nothing here claims a tested integration with
  Claude Code or any external agent.
