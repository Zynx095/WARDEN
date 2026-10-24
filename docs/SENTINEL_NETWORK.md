# Sentinel Network: agents, contracts and orchestration

Status (2026-10-24, branch `integration/sentinel-final`): implemented and tested **locally**.
The full chain runs over real uAgents envelopes on loopback, with the Risk Analyst and Auditor
as separate processes, in `tests/integration/test_sentinel_network_live.py`. Nothing here has been
deployed or tried in ASI:One or Agentverse.

## Flow

```
ASI:One user ──ACP chat──▶ WARDEN (hosted uAgent, WardenACPHandler: the only chat handler)
  1 Intent        IntentAgent → warden.intent.proposal.v1 (in-process; rules, or ASI:One model if keyed)
  2 Risk Analyst  ──signed RiskRequest v2──▶ Risk Analyst uAgent ──signed RiskAssessment v2──▶
                  (or in-process LocalRiskAnalyst, same contract and analysis)
  3 Policy Guard  PolicyEngine: ALLOW | BLOCK | REQUIRE_APPROVAL   (sole authority)
  4 Approval      review card click or typed APPROVE/REJECT → WardenACPHandler.decide
                  → WardenAgent.approve_and_execute / reject_pending (re-checks policy, digest,
                    approver, expiry, single use, target state)
  5 Executor      RestrictedExecutor: HMAC token bound to digest + target state; revalidates paths
  6 Auditor       local OutcomeAuditor + optional Auditor uAgent (signed attestation, both required)
  7 Result        text report with workflow trace + terminal result card
```

| Stage | Component | Separate runtime identity? | Transport |
|---|---|---|---|
| Intent | `warden.agents.intent_agent.IntentAgent` over `IntentEngine` | no | function call (optional HTTPS call to the ASI:One model) |
| Risk Analyst | `warden.risk` (client), `warden.risk_analyst` (agent) | yes with `WARDEN_RISK_ANALYST=remote` | signed uAgents envelopes, `WardenRiskAnalystProtocol` 1.0.0 |
| Policy Guard | `warden.security.policy.PolicyEngine` | no | function call |
| Approval | `WardenACPHandler.decide` → `AuthorizationManager` (+ `StateStore`) | no | ACP chat from the user |
| Executor | `warden.execution.executor.RestrictedExecutor` | no | function call |
| Auditor | `warden.audit` (client), `warden.auditor` (agent) | yes with `WARDEN_REMOTE_AUDITOR=true` | signed uAgents envelopes, `WardenAuditorProtocol` 1.0.0 |

**Which paths are ACP.** Only user ↔ WARDEN uses the Agent Chat Protocol. WARDEN ↔ Risk Analyst
and WARDEN ↔ Auditor are typed request/response uAgents protocols over the same signed-envelope
transport, not ACP chat: ACP chat has no request/response pairing (acknowledgement plus an
asynchronous reply), so a structured contract over it would mean parsing JSON out of chat text.
In the default configuration (`local` analyst, remote Auditor off) there is exactly one agent
identity; the stages are separate components, not separate agents.

## Intent proposal (`warden.intent.proposal.v1`)

`proposal_id` (becomes the action id), `request_id` (the chat message), `operation`, `target`,
`destination`, `content_sha256`, `content_length`, `reason`, `source` (`deterministic` or
`llm`), `target_named_by_user`, `assumptions` (e.g. an inferred target, or a path outside the
workspace that the parser narrowed to a file name). Parser output is untrusted: unsupported
operations, control characters, oversized targets or content (>100000 characters), renames
without destination and more than 10 actions per request are dropped with a reason. The proposal
is recorded on the `PROPOSED` audit event. No execution permission, no authority.

## Risk Analyst contract (`warden.risk.contract`, v2)

`RiskRequest`: `request_id`, `nonce`, `action_id`, `correlation_id`, `action_digest` (`''` if the
action could not be bound inside the workspace), `operation`, workspace-relative `target`,
`requested_target` (as proposed), `destination`, `content_sha256`, `content_length`,
`content_preview` (first 2000 characters of user-supplied content to be written; never a file
that was read), `target_state` / `destination_state` (exists, kind, size, sha256 as observed),
`request_text` (≤4000), `batch_size`, `protected_names`, `issued_at`, `expires_at`.

`RiskAssessment`: echoes `request_id`, `nonce`, `action_id`, `correlation_id`, `action_digest`;
adds `analyst_address`, `risk_level` (LOW|MEDIUM|HIGH|CRITICAL), `recommendation`
(`ALLOW_CANDIDATE` | `ESCALATE` | `BLOCK_CANDIDATE`), `uncertainty`, up to 16 `findings`
(`code`, `severity`, `evidence` ≤200), `summary`, `assessed_at`, `signature`
(`Identity.sign_digest` over the canonical JSON of all other fields).

Finding codes: `DESTRUCTIVE_IMPACT`, `PROTECTED_TARGET`, `SENSITIVE_NAME`, `UNRESOLVED_TARGET`,
`PATH_TRAVERSAL`, `SYMLINK_TARGET`, `OVERWRITE`, `COLLATERAL_EFFECT`, `EXCESSIVE_SCOPE`,
`AMBIGUOUS_REQUEST`, `AUTHORITY_CLAIM`, `CONTENT_INJECTION`, `UNCERTAIN_STATE`. The analysis
(`warden.risk.analysis.analyze`) is deterministic, with no filesystem, network or model access.

## Authority boundaries

- The assessment is advice. `PolicyEngine.evaluate` never sees it; approval and execution never
  read it. A recommendation can neither unblock nor block (`tests/risk/test_risk_pipeline.py`).
- One deterministic rule depends on the assessment's *availability*, not its content: with
  `WARDEN_RISK_REQUIRED=true`, a change that policy would allow needs approval when no valid
  assessment was obtained (`WDN-006`). Off by default.
- The Risk Analyst agent holds no WARDEN key or token and does not touch the workspace. It answers
  only the configured requester address.
- Its text is shown as "Risk (advisory, not an authorization)", sanitized and length-limited.

## Approval identity

`WARDEN_APPROVAL_MODE=self` (local default): the requester or a configured approver may approve.
`independent`: only an address in `WARDEN_APPROVER_ADDRESSES` other than the requester may
approve; the requester may still reject. Both are stored in the pending record, so typed commands
and card clicks are held to them alike, also after a restart. Hosted mode requires the mode to be
set explicitly. Identity is the sender address the uAgents transport authenticates; whether
ASI:One gives each user a distinct address has not been verified.

## Failure handling

| Condition | Result |
|---|---|
| analyst unreachable, timeout, transport error | risk `UNAVAILABLE` (trace: unavailable / timed out); policy decides as usual (`WDN-006` if required) |
| assessment malformed, unsigned, wrong signer, tampered, expired, or bound to another request/action/correlation/digest | `UNAVAILABLE`, reason recorded |
| analyst raises | `UNAVAILABLE`; the pipeline never breaks |
| duplicate delivery to the analyst | same signed answer; reused `request_id` with a new nonce is ignored |
| request from a sender other than the allowed requester | analyst stays silent → `UNAVAILABLE` |
| `WARDEN_RISK_ANALYST=remote` without address or analyst | startup refused |
| duplicate chat message (also after restart) | cached reply / notice; nothing re-runs |
| stale, expired, replayed, mismatched or unauthorized approval | refused, request unchanged (or `EXPIRED`) |
| target or policy changed while pending | request invalidated / cancelled |
| executor failure | `FAILED`, no success claimed |
| Auditor timeout, unreachable, forged or mismatched attestation | `UNVERIFIED`; a valid attestation reporting a problem → `FAILED` |

## Correlation

One `action_id` (= `proposal_id` = `correlation_id`) and one canonical `action_digest` go through
every stage: proposal audit event, risk request and assessment, risk audit event, pending record,
card selection, HMAC token, audit request and attestation, final audit event
(`test_every_stage_is_correlated_by_the_same_action_id_and_digest`).

## Running separate peers

```
# Risk Analyst process (loopback only; needs its own seed, which you create and authorize)
WARDEN_RISK_ANALYST_SEED=<its own seed>  WARDEN_RISK_ANALYST_ALLOWED_REQUESTER=<WARDEN address>
python -m warden.risk_analyst

# WARDEN process
WARDEN_RISK_ANALYST=remote  WARDEN_RISK_ANALYST_ADDRESS=<analyst address>
WARDEN_RISK_ANALYST_ENDPOINT=http://127.0.0.1:8002/submit
```

The Auditor works the same way (`python -m warden.auditor`, `WARDEN_AUDITOR_*`,
`WARDEN_AUDITOR_ENDPOINT`). Each peer must be its **own process**: uAgents delivers a reply to an
agent in the same process locally instead of answering the synchronous request.

## Not done / not verified

- The Intent stage is in-process, not a separate agent.
- No deployment and no ASI:One or Agentverse test.
- The container image runs only WARDEN; sidecar peers need a process supervisor or separate
  containers and two new identities.
- All components run as the same OS user unless deployed separately; a distinct uAgent address is
  a distinct identity, not privilege isolation.
