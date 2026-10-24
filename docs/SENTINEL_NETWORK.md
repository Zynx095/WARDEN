# Sentinel Network: multi-agent orchestration

Status (2026-10-24, branch `feature/sentinel-network`): implemented and tested **locally**.
The full chain runs over real uAgents envelopes on loopback in
`tests/integration/test_sentinel_network_live.py`. Nothing here has been deployed, and none of it
has been tried in ASI:One or Agentverse.

## Flow

```
ASI:One user ──ACP chat──▶ WARDEN (hosted uAgent)
                            1 Intent        IntentEngine (in-process; deterministic, or ASI:One LLM if keyed)
                            2 Risk Analyst  ──signed RiskRequest──▶ Risk Analyst uAgent ──signed RiskAssessment──▶
                                            (or in-process LocalRiskAnalyst, same contract)
                            3 Policy Guard  PolicyEngine: ALLOW | BLOCK | REQUIRE_APPROVAL  (sole authority)
                            4 Approval      review card / typed command → WardenACPHandler.decide
                            5 Executor      RestrictedExecutor, HMAC token bound to digest + target state
                            6 Auditor       local OutcomeAuditor + optional Auditor uAgent (signed attestation)
                            7 Result        text report + terminal result card
```

| Stage | Component | Separate agent? | Transport |
|---|---|---|---|
| Intent | `warden.agents.intent_engine.IntentEngine` | no (in-process) | function call |
| Risk Analyst | `warden.risk` (client), `warden.risk_analyst` (agent) | yes when `WARDEN_RISK_ANALYST=remote` | uAgents signed envelopes, `WardenRiskAnalystProtocol` 1.0.0 |
| Policy Guard | `warden.security.policy.PolicyEngine` | no | function call |
| Approval | `WardenACPHandler.decide` → `AuthorizationManager` | no | ACP chat (user) |
| Executor | `warden.execution.executor.RestrictedExecutor` | no | function call |
| Auditor | `warden.audit` (client), `warden.auditor` (agent) | yes when `WARDEN_REMOTE_AUDITOR=true` | uAgents signed envelopes, `WardenAuditorProtocol` 1.0.0 |

The user-facing interface is the Agent Chat Protocol. Agent-to-agent calls (WARDEN to the Risk
Analyst and to the Auditor) are **not** ACP chat messages: they are typed request/response
uAgents protocols over the same signed-envelope transport. ACP chat has no request/response
pairing (it is acknowledgement plus an asynchronous reply), so carrying a structured contract
over it would mean parsing JSON out of chat text. The typed protocols keep one schema per
message and let the receiving side validate it.

## Risk Analyst contract (`warden.risk.contract`)

`RiskRequest` (`warden.risk.request.v1`), WARDEN to analyst. No file content:
`request_id`, `nonce`, `action_id`, `action_digest` (the canonical digest; `''` if the action
could not be bound inside the workspace), `operation`, workspace-relative `target` and
`destination`, `content_sha256`, `content_length`, `target_state` / `destination_state`
(exists, kind, size, sha256 as WARDEN observed them), `request_text` (the instruction, at most
4000 characters), `batch_size` (actions produced by that instruction), `protected_names`,
`issued_at`, `expires_at`.

`RiskAssessment` (`warden.risk.assessment.v1`), analyst to WARDEN: echoes `request_id`,
`nonce`, `action_id`, `action_digest`; adds `analyst_address`, `risk_level`
(LOW|MEDIUM|HIGH|CRITICAL), `recommendation` (PROCEED|REVIEW|DO_NOT_PROCEED), `uncertainty`
(LOW|MEDIUM|HIGH), up to 16 `findings` (`code`, `severity`, `evidence` of at most 200 characters),
`summary`, `assessed_at`, `signature` (`Identity.sign_digest` over the canonical JSON of all
other fields).

Finding codes: `DESTRUCTIVE_IMPACT`, `PROTECTED_TARGET`, `SENSITIVE_NAME`, `UNRESOLVED_TARGET`,
`EXCESSIVE_SCOPE`, `AMBIGUOUS_REQUEST`, `AUTHORITY_CLAIM`, `UNCERTAIN_STATE`. The analysis
(`warden.risk.analysis.analyze`) is deterministic and has no filesystem, network or model access.

## Authority boundaries

- The assessment is advice. `PolicyEngine.evaluate` never sees it; approval and execution never
  read it. Tests show a PROCEED verdict cannot unblock or skip approval, and a DO_NOT_PROCEED
  verdict cannot block a policy ALLOW (`tests/risk/test_risk_pipeline.py`).
- The Risk Analyst agent holds no WARDEN key or token and does not touch the workspace.
- Shown to people as "Risk (advisory, not an authorization)"; its text is sanitized and
  length-limited because it comes from another agent.

## Failure handling

| Condition | Result |
|---|---|
| analyst unreachable, timeout (`WARDEN_RISK_ANALYST_TIMEOUT_SECONDS`), transport error | risk `UNAVAILABLE`; policy decides as usual |
| malformed, unsigned, wrong signer, tampered, expired, or bound to another request/action/digest | `UNAVAILABLE` (reason recorded) |
| analyst raises | `UNAVAILABLE`; the pipeline never breaks |
| duplicate delivery to the analyst | same signed answer from its cache; reused `request_id` with a new nonce is ignored |
| request from a sender other than the allowed requester | analyst stays silent → `UNAVAILABLE` |
| `WARDEN_RISK_ANALYST=remote` without an address, or no analyst supplied | startup refused (`ConfigError`) |
| duplicate chat message, stale/expired/replayed approval, changed target, auditor failure | unchanged from the existing pipeline: cached reply, `EXPIRED`/refused, invalidated, `UNVERIFIED` |

## Correlation

One `action_id` and one canonical `action_digest` go through every stage: the risk request and
assessment, the audit event of the risk stage, the pending approval record (which also keeps the
assessment), the card selection, the HMAC token, the audit request and attestation, and the
final audit event. `test_every_stage_is_correlated_by_the_same_action_id_and_digest` checks this.

## Running it

In-process (default, `WARDEN_RISK_ANALYST=local`): nothing to do.

As a separate agent (needs a second identity, which you must create and authorize):

```
# Risk Analyst process (loopback only)
WARDEN_RISK_ANALYST_SEED=<its own seed>  WARDEN_RISK_ANALYST_ALLOWED_REQUESTER=<WARDEN address>
python -m warden.risk_analyst

# WARDEN process
WARDEN_RISK_ANALYST=remote  WARDEN_RISK_ANALYST_ADDRESS=<analyst address>
WARDEN_RISK_ANALYST_ENDPOINT=http://127.0.0.1:8002/submit
```

The Auditor works the same way with `WARDEN_AUDITOR_*` and the new optional
`WARDEN_AUDITOR_ENDPOINT`. Run each peer as its **own process**: uAgents delivers a reply to an
agent living in the same process locally instead of answering the synchronous request, so a
peer inside WARDEN's process (for example in a Bureau) would never answer. In a single
container that means sidecar processes on loopback.

## Not done / not verified

- The Intent stage is in-process, not a separate agent.
- No deployment and no ASI:One or Agentverse test of any of this.
- The hosted container image runs only WARDEN; running the analyst and Auditor as sidecars needs
  a process supervisor in the image (or separate containers) and two new identities.
- Peers share the operator's trust domain unless deployed separately; a distinct uAgent address
  is a distinct identity, not privilege isolation.
