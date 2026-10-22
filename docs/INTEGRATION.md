# WARDEN — Agentverse and ASI:One Integration Guide

This document separates what the installed SDK **does** (read from its source, uAgents 0.26.1 /
uagents-core 0.4.12), what WARDEN has **verified locally**, and what **needs your Agentverse
account** and has therefore **not been verified**. Nothing here was run against Agentverse.

## 1. The five things people call "connected"

They are different, independent states. Having one does not imply the next.

| # | State | What it means | Needs | WARDEN today |
|---|---|---|---|---|
| 1 | **Local-only uAgent** | Agent runs on your machine, listens on `127.0.0.1:<port>`, ACP handlers attached. Nobody outside the machine can reach it. | Nothing external | Implemented and locally tested. Default mode. |
| 2 | **Mailbox connectivity** | The agent polls an Agentverse-hosted mailbox for messages, so it needs no inbound port. | An Agentverse account; the mailbox provisioned for this agent address | Code path implemented (`--mailbox`). **Provisioning not performed, not verified.** |
| 3 | **External endpoint registration** | The agent publishes a public HTTPS URL; senders deliver directly to `POST /submit`. | A public HTTPS URL (tunnel or server), `--bind-all` or a reverse proxy | Supported via `--endpoint`. **Not performed, not verified.** Exposes the agent to the internet. |
| 4 | **Agentverse discovery** | The agent has an Agentverse profile, is registered with Almanac, and is findable by search/ASI:One routing. | 2 or 3 above, plus registration and (recommended) a published protocol manifest | **Not performed, not verified.** |
| 5 | **ASI:One conversation** | A user in ASI:One reaches the agent and the chat completes end to end. | 4 above, and a working live session | **Not performed, not verified.** |

Local-only operation (state 1) is fully functional and needs no credentials. The ACP handler is
exercised in tests with mocked contexts, not against a live peer.

## 2. What the SDK source shows (verified by reading `site-packages`)

* **Identity.** `Agent(seed=...)` derives its address with `Identity.from_seed(seed, 0)`. The address
  does not depend on the agent name or port. Same seed ⇒ same `agent1q...` address. WARDEN's
  `python -m warden.identity address` and the runner use the same derivation, and a test asserts it
  equals `Agent(...).address`.
* **Mailbox.** `Agent(mailbox=True)` sets the endpoint to Agentverse's mailbox URL and starts a
  `MailboxClient`. There is **no mailbox-key parameter** in this SDK version: `parse_agentverse_config`
  discards anything before `@`. `AGENTVERSE_MAILBOX_KEY` therefore cannot authenticate anything; WARDEN
  keeps it only as a deprecated switch that selects mailbox mode and logs a warning.
* **Provisioning.** With the inspector enabled (default) the agent serves `POST /connect` locally, taking
  an Agentverse **user token**. It fetches an identity challenge from Agentverse, signs it with the agent
  key, and registers the mailbox. The agent logs an inspector URL of the form
  `https://agentverse.ai/inspect/?uri=http%3A//127.0.0.1%3A<port>&address=<agent address>`; that page is the
  intended caller of the local `/connect` (inferred from the endpoint and log message; this flow was
  not exercised). This is the account-specific step.
* **Startup traffic even in local mode.** `run_startup_tasks` always sends a signed "active" status for the
  agent's public identifier to the Almanac API (failures are suppressed), and again "inactive" on
  shutdown. This is not registration, but it is outbound traffic. `report_events=False` (what WARDEN's
  local mode sets) disables telemetry, which is only sent for registered agents anyway.
* **Endpoint registration.** With `endpoint=` set, the default policy registers via the Almanac API
  first, then attempts ledger registration, which needs funds and is skipped quietly when
  funds are missing. WARDEN does not fund or create wallets.
* **Network binding.** The SDK's embedded server binds `0.0.0.0` through the module constant
  `uagents.asgi.HOST` and offers no constructor option. WARDEN sets that constant to `127.0.0.1`
  before `agent.run()` (`restrict_bind_host`), and refuses to start if the constant is missing so it
  never claims a loopback-only agent that is not. `--bind-all` is an explicit opt-out.
* **Protocol manifest.** `Agent.include(protocol, publish_manifest=False)` is the default. Publishing the
  chat protocol manifest is part of discovery (state 4) and is deliberately not done locally.

## 3. ACP implementation review

| Property | Status | Evidence |
|---|---|---|
| Uses official `chat_protocol_spec` (AgentChatProtocol 0.3.0) | Verified | `test_protocol_registers_chat_spec_and_handlers` compares the digest |
| Handlers for `ChatMessage` and `ChatAcknowledgement` registered | Verified | `test_registered_handler_acks_then_replies_to_sender`, `test_acknowledgement_handler_registered` |
| Ack sent before the reply, both to the sender | Verified (mock context) | same test |
| Incoming content validated | Pydantic via uagents-core; text length capped at 4000 chars; empty input handled | `test_oversized_message_rejected_without_action` |
| Handler errors contained | Verified: generic reply, no details, only exception type logged | `test_internal_error_returns_safe_reply_and_ack` |
| Every proposal goes through deterministic policy | Verified: ACP only calls `WardenAgent.handle_action_request` | `test_end_to_end_workflow`, adversarial tests |
| Outcomes independently verified | Verified: auditor re-reads the filesystem | `test_audit`, demo step 7 |
| Approvals | Only the requester or a `WARDEN_APPROVER_ADDRESSES` sender can approve; replays fail without re-executing | `test_other_sender_cannot_approve`, `test_replayed_approval_...` |
| Secrets not in replies/logs | Seed never appears; workspace paths are scrubbed from replies | `test_reply_never_contains_agent_seed`, `test_workspace_paths_scrubbed_from_replies` |
| LLM network errors | Fall back to the deterministic parser | `test_llm_network_error_falls_back_to_deterministic_parser` |

Known limitations: the handler is synchronous inside an async callback (fine for local use, a
bottleneck under load); pending approvals are in memory and lost on restart; WARDEN trusts the
sender address the SDK hands to the handler and has not been exercised against a real remote peer.

## 4. Next phase: connecting to Agentverse (not done)

No code redesign is needed; the steps are account-side. Do them deliberately, one at a time, and
re-run `.\scripts\doctor.ps1` between steps.

1. **Mailbox route (recommended; no public port).**
   1. `.\scripts\run.ps1 -Mailbox` and keep it running.
   2. Open the `agentverse.ai/inspect/...` URL printed in the log, sign in to Agentverse, and choose *Connect → Mailbox*. The browser calls the local `/connect` with your session; the secret never goes through WARDEN's code.
   3. Confirm in the Agentverse dashboard that the agent shows as a mailbox agent and is active. **Only then** can the mode be called connected.
2. **Discovery.** Add a profile (name, description, README), publish the chat protocol manifest (`publish_manifest=True` when including the protocol is the SDK mechanism) and confirm the agent is found by search. This changes what is public, so review it first.
3. **ASI:One.** Start a chat that targets the agent and complete the cleanup workflow end to end, including an `APPROVE` round trip. Record the shared-chat URL.
4. **Before any public exposure:** set `WARDEN_APPROVER_ADDRESSES` deliberately, keep the workspace disposable, and consider that any ASI:One user who can reach the agent can ask it to propose actions in its workspace.

## 5. What is not claimed

* No Agentverse registration, mailbox, discovery or ASI:One conversation has been verified.
* The ASI:One LLM intent path (`ASI_ONE_API_KEY`) is exercised only with mocks; the endpoint, model
  name and request format (`https://api.asi1.ai/v1`, OpenAI-compatible, `asi1-mini`) come from the
  repository's earlier configuration and were not checked against live documentation or the service.
* Sending a request through the LLM path discloses the user's text and workspace file names to the
  configured endpoint.
