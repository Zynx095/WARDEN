# WARDEN — Agentverse and ASI:One Integration Guide

This document separates what the installed SDK **does** (read directly from its source, uAgents 0.26.1 /
uagents-core 0.4.12), what WARDEN has **verified locally**, and what **needs your Agentverse
account** and has therefore **not been verified**. Nothing here was run against external live Agentverse services.

---

## 1. The five things people call "connected"

They are different, independent states. Having one does not imply the next.

| # | State | What it means | Needs | WARDEN status |
|---|---|---|---|---|
| 1 | **Local-only uAgent** | Agent runs on your machine, listens on `127.0.0.1:<port>`, ACP handlers attached. Nobody outside the machine can reach it. | Nothing external | **Implemented and locally tested.** Default mode. |
| 2 | **Mailbox connectivity** | The agent polls an Agentverse-hosted mailbox for messages, so it needs no inbound open port. | An Agentverse account; the mailbox provisioned for this agent address | **Code path implemented (`--mailbox`).** Provisioning requires user Agentverse browser session. |
| 3 | **External endpoint registration** | The agent publishes a public HTTPS URL; senders deliver directly to `POST /submit`. | A public HTTPS URL (tunnel or server), `--bind-all` or a reverse proxy | Supported via `--endpoint`. **Not recommended.** Exposes the agent directly to the internet. |
| 4 | **Agentverse discovery** | The agent has an Agentverse profile, is registered with Almanac, and is findable by search / ASI:One routing. | 2 or 3 above, plus published protocol manifest (`--publish-manifest`) | **Code path implemented.** Awaiting external registration. |
| 5 | **ASI:One conversation** | A user in ASI:One reaches the agent and the chat completes end to end. | 4 above, and a working live session | **Handler verified in mock tests.** Live session not yet run. |

Local-only operation (state 1) is fully functional and needs no external credentials. The ACP handler is
exercised in tests with mocked contexts, not against a live peer.

---

## 2. What the SDK source shows (verified from `site-packages`)

### 2.1 Identity Derivation
* `Agent(seed=...)` derives its address using `Identity.from_seed(seed, 0)`.
* The address depends solely on the seed; it does not depend on the agent name, port, or host environment.
* Same seed ⇒ identical `agent1q...` address across every restart.
* WARDEN's `python -m warden.identity address` and the runner use the same derivation.

### 2.2 Startup Almanac Active-Status Request (Source Inspection)
* **When it occurs:** In `Agent.run_async()`, `Agent.setup()` schedules `self.run_startup_tasks()`, which executes:
  ```python
  await self._update_agent_status(active=True)
  ```
  On shutdown, if `_mark_inactive_on_shutdown` is True (the default), `await self._update_agent_status(active=False)` is executed.
* **Network destination:** HTTP POST to `{almanac_api}/agents/{agent_address}/status` (default: `https://agentverse.ai/v1/almanac/agents/<address>/status`).
* **Identity data transmitted:** The payload is an instance of `AgentStatusUpdate`:
  ```json
  {
    "agent_identifier": "agent1q...",
    "is_active": true,
    "timestamp": 1792760703,
    "signature": "sig1..."
  }
  ```
  The payload is signed using `status.sign(self._identity)`. It contains the public agent identifier, the active boolean flag, a timestamp, and a cryptographic signature.
* **Secrets protected:** The agent seed, private key, and mnemonic are **never** transmitted.
* **On-chain / FET expenditure:** **Zero.** This is a REST API call to the Almanac web service, **not** an on-chain CosmWasm transaction. No gas is spent, no wallet funds are needed, and no tokens are burned.
* **Is it required?** **No.** `update_agent_status` wraps the network call in `with contextlib.suppress(Exception): ...`. If the agent is offline or the Almanac API is unreachable, the exception is safely suppressed. The agent continues running locally.
* **Can it be disabled?** uAgents 0.26.1 provides no `mark_active_on_startup` constructor argument. Shutdown status updates can be disabled via `mark_inactive_on_shutdown=False`.
* **Evidence confirming occurrence:**
  - Success: SDK logs `INFO: Agent registration status updated to active`
  - Network failure / offline: SDK logs `EXCEPTION: Failed to update agent registration status: ...` (non-fatal)

### 2.3 Mailbox Architecture and Provisioning
* `Agent(mailbox=True)` sets the agent's target endpoint to `agentverse.mailbox_endpoint` (`https://agentverse.ai/v2/agents/mailbox/submit`) and instantiates a `MailboxClient`.
* **No `endpoint` with `mailbox=True`:** In `uagents 0.26.1`, setting `endpoint` (e.g. `endpoint="http://127.0.0.1:8000/submit"`) overrides and **disables** mailbox mode, setting `_use_mailbox = False` and `_mailbox_client = None`. **Do not pass `endpoint` when using `mailbox=True`.**
* **No Mailbox Key in 0.26.1:** `parse_agentverse_config` discards anything before `@`. `AGENTVERSE_MAILBOX_KEY` is obsolete and cannot authenticate anything; WARDEN treats it only as a deprecated trigger that selects mailbox mode with a warning.
* **Polling Loop:** `MailboxClient._check_mailbox_loop()` continuously polls `GET {agents_api}/{address}/mailbox` with `Authorization: Agent <attestation>`, where the attestation is signed by the agent's private key.
* **Unprovisioned status:** If the mailbox has not yet been registered on Agentverse, the mailbox API responds with **HTTP 404**, and the agent logs:
  `Agent mailbox not found: create one using the agent inspector`
* **Provisioning Handshake (Browser-assisted `/connect`):**
  1. The agent starts an embedded ASGI server bound to `127.0.0.1:<port>` with `enable_agent_inspector=True` (default).
  2. The agent logs and prints an inspector URL:
     `https://agentverse.ai/inspect/?uri=http%3A//127.0.0.1%3A<port>&address=<agent_address>`
  3. The operator signs into Agentverse in a browser and opens this inspector URL.
  4. The browser issues a `POST /connect` to the local agent containing the user's Agentverse session token (`user_token`).
  5. The local agent contacts Agentverse (`GET {identity_api}/{address}/challenge`) with `Bearer {user_token}` to fetch a cryptographic challenge.
  6. The local agent signs the challenge with its identity private key and returns the proof (`POST {identity_api}`).
  7. The local agent registers its details, endpoints, and profile (`POST {agents_api}`).
  8. Agentverse provisions the mailbox for that agent address. Subsequent polls return HTTP 200 with message envelopes.

### 2.4 Protocol Manifest Publication & Discovery
* Protocol manifests describe the interface, schemas, and interaction models of an agent.
* In uAgents, `agent.include(protocol, publish_manifest=True)` uploads the protocol's machine-readable JSON schema to `{almanac_api}/manifests`.
* WARDEN supports manifest publishing via `--publish-manifest` (or `AGENTVERSE_PUBLISH_MANIFEST=true`).
* When enabled, WARDEN's `AgentChatProtocol` (v0.3.0) manifest is registered in Almanac, enabling Agentverse search and ASI:One to index and route conversational interactions to WARDEN.

### 2.5 Security Invariants & Approver Authorization
* **Loopback binding:** WARDEN enforces `uagents.asgi.HOST = "127.0.0.1"` (`restrict_bind_host`) unless `--bind-all` is explicitly passed.
* **Private Network Access (PNA) CORS:** WARDEN's ASGI runner automatically includes `Access-Control-Allow-Private-Network: true` on OPTIONS preflight responses so that modern browsers can reach loopback REST handlers from `https://agentverse.ai`.
* **Approver isolation:** By default, only the sender who requested an action can approve it. However, in a public chat context (e.g. ASI:One), any remote sender is the requester of their own proposals.
* **Before public exposure:** The operator must configure `WARDEN_APPROVER_ADDRESSES` in `.env` with their personal agent address. When set, only those designated addresses (or the original requester) can authorize destructive operations.

---

## 3. ACP Implementation Review

| Property | Status | Evidence |
|---|---|---|
| Uses official `chat_protocol_spec` (AgentChatProtocol 0.3.0) | Verified | `test_protocol_registers_chat_spec_and_handlers` compares the digest |
| Handlers for `ChatMessage` and `ChatAcknowledgement` registered | Verified | `test_registered_handler_acks_then_replies_to_sender`, `test_acknowledgement_handler_registered` |
| Ack sent before the reply, both to the sender | Verified (mock context) | `test_registered_handler_acks_then_replies_to_sender` |
| Incoming content validated | Pydantic via uagents-core; text length capped at 4000 chars; empty input handled | `test_oversized_message_rejected_without_action`, `test_empty_message_returns_ack_and_guidance` |
| Handler errors contained | Verified: generic reply, no details, only exception type logged | `test_internal_error_returns_safe_reply_and_ack` |
| Every proposal goes through deterministic policy | Verified: ACP only calls `WardenAgent.handle_action_request` | `test_end_to_end_workflow`, adversarial tests |
| Outcomes independently verified | Verified: auditor re-reads the filesystem | `test_audit`, demo step 7 |
| Approvals | Requester or `WARDEN_APPROVER_ADDRESSES` can approve; replays fail without re-executing | `test_other_sender_cannot_approve`, `test_replayed_approval_...` |
| Secrets not in replies/logs | Seed never appears; workspace paths are scrubbed from replies | `test_reply_never_contains_agent_seed`, `test_workspace_paths_scrubbed_from_replies` |
| LLM network errors | Fall back to the deterministic parser | `test_llm_network_error_falls_back_to_deterministic_parser` |

---

## 4. Step-by-Step Operator Setup Procedure

Follow these steps in sequence. Run `.\scripts\doctor.ps1` to verify configuration between steps.

### Step 1: Pre-flight Verification
Confirm that your local environment is sound:
```powershell
.\scripts\doctor.ps1
.\scripts\test.ps1
.\scripts\demo.ps1
```
Expected: Doctor reports 24 passed (with warnings for optional unconfigured mailbox/ASI:One key), 192 tests pass, and demo reports 12 independent checks passed.

### Step 2: Start WARDEN in Mailbox Mode
Launch the agent with mailbox mode enabled:
```powershell
.\scripts\run.ps1 -Mailbox
```
Console output will display:
```
[STARTING] WARDEN agent agent1q0kewgd2uyceeqrfn9jdln75nhwvfk7pmycaacqvcqm8qtxptsea6szeql7
  Config file: D:\AI\WARDEN\.env
  Mode:        mailbox (configured, Agentverse provisioning not verified)
  Listening:   127.0.0.1:8000 (loopback only)
  Inspector:   https://agentverse.ai/inspect/?uri=http%3A//127.0.0.1%3A8000&address=agent1q0kewgd2uyceeqrfn9jdln75nhwvfk7pmycaacqvcqm8qtxptsea6szeql7
  Note:        If mailbox is not yet provisioned on Agentverse, open the
               Inspector URL above in your browser to complete connection.
  Browser tip: If the Inspector shows 'Check your agent' instructions, your
               browser is blocking mixed-content from HTTPS (agentverse.ai)
               to local HTTP. In Chrome/Edge: click site settings -> allow
               'Insecure content' for agentverse.ai and refresh the page.
```
*Note: Before provisioning, the agent log will periodically show:*
`[WARN] Agent mailbox not found: create one using the agent inspector`

### Step 3: Complete Mailbox Provisioning in Agentverse
1. Keep `.\scripts\run.ps1 -Mailbox` running in your terminal.
2. In your web browser, log in to your account at [https://agentverse.ai](https://agentverse.ai).
3. Navigate to the Inspector URL printed in Step 2:
   `https://agentverse.ai/inspect/?uri=http%3A//127.0.0.1%3A8000&address=agent1q0kewgd2uyceeqrfn9jdln75nhwvfk7pmycaacqvcqm8qtxptsea6szeql7`
4. **If the Inspector displays "Check your agent" instructions:**
   - This popup is a generic frontend fallback caused by browser security blocking cross-origin HTTP calls from a public HTTPS page (`agentverse.ai`) to localhost (`http://127.0.0.1:8000`).
   - **Do NOT add `endpoint=("http://127.0.0.1:8000/submit")` to your code.** In uAgents 0.26.1, adding `endpoint` overrides and disables `mailbox=True`.
   - **In Google Chrome / Microsoft Edge:**
     1. Click the "View site information" (tune / padlock icon) on the left side of the address bar next to `https://agentverse.ai`.
     2. Click **Site settings**.
     3. Locate **Insecure content** and change it from *Block (default)* to **Allow**.
     4. Return to the Inspector tab and refresh the page (F5).
   - **In Brave:**
     1. Click the Brave Shields (lion icon) in the address bar.
     2. Toggle Shields **DOWN** for `agentverse.ai` and refresh the page.
5. Once the browser connects, the Inspector UI will display WARDEN's agent details (`agent1q0kew...`). Click **Connect** and select **Mailbox**.
6. The browser issues `POST /connect` to `http://127.0.0.1:8000/connect`, completing the cryptographic challenge-response registration.

### Step 4: Confirm Mailbox Connectivity
Look at the terminal where WARDEN is running:
- You will see:
  `[INFO] Successfully registered as mailbox agent in Agentverse`
- On the next poll interval (5s), the 404 warning stops, and `MailboxClient` polls successfully.
- In your Agentverse dashboard ([https://agentverse.ai/agents](https://agentverse.ai/agents)), WARDEN will appear as an active **Mailbox** agent.

### Step 5: Publish Protocol Manifest for Discovery
Once mailbox connectivity is verified, restart WARDEN with manifest publishing enabled:
```powershell
.\scripts\run.ps1 -Mailbox -PublishManifest
```
Terminal logs will confirm:
`[INFO] Manifest published successfully: AgentChatProtocol`
Your agent's capabilities are now indexed in Almanac and searchable by ASI:One.

### Step 6: Test an ASI:One Conversation
1. Open [https://asi1.ai](https://asi1.ai) or your ASI:One client.
2. Search for WARDEN by name (`warden-verification-agent`) or address (`agent1q0kewgd2uyceeqrfn9jdln75nhwvfk7pmycaacqvcqm8qtxptsea6szeql7`).
3. Send a test message: `"Read README.txt"`.
4. Send a mutation request: `"Clean up temporary files in the workspace"`.
5. Observe the `[AWAITING APPROVAL]` response with the action ID.
6. Reply with: `APPROVE <action-id>`.
7. Verify that WARDEN executes the operation, ground-truth verifies the outcome, and replies with `[VERIFIED]`.

---

## 5. Required Credentials & Where They Belong

| Credential | Where it belongs | Purpose | Sensitivity |
|---|---|---|---|
| **Agentverse Account** | Browser session at `agentverse.ai` | Authenticates your user account to provision the agent's mailbox via `/connect` | Private user account credentials |
| `AGENT_SEED` | `.env` (already populated) | Derives persistent cryptographic agent address (`agent1q...`) | **Critical secret.** Never commit or share |
| `WARDEN_APPROVER_ADDRESSES` | `.env` (optional, recommended before public exposure) | Comma-separated agent addresses permitted to approve destructive actions | Public addresses (`agent1q...`) |
| `ASI_ONE_API_KEY` | `.env` (optional) | Only needed if using ASI:One hosted LLM for intent parsing (otherwise rule-based deterministic parser handles commands) | Secret API key |

**Never enter or reveal seeds, private keys, or passwords in chat or public repositories.**

---

## 6. What is not claimed

* No live Agentverse registration, mailbox provisioning, or ASI:One chat has been performed yet in this environment.
* The ASI:One LLM intent endpoint (`https://api.asi1.ai/v1`, `asi1-mini`) is tested hermetically with mocks; actual live behavior depends on upstream API availability.
* WARDEN's deterministic policy engine and verification core do not depend on the LLM or external services.
