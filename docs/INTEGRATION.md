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
| 2 | **Mailbox connectivity** | The agent polls an Agentverse-hosted mailbox for messages, so it needs no inbound open port. | An Agentverse account; the mailbox provisioned for this agent address | **Implemented (`--mailbox`) and tested locally.** Provisioning needs your account: the Inspector's Connect button or `mailbox connect` with an API key. `mailbox status` checks it. |
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
* **How the Inspector finds the agent:** the Inspector page (`https://agentverse.ai/inspect/?uri=...`, which embeds
  `https://agentverse.ai/inspector`) runs `fetch("http://127.0.0.1:<port>/agent_info")` from the browser once when the
  page loads, without custom headers. Any failure of that fetch, including the browser refusing it, shows
  **"Agent Not Found — Could not find this Agent on your local network."** The page does not retry that notice, so
  reload it after the agent is running.
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
* **Provisioning without a browser:** `python -m warden.agents.mailbox connect --confirm` (or
  `.\scripts\mailbox.ps1 connect -Confirm`) runs steps 5–8 itself through the same SDK function
  (`uagents.mailbox.register_in_agentverse`), authenticated with an Agentverse API key (`AGENTVERSE_API_KEY`)
  instead of the browser session. A test asserts it sends the same address, name, endpoints and protocols as the
  Inspector's `/connect`, plus WARDEN's public profile (README, description, starter prompts).
* **Checking it:** `python -m warden.agents.mailbox status` reads `/agent_info` the way the Inspector does, the
  public Almanac record, and `GET {agents_api}/{address}/mailbox` with the agent's own signed attestation
  (HTTP 404 = not provisioned). It never collects or prints messages.
* **Almanac contract funds:** `I do not have enough funds to register on Almanac contract` concerns the optional
  on-chain record. The default registration policy registers on the Almanac API first (free); that record is what
  resolves the agent to its mailbox. No FET is needed for mailbox operation.

### 2.4 Protocol Manifest Publication & Discovery
* Protocol manifests describe the interface, schemas, and interaction models of an agent.
* In uAgents, `agent.include(protocol, publish_manifest=True)` uploads the protocol's machine-readable JSON schema to `{almanac_api}/manifests`.
* WARDEN supports manifest publishing via `--publish-manifest` (or `AGENTVERSE_PUBLISH_MANIFEST=true`).
* When enabled, WARDEN's `AgentChatProtocol` (v0.3.0) manifest is registered in Almanac, enabling Agentverse search and ASI:One to index and route conversational interactions to WARDEN.

### 2.5 Security Invariants & Approver Authorization
* **Loopback binding:** WARDEN enforces `uagents.asgi.HOST = "127.0.0.1"` (`restrict_bind_host`) unless `--bind-all` is explicitly passed.
* **Browser access to the local agent:** WARDEN's runner answers with CORS headers and
  `Access-Control-Allow-Private-Network: true` (for browsers that still send Private Network Access preflights).
  Chromium 142+ (Chrome, Edge, Brave) instead enforces **Local Network Access**: a public site such as
  `https://agentverse.ai` may reach `127.0.0.1` only after the user allows it **"Apps on device"** (called "Local
  network access" before the permission was split). After a prompt is dismissed several times the browser stops
  showing it for that site; set the permission to Allow at
  `chrome://settings/content/siteDetails?site=https%3A%2F%2Fagentverse.ai` (`brave://…` / `edge://…`).
  "Insecure content" (mixed content) does not apply to `127.0.0.1`, and Brave Shields are not involved.
* **Inspector routes only for the Inspector:** the runner refuses `/agent_info`, `/messages`, `/connect` and
  `/disconnect` to any web origin other than `https://agentverse.ai` (requests without `Origin`, such as `curl`
  or `mailbox status`, still work). Otherwise any site a browser lets reach `127.0.0.1` could read the message
  history or register this identity in another account with a text/plain `POST /connect`. Proxy headers are
  trusted only from `127.0.0.1`.
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

## 4. Step-by-Step: the ASI:One mailbox agent

Mailbox mode keeps WARDEN on your machine (bound to `127.0.0.1`, no open port, no public URL) while Agentverse
holds a mailbox for its address; ASI:One and other agents send to the mailbox and WARDEN collects from it.
Run `.\scripts\doctor.ps1` whenever something looks off.

### Step 1: Pre-flight
```powershell
.\scripts\doctor.ps1
.\scripts\test.ps1
.\scripts\demo.ps1
```

### Step 2: Start WARDEN as a mailbox agent
```powershell
.\scripts\run.ps1 -Mailbox -PublishManifest -DemoWorkspace
```
`-DemoWorkspace` runs on the synthetic sandbox (`hosted_workspace\`: `README.txt`, `cache.tmp`, `debug.log`, a decoy
`production.env`) that the public Agentverse profile describes and the starter prompts use. The banner prints the
Inspector URL, the commands below and browser guidance. Before the mailbox exists the log shows
`Agent mailbox not found: create one using the agent inspector`, and
`I do not have enough funds to register on Almanac contract` is expected (see 2.3). Leave the agent running.

### Step 3: Connect the mailbox (once per agent address)

**Option A — Agentverse Inspector (browser):**
1. Sign in at [https://agentverse.ai](https://agentverse.ai) in the same browser.
2. Allow agentverse.ai to reach your machine: open
   `chrome://settings/content/siteDetails?site=https%3A%2F%2Fagentverse.ai` (Brave: `brave://…`, Edge: `edge://…`)
   and set **Apps on device** (Brave may call it *Localhost access*) to **Allow** (if a page instead asks to let agentverse.ai access apps or devices on
   this device, click **Allow**). Without this the Inspector shows "Agent Not Found" even though the agent is
   running. "Insecure content" and Brave Shields are unrelated; leave them alone.
3. Open (or reload) the Inspector URL from the banner. It must show your agent's address.
4. Click **Connect** → **Mailbox** → finish. The agent's terminal prints
   `Successfully registered as mailbox agent in Agentverse`.

**Option B — no browser (API key):**
1. Create a key at [https://agentverse.ai/profile/api-keys](https://agentverse.ai/profile/api-keys).
2. Add a line `AGENTVERSE_API_KEY=<your key>` to `.env` yourself (it is git-ignored; never paste the key into a chat
   or commit it).
3. Preview, then send:
   ```powershell
   .\scripts\mailbox.ps1 connect -DryRun
   .\scripts\mailbox.ps1 connect -Confirm
   ```
   It registers the agent as a Mailbox agent with WARDEN's public profile and verifies the mailbox afterwards. An
   Agentverse refusal (invalid key, address owned by another account, agent limit) is printed as Agentverse sent
   it, with the next step. If the address is already registered with another connection type (for example an
   earlier hosted/proxy registration), remove that first with `.\scripts\mailbox.ps1 disconnect -Confirm` (or
   under Agentverse → My Agents) and connect again. With the key in `.env`, `mailbox.ps1 status` also shows the
   agent's registration type in your account.

### Step 4: Verify
```powershell
.\scripts\mailbox.ps1 status
```
Expected: every check `PASS` — the local agent answers `/agent_info` for your address with the mailbox endpoint
and AgentChatProtocol, the browser-access headers are correct, the Almanac record routes to the mailbox and lists
the chat protocol, and **Agentverse mailbox: provisioned**. If the local checks pass but the Inspector still says
"Agent Not Found", the browser is blocking it (Step 3A.2). If the local check names a different agent, a stale
process holds the port: stop it (`Get-NetTCPConnection -LocalPort 8000` shows the owner). On
[https://agentverse.ai/agents](https://agentverse.ai/agents) the agent appears with a **Mailbox** tag.

### Step 5: Talk to it from ASI:One
1. Open [https://asi1.ai](https://asi1.ai) and address the agent by its address (or name,
   `warden-verification-agent`), or start a chat from its page on Agentverse. New agents can take a while to
   appear in ASI:One search; the address works as soon as the mailbox is connected.
2. Try `List the files in the WARDEN workspace`, then `Delete cache.tmp`.
3. WARDEN pauses with **AWAITING APPROVAL**. Approve by replying with the exact line it gives:
   `APPROVE <action-id> <digest>` (or `REJECT ...`). With `WARDEN_INTERACTIVE_CARDS=true` it also shows buttons.
4. `Delete production.env` is blocked by policy however it is phrased.

**Confirming that a real message reached WARDEN:** the agent's terminal logs
`Received ACP ChatMessage from <sender>` and `Sent ACP response to <sender>`, and
`.\scripts\mailbox.ps1 status` reports `Inbound chat messages: N received since the agent started` (counts and
sender only, never content).

Before inviting others: set `WARDEN_APPROVAL_MODE=independent` and `WARDEN_APPROVER_ADDRESSES` so requesters
cannot approve their own destructive actions (the banner warns while this is unset).

---

## 5. Required Credentials & Where They Belong

| Credential | Where it belongs | Purpose | Sensitivity |
|---|---|---|---|
| **Agentverse Account** | Browser session at `agentverse.ai` | Inspector path: authorizes the mailbox via `/connect` | Private user account credentials |
| `AGENTVERSE_API_KEY` | `.env` (optional) | Browser-free path: `mailbox.ps1 connect -Confirm`; hosted registration | **Secret.** Never commit or paste into chats |
| `AGENT_SEED` | `.env` (already populated) | Derives persistent cryptographic agent address (`agent1q...`) | **Critical secret.** Never commit or share |
| `WARDEN_APPROVER_ADDRESSES` | `.env` (optional, recommended before public exposure) | Comma-separated agent addresses permitted to approve destructive actions | Public addresses (`agent1q...`) |
| `ASI_ONE_API_KEY` | `.env` (optional) | Only needed if using ASI:One hosted LLM for intent parsing (otherwise rule-based deterministic parser handles commands) | Secret API key |

**Never enter or reveal seeds, private keys, or passwords in chat or public repositories.**

---

## 6. What is not claimed

* Mailbox provisioning, the Inspector flow in a real browser, Agentverse registration and an ASI:One chat have not
  been run from this repository's tests. The tests cover the local server (real HTTP on loopback, including a real
  Agent Chat Protocol exchange), the provisioning request, and the status checks with Agentverse mocked.
* The ASI:One LLM intent endpoint (`https://api.asi1.ai/v1`, `asi1-mini`) is tested hermetically with mocks; actual live behavior depends on upstream API availability.
* WARDEN's deterministic policy engine and verification core do not depend on the LLM or external services.
