# Hosting WARDEN for ASI:One

Status: the hosted entry point, registration tool and tests are implemented. **WARDEN is not
deployed and has not been tested in a real ASI:One conversation.** Doing so needs an account
on a container host, an Agentverse API key and your permission to publish (see "Remaining
manual steps").

## Options considered (checked against current Fetch.ai docs)

| Option | Laptop can be off | Keeps the tested security stack | Verdict |
|---|---|---|---|
| Local agent + Agentverse mailbox | No: messages queue until the local agent fetches them | Yes | Not hosted |
| Agentverse-hosted agent (in-browser editor) | Yes | **No.** Hosted agents reset globals after each invocation, so pending approvals and the per-process signing key would not survive between the request and the approval; imports are an allowlist; filesystem behaviour is undocumented | Would need a redesign around agent storage; not the fastest safe path |
| **External uAgent on a container host, registered on Agentverse with a public endpoint** | Yes | Yes, unchanged | **Selected** |

Sources: Agentverse "Launch ASI:One compatible uAgent" (external agents need a public endpoint
Agentverse can reach), "Agentverse Hosted Agents" (globals reset per invocation; allowed
imports), and `uagents_core.utils.registration.register_chat_agent` (installed SDK 0.4.12),
which registers an endpoint with the chat-protocol digest so ASI:One can discover it.

## Selected architecture

```
ASI:One ──ACP──▶ Agentverse ──HTTPS POST /submit──▶ container: python -m warden.hosting.server
                                                     ├─ WARDEN pipeline (policy → approval → executor → verifier)
                                                     ├─ synthetic workspace /app/hosted_workspace (fixtures only)
                                                     └─ GET /health
```

- One long-running process holds pending approvals in memory. A restart drops them, which
  fails safe: an approval for a dropped request is refused and must be requested again.
- The workspace is created by `prepare_demo_workspace`, which refuses a filesystem root,
  home directory, the repository, a Git checkout, or any non-empty directory without the
  `.warden-demo-workspace` marker. Missing fixtures are restored at startup only; nothing is
  reset mid-session. The marker and `production.env` are protected files.
- `/health` reports status, address, workspace readiness and whether remote audit is on.
  It never returns paths, secrets or file content.
- The remote Auditor stays off (`WARDEN_REMOTE_AUDITOR` unset) until its identity and
  transport are separately verified.
- The Risk Analyst runs in-process by default (`WARDEN_RISK_ANALYST=local`). A separate
  Risk Analyst or Auditor agent must be its own process (sidecar or container), never inside
  WARDEN's process; see docs/SENTINEL_NETWORK.md.
- Interactive Cards are on by default in hosted mode (`WARDEN_INTERACTIVE_CARDS=false` turns
  them off). Every reply leads with the plain-text report, so ASI:One's documented fallback to
  text keeps the flow usable if a card is rejected. See docs/INTERACTIVE_CARDS.md.

## Endpoint exposure and request handling (reviewed against uAgents 0.26.1 / uagents-core 0.4.12)

| Route | Served | Notes |
|---|---|---|
| `POST /submit` | yes | uAgents envelopes only (`application/json`, envelope schema). Agent senders must carry a valid signature; unsigned `user…` senders are refused by the signed chat handler. Only the Agent Chat Protocol is included. |
| `HEAD /submit` | yes | SDK readiness probe used by Agentverse. |
| `GET /health` | yes | Status, agent address, workspace readiness, remote-audit flag, endpoint scheme. No paths, secrets or contents. |
| `/agent_info`, `/messages`, `/connect`, `/disconnect` | **no** | The SDK inspector is disabled in hosted mode. The SDK guards `/connect` and `/disconnect` only by client IP while trusting every `X-Forwarded-For` header, so a spoofed `127.0.0.1` reached `/connect`, which signs with the agent identity (reproduced in `tests/hosting/test_hosted_live.py` before the fix). |

- Request bodies above `WARDEN_MAX_REQUEST_BYTES` (default 256 KiB) are not buffered and get
  HTTP 400. Chat text above 4000 characters is refused without action.
- Payload validation: only `TextContent` is interpreted. Decisions are accepted only as
  `APPROVE|REJECT <id> <digest>` or a `warden.decision.v1` card selection, and always go
  through `WardenACPHandler.decide`. Action requests become `Action`s via the intent parser
  and then pass policy, approval, the restricted executor and verification unchanged.
- Duplicate deliveries (same sender and `msg_id`) return the cached reply; nothing re-runs.
- Every handler error is caught and answered with a generic "no action was taken" reply; only
  the exception type is logged. Message text, seeds and keys are not logged.
- Timeouts: approvals expire after `WARDEN_APPROVAL_TTL_SECONDS` (default 300 s); the remote
  Auditor (off) has `WARDEN_AUDITOR_TIMEOUT_SECONDS`. HTTP connection timeouts are uvicorn's
  defaults (keep-alive 5 s); slow-client protection is left to the platform's proxy.
- Secrets come only from the runtime environment (`AGENT_SEED`, optional `AGENTVERSE_API_KEY`).
  `.dockerignore` excludes `.env`, `*.env`, logs and workspaces; the image contains no secret.

## Container build status

Docker is **not available on the development machine** (`docker` is not installed, and WSL2
cannot start because hardware virtualization is disabled), so the image has not been built
or run. On a machine with Docker, from the repository root:

```
docker build -t warden-hosted:local .
docker run --rm -p 8000:8000   -e AGENT_SEED="<throwaway test seed>"   -e WARDEN_PUBLIC_ENDPOINT=http://127.0.0.1:8000/submit   -e WARDEN_HOSTED_ALLOW_INSECURE_ENDPOINT=true   warden-hosted:local
curl -s http://127.0.0.1:8000/health          # expect "status":"ok"
curl -s -o /dev/null -w "%{http_code}
" http://127.0.0.1:8000/agent_info   # expect 404
```

Use a throwaway seed for this local check; the insecure-endpoint flag is for loopback only.

## Remaining manual steps (need your accounts and permission)

1. **Choose a container host** with a stable public HTTPS URL and no cold-start sleep long
   enough to fail Agentverse's reachability checks. Build `Dockerfile` (not yet built or run
   here: see "Container build status").
2. **Set runtime secrets in the host's secret store**, never in the image: `AGENT_SEED` (the
   existing WARDEN identity, or a new one if you decide the public demo should have its own),
   `WARDEN_PUBLIC_ENDPOINT=https://<host>/submit`. Optionally `WARDEN_APPROVER_ADDRESSES`.
3. **Deploy and check** `GET https://<host>/health` returns `"status": "ok"`.
4. **Register**: locally, with `AGENTVERSE_API_KEY` set,
   `python -m warden.hosting.register --dry-run`, review the output, then `--confirm`.
5. **Verify in ASI:One**: search for the agent, then run the starter prompts: list files,
   `Delete production.env` (BLOCKED), `Delete cache.tmp` → approve with the exact line →
   VERIFIED, then a REJECT. Record the conversation.
6. Only then describe WARDEN as hosted and reachable through ASI:One.

## Residual risks

- **Approver identity depends on ASI:One.** WARDEN binds approval to the requesting sender
  address. Whether ASI:One gives each user a distinct sender address is not documented; if it
  does not, any user of the same ASI:One address could decide a request whose id and digest
  they know. Check the sender address in a real conversation before relying on this.
- Self-approval: without `WARDEN_APPROVER_ADDRESSES`, the requester approves their own request.
- WRITE over an existing non-protected file is auto-allowed.
- Same-process, same-user execution; no OS-level isolation between policy, executor and
  verifier. Collateral detection covers only the touched directories.
- The SDK sends a signed "active" status update and, with an endpoint, Almanac registration and
  the chat manifest at startup. These are expected in hosted mode; tests disable them.
