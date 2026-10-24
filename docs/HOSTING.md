# Hosting WARDEN for ASI:One

Status: the hosted entry point, registration tool and tests are implemented. **WARDEN is not
deployed, the container image has not been built, and nothing has been tried in a real ASI:One
conversation.** Those steps need a container host, an Agentverse API key and your permission.

## Options considered (checked against current Fetch.ai docs)

| Option | Laptop can be off | Keeps the tested security stack | Verdict |
|---|---|---|---|
| Local agent + Agentverse mailbox | No: messages queue until the local agent fetches them | Yes | Not hosted |
| Agentverse-hosted agent (in-browser editor) | Yes | **No.** Globals reset after each invocation, imports are an allowlist and filesystem behaviour is undocumented; the executor, workspace and durable approval store would all need a redesign | Rejected |
| **External uAgent on a container host, registered on Agentverse with a public endpoint** | Yes | Yes, unchanged | **Selected** |

Sources: Agentverse "Launch ASI:One compatible uAgent", "Agentverse Hosted Agents", and
`uagents_core.utils.registration.register_chat_agent` (installed SDK 0.4.12).

## Architecture

```
ASI:One ──ACP──▶ Agentverse ──HTTPS POST /submit──▶ container: python -m warden.hosting.server
                                                     ├─ Intent → Risk (in-process) → Policy → Approval → Executor → Auditor
                                                     ├─ synthetic workspace /app/hosted_workspace (fixtures only)
                                                     ├─ /app/state (volume): approval state DB + hash-chained audit log
                                                     └─ GET /health
```

- **Approvals survive restarts** (`WARDEN_STATE_DB`, required when hosted; see
  [PERSISTENCE.md](PERSISTENCE.md)). A consumed approval is never usable again; an action
  interrupted mid-run is never re-run.
- **Approval mode must be chosen** (`WARDEN_APPROVAL_MODE`, required when hosted):
  `independent` with `WARDEN_APPROVER_ADDRESSES` (recommended: requesters cannot approve their
  own actions) or `self` (demo only).
- The workspace is created by `prepare_demo_workspace`, which refuses a filesystem root, home,
  the repository, a Git checkout or any non-empty unmarked directory. The marker and
  `production.env` are protected (no read, no change).
- Remote Auditor and remote Risk Analyst stay off until their identities are created and
  authorized. They must run as their own processes (sidecar or container), never inside WARDEN's.
- Interactive Cards are on by default when hosted; every reply leads with the text report.

## Endpoint exposure and request handling (uAgents 0.26.1 / uagents-core 0.4.12)

| Route | Served | Notes |
|---|---|---|
| `POST /submit` | yes | uAgents envelopes only. Agent senders must be signed; unsigned `user…` senders are refused by the signed chat handler. Only the Agent Chat Protocol is included. |
| `HEAD /submit` | yes | SDK readiness probe. |
| `GET /health` | yes | status, address, workspace readiness, remote-audit flag, endpoint scheme, approval mode, durable state, Risk Analyst mode. No paths, secrets or contents. |
| `/agent_info`, `/messages`, `/connect`, `/disconnect` | **no** | SDK inspector disabled: it guards `/connect` only by client IP while trusting any `X-Forwarded-For`, and `/connect` signs with the agent identity (reproduced in a test before the fix). |

- Bodies above `WARDEN_MAX_REQUEST_BYTES` (256 KiB) get HTTP 400; chat text above 4000
  characters is refused without action.
- Only `TextContent` is interpreted. Decisions are accepted only as `APPROVE|REJECT <id> <digest>`
  or a `warden.decision.v1` card selection, always through `WardenACPHandler.decide`.
- Duplicate deliveries return the cached reply (in memory) or a notice (after a restart).
- Handler errors are answered with a generic "no action was taken" reply; only the exception type
  is logged. Message text, seeds and keys are not logged.
- Timeouts: approvals `WARDEN_APPROVAL_TTL_SECONDS` (300 s), Risk Analyst
  `WARDEN_RISK_ANALYST_TIMEOUT_SECONDS` (5 s), Auditor `WARDEN_AUDITOR_TIMEOUT_SECONDS` (10 s).
  HTTP timeouts are uvicorn defaults (keep-alive 5 s); **slow-client protection is left to the
  platform's proxy**.

## Configuration (runtime, from the host's secret store / environment)

| Variable | Required | Value |
|---|---|---|
| `AGENT_SEED` | yes (secret) | WARDEN's identity; never in the image |
| `WARDEN_PUBLIC_ENDPOINT` | yes | `https://<host>/submit` |
| `WARDEN_APPROVAL_MODE` | yes | `independent` (with `WARDEN_APPROVER_ADDRESSES`) or `self` |
| `WARDEN_APPROVER_ADDRESSES` | for `independent` | comma-separated agent addresses |
| `WARDEN_STATE_DB` | yes (image default `/app/state/warden.db`) | on a persistent volume |
| `WARDEN_AUDIT_LOG` | image default `/app/state/audit.jsonl` | on the same volume |
| `PORT` | platform-provided | listening port |
| `AGENTVERSE_API_KEY` | only for `register --confirm` (secret) | keep out of the image |

## Build and local container check (not run here)

Docker is not available on the development machine (`docker` is not installed; WSL2 cannot start
because hardware virtualization is disabled). On a machine with Docker:

```
docker build -t warden-hosted:local .
docker volume create warden-state
docker run --rm -p 8000:8000 -v warden-state:/app/state \
  -e AGENT_SEED="<throwaway test seed>" \
  -e WARDEN_PUBLIC_ENDPOINT=http://127.0.0.1:8000/submit \
  -e WARDEN_HOSTED_ALLOW_INSECURE_ENDPOINT=true \
  -e WARDEN_APPROVAL_MODE=self \
  warden-hosted:local
curl -s http://127.0.0.1:8000/health                                       # "status":"ok", "durable_state":true
curl -s -o /dev/null -w "%{http_code}\n" http://127.0.0.1:8000/agent_info  # 404
```

Use a throwaway seed; the insecure-endpoint flag is for loopback only. Without Docker, the same
entry point runs directly: `python -m warden.hosting.server` with the variables above.

## Deployment steps (need your accounts and permission)

1. Choose a host with a stable public HTTPS URL, a persistent volume for `/app/state`, and no
   cold-start sleep long enough to fail Agentverse's reachability checks.
2. Build and push the image; set the runtime variables above in the host's secret store.
3. Deploy; check `GET https://<host>/health` → `"status":"ok"`, `"durable_state":true`, and the
   approval mode you chose.
4. Register: with `AGENTVERSE_API_KEY` set locally, `python -m warden.hosting.register --dry-run`,
   review the output, then `--confirm`.
5. Verify in ASI:One: list files; `Delete production.env` (BLOCKED); `Delete cache.tmp` → note the
   sender address WARDEN logs (decides whether `independent` mode works for you) → approve with the
   card or the exact text line → VERIFIED; a REJECT; an approval after expiry. Record it.
6. Only then describe WARDEN as hosted and reachable through ASI:One.

## Rollback

- Code: redeploy the previous image tag. The state schema is versioned; an older build refuses a
  newer database rather than misreading it.
- State: keep the volume. To start clean on purpose, stop the service, move `warden.db*` aside,
  reset the workspace volume (pending approvals are forgotten and stay unusable), restart.
- Registration: re-run `register --confirm` with the previous endpoint, or mark the agent inactive
  in Agentverse.

## Residual risks

- Approver identity depends on the sender address ASI:One uses (not verified). If many users share
  one address, `independent` mode cannot distinguish them.
- `self` mode lets a requester approve their own request.
- All stages run in one process as one OS user; no OS-level sandbox. Collateral detection covers
  only the touched directories.
- The audit hash chain detects edits but not a consistent rewrite by someone with write access.
- The SDK sends a signed "active" status update and, with an endpoint, Almanac registration and the
  chat manifest at startup. Expected in hosted mode; tests disable them.
