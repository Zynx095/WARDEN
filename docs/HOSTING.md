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
- Interactive Cards are on by default in hosted mode (`WARDEN_INTERACTIVE_CARDS=false` turns
  them off). Every reply leads with the plain-text report, so ASI:One's documented fallback to
  text keeps the flow usable if a card is rejected. See docs/INTERACTIVE_CARDS.md.

## Remaining manual steps (need your accounts and permission)

1. **Choose a container host** with a stable public HTTPS URL and no cold-start sleep long
   enough to fail Agentverse's reachability checks. Build `Dockerfile` (not yet built or run
   here: no container runtime was available).
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
