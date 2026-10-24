# Northstar demo: operator runbook

Everything here runs in PowerShell from the WARDEN checkout the live agent uses:
`D:\AI\WARDEN_final` (branch `feat/northstar-demo`). No command prints a seed, key or token.

## Facts about the live agent (checked 2026-10-25)

- It is the local agent `agent1qv9pt68m6ups8c9j22zz0a0rmmf5dp93q93vzvwlhx98x0h3yuknwk9jz46`, reached from
  ASI:One through its Agentverse mailbox (`mailbox.ps1 status`: mailbox provisioned, Almanac active,
  chat protocol listed). There is no hosted deployment; the agent only answers while this laptop
  runs it.
- The process running at the time was started on 2026-10-24 at 18:05 with
  `run_agent --mailbox --publish-manifest`. That means: workspace `temp_workspace` (empty, from
  `WARDEN_WORKSPACE_ROOT`), **no Interactive Cards** (`WARDEN_INTERACTIVE_CARDS` unset) and code from
  before the chat redesign. **Restart it as below before the demo.**
- Intent parsing is the rule-based parser (`ASI_ONE_API_KEY` is not set), the same one the
  validation used. Approval mode is `self`: the person chatting approves their own deletes.
- Audit log: `logs\audit.jsonl` (`WARDEN_AUDIT_LOG`), hash-chained.

## Setup (10 minutes before)

```powershell
cd D:\AI\WARDEN_final
git status -sb                                     # expect: ## feat/northstar-demo, clean
# 1. Stop the running agent: Ctrl+C in its window. Confirm nothing listens on 8000:
Get-NetTCPConnection -LocalPort 8000 -State Listen -ErrorAction SilentlyContinue   # expect: no output
# 2. Create or reset the demo workspace (only ever touches .\northstar_workspace):
.\.venv\Scripts\python.exe demo\northstar.py setup
# 3. Prove the scripted prompts still behave as documented (offline, about 2 s):
.\.venv\Scripts\python.exe demo\northstar_validate.py | Select-String "Result:"     # expect: 20 checks passed, 0 failed
# 4. Start the agent on the demo workspace with cards on (this window stays open during the demo):
$env:WARDEN_INTERACTIVE_CARDS = "true"
.\.venv\Scripts\python.exe -m warden.agents.run_agent --mailbox --publish-manifest --demo-workspace --workspace northstar_workspace
```

The start banner must show `Mode: mailbox`, `Listening: 127.0.0.1:8000 (loopback only)` and
`Workspace: synthetic demo workspace (fixtures only)`. It also prints an advisory that
`WARDEN_APPROVER_ADDRESSES` is unset: expected for this demo (self approval).

In a second PowerShell window:

```powershell
cd D:\AI\WARDEN_final
.\scripts\mailbox.ps1 status       # expect: Summary ... 0 failed (the "Inbound chat messages" WARN is fine before the first message)
.\scripts\doctor.ps1               # optional: configuration checks, prints no secret values
```

## Check that the live agent uses the expected configuration

1. In ASI:One send prompt 0, `List the files in the WARDEN workspace`. The listing must contain
   `README.md`, `config`, `src`, `tests`, `tmp`, `production.env`, `demo_manifest.json`. If it is
   empty or shows other files, the agent was not started with `--workspace northstar_workspace`.
2. The reply should come with a result card. If there is no card anywhere, the agent was started
   without `$env:WARDEN_INTERACTIVE_CARDS = "true"` in the same window (cards are optional; typed
   commands still work).
3. `.\scripts\mailbox.ps1 status` now reports `Inbound chat messages: 1 received`, and the agent
   window logs `Received ACP ChatMessage from …`.

Do one full rehearsal of PROMPT_CARDS.md in ASI:One, then reset (below) before judges arrive.
Note during the rehearsal whether the review card's **Approve** button works; if it does not,
plan to use the typed `APPROVE …` line.

## Reset between rehearsals

```powershell
# Ctrl+C the agent first (clears in-memory pending approvals), then:
.\.venv\Scripts\python.exe demo\northstar.py setup
$env:WARDEN_INTERACTIVE_CARDS = "true"
.\.venv\Scripts\python.exe -m warden.agents.run_agent --mailbox --publish-manifest --demo-workspace --workspace northstar_workspace
```

`setup` refuses any directory that is not empty unless it is a Northstar workspace it created
(WARDEN demo marker plus a Northstar `demo_manifest.json`), and it refuses the repository itself,
your home directory, filesystem roots and Git checkouts. It never touches `production.env`
anywhere else, the `.env` file or the Microblog clone.

## During and after the demo

```powershell
.\.venv\Scripts\python.exe demo\northstar.py check    # file states vs. the setup baseline; "Protected files unchanged: yes"
.\.venv\Scripts\python.exe demo\northstar.py audit    # audit events since setup, hash-chain check, final status per action
.\.venv\Scripts\python.exe demo\northstar.py audit --all   # the whole log
```

`check` exits non-zero if `production.env` differs from the baseline. After the full script expect:
`notes/release_note.txt created since setup`, `tmp/session_cache.tmp deleted since setup`,
everything else `unchanged`.

`audit` shows each action's events (PROPOSED for the proposal, then `PROPOSED (risk advice)` for
the advisory risk assessment, then the decision and outcome), then the final status per audit
reference. Approved actions show
`AUTHORIZED WDN-004-APPROVED` before `VERIFIED`. Audit references match the "Audit ref" lines in
the chat.

## Recovery

| Problem | Action |
|---|---|
| "Approval expired" | Approvals last 5 minutes. Send `Delete tmp/session_cache.tmp` again and approve promptly. |
| "Decision refused" | The approval did not come from the requesting chat, or its digest did not match. Send the delete prompt again and approve from the same chat, using the button or the exact `APPROVE` line. |
| Delete still asks for approval but the risk line says the file "does not exist"; approving gives "Action failed … Target does not exist" | The file is already gone (an earlier approval ran; validated). Reject instead, show `northstar.py check`, reset after the demo. |
| Note contains "Default generated content." | Curly quotes were used in prompt A. It is harmless; retype with straight quotes for a matching note, or move on. |
| No reply | Agent window running? `mailbox.ps1 status` all PASS? Resend once; replies normally arrive within seconds. |
| Wrong files listed | Restart the agent with `--demo-workspace --workspace northstar_workspace` (Setup step 4). |
| `Port 8000 is already in use` on start | An earlier agent is still running: `Get-NetTCPConnection -LocalPort 8000` shows its process; stop it. |
| `check` says production.env changed | Stop the demo and investigate: WARDEN blocks every change to it, so something outside WARDEN wrote to it. |

## Cleanup

```powershell
# Ctrl+C the demo agent. Optional: restart your usual configuration
.\scripts\run.ps1 -Mailbox -PublishManifest
Remove-Item -Recurse -Force .\northstar_workspace     # optional; git-ignored and recreated by setup
Remove-Item Env:\WARDEN_INTERACTIVE_CARDS              # or close the window
```

The Microblog reference clone in `D:\AI\northstar_reference\microblog` can be deleted at any time;
nothing depends on it.
