# WARDEN in chat: replies, cards and approvals

What a user sees when talking to WARDEN over the Agent Chat Protocol (ASI:One, Agentverse chat or
any ACP client), and how to check it.

Status: implemented and tested through the real chat handler, with and without cards
(`tests/integration/test_acp_presentation.py`, `tests/presentation/`, `tests/unit/test_cards.py`,
`tests/integration/test_interactive_cards.py`). **Not yet seen rendered in ASI:One**: how ASI:One
lays out the Markdown and the cards, and how it reports a button click, need a real conversation.

## What WARDEN controls and what ASI:One controls

| WARDEN controls | ASI:One controls |
|---|---|
| The text of every reply: a small Markdown subset (bold, inline code, bullet lists, one fenced block for read output) chosen to stay readable as plain text | How that Markdown is rendered: fonts, colours, spacing, line breaks |
| Whether a reply carries an Interactive Card, its kind (`review` or `custom`), its fields and, for buttons, the selection they return | Card layout and styling, beyond the protocol's badge variants (`info`, `success`, `warning`) and text styles (`body`, `muted`, `emphasis`); whether cards render at all |
| How an incoming decision is checked and applied | How a click comes back (the selection JSON or planner prose) and the sender address it uses |

WARDEN sends no HTML, CSS or JavaScript and cannot restyle ASI:One. Everything below is message
content.

## Anatomy of a reply

Every reply is one `ChatMessage`: a `TextContent` report first, then, when cards are on, protocol-valid
`MetadataContent` cards. One action:

```text
**WARDEN Sentinel — Approval required**          headline: what happened, in two or three words

**Status:** 🔒 AWAITING APPROVAL                 the only emoji: one status badge per action

- **Operation:** `DELETE`
- **Target:** `cache.tmp`                         workspace-relative, never a local path
- **Policy:** `WDN-004` — Destructive action: explicit human approval required
- **Execution:** not started. Nothing runs until an authorized approver decides.
- **Risk (advisory):** HIGH (review carefully): Permanently deletes cache.tmp (33 bytes).
- **If approved:** permanently deletes `cache.tmp`
- **Approver:** you or a configured approver
- **Expires:** in 5 min (11:15 UTC)

**Decide** by replying with one line exactly as shown:
- Approve: `APPROVE <action id> <64-character action digest>`
- Reject: `REJECT <action id> <64-character action digest>`

- **Trace:** Intent → Risk → Policy → Approval (pending) · not executed yet
- **Audit ref:** `<correlation id>`              resolves to this action's events in the audit log
```

| Outcome | Headline | Execution / verification lines |
|---|---|---|
| `VERIFIED` | Action verified | `completed (…)`, then the auditor's finding |
| `BLOCKED` | Action blocked | `prevented. Blocked by deterministic policy before execution; nothing was changed.` plus the policy's reason |
| `AWAITING_APPROVAL` | Approval required | `not started`, the effect, approver, expiry and both commands |
| `REJECTED` | Action rejected | `none. Rejected by an authorized approver; nothing was executed and the request is closed.` |
| `EXPIRED` | Approval expired | `none. The approval window closed before a decision; nothing was executed.` |
| `FAILED`, decision refused | Decision refused | `**Approval refused** for …: <reason>` and `none. Nothing was executed.` |
| `FAILED`, before execution | Action failed | `not executed: <reason>. No success is claimed.` |
| `FAILED`, execution failed | Action failed | `failed: <error>. No success is claimed.` and `Verification: not performed` |
| `FAILED`, verification failed | Action failed | `completed`, then `Verification: failed: <finding>. No success is claimed.` |
| `UNVERIFIED` | Outcome unverified | `completed`, then `not confirmed … could NOT be independently confirmed` |

Rules the reports follow (tested):

- **VERIFIED only on a positive independent verification.** A successful executor run without it is
  `UNVERIFIED`, never "verified".
- **"Prevented" only when nothing ran.** Anything that reached the executor says `completed` or
  `failed`, even when the outcome is then `FAILED` or `UNVERIFIED`.
- **Risk is advice.** The line is labelled "(advisory)"; its text comes from the Risk Analyst and is
  sanitized and length-limited. It never changes a decision.
- **The trace lists only stages the action went through** (`Intent → Risk → Policy → …`), names the
  decisive outcome in brackets, and ends with `· not executed` when the executor was never reached.
- **The audit reference is the action's correlation id**, the key of its events in
  `WARDEN_AUDIT_LOG` (and of the pending record for an approval).
- **Nothing local or secret leaves**: workspace paths become `<workspace>`, protected file contents
  are never read, tokens and signing material are never included, internal errors become a
  generic "Request not processed" notice.

Several actions in one request get `N actions evaluated`, a status summary and one numbered block
per action. Above three actions each block is brief (policy and execution, or the two commands) so
that every action's commands fit in one message.

A message that names no supported file action gets **No action taken**, a one-line scope statement
and examples the active parser understands. `RENAME` is listed only when the ASI:One model parser
is configured (`ASI_ONE_API_KEY`); the rule-based parser has no rename rule. The user's text is not
echoed. Empty, oversized (over 4000 characters) and already-processed messages get short notices in
the same style.

## Interactive Cards

Enabled by `WARDEN_INTERACTIVE_CARDS`: off by default for the local runner, on by default for the
hosted server (`python -m warden.hosting.server`). Cards follow ASI:One Interactive Cards protocol
version 1 (see [INTERACTIVE_CARDS.md](INTERACTIVE_CARDS.md)).

| Card | When | Content |
|---|---|---|
| `review` | one action awaits approval | title `WARDEN Sentinel — Approval required`; rows Status, Operation, Target, (Destination), If approved, Policy, Risk (advisory), (Content SHA-256), Approver, Expires, Action ID, Action digest (first 16 characters); Approve and Reject buttons |
| `custom` | several actions await approval | one section per action (operation and target in its title) with the same rows and its own two buttons |
| `custom`, terminal | an action finished | per action: status badge, what the status means (a `FAILED` card says whether anything ran) and the policy; nothing else |

**Text and cards together.** When a valid card is attached, the text becomes compact: a pending
action's risk, effect, approver, expiry and content hash are left to the review card, while status,
target, policy, execution, verification, read output, the typed commands, the trace and the audit
reference stay in the text. Result cards are glanceable only, so a finished action's evidence
(risk, verification details, errors, output, audit reference) is in the text alone. When cards are
off, or a card is dropped because it fails validation after path scrubbing, the text is the
complete report. ASI:One may also ignore a card; the text always lets the user decide.

## Approving and rejecting

- **Typed:** reply with the exact line from the report: `APPROVE <action id> <digest>` or
  `REJECT <action id> <digest>` (a leading `@agent…` mention is fine).
- **Buttons:** a click returns `{"warden": "warden.decision.v1", "decision": "approve"|"reject",
  "action_id": …, "digest": …}` (or planner prose that names exactly one action id and digest).
- Both reach the same check, `WardenACPHandler.decide` → `WardenAgent.approve_and_execute` /
  `reject_pending`: the sender must be authorized for that record, the digest must match it, the
  record must be live and unexpired, the target must be unchanged, and a decision can be used once.
  Anything else is answered with **Decision refused** (or **Approval expired**) and nothing runs.

## Settings that change what users see

| Setting | Effect on replies |
|---|---|
| `WARDEN_INTERACTIVE_CARDS` | cards on or off (and therefore compact or complete text) |
| `WARDEN_APPROVAL_MODE`, `WARDEN_APPROVER_ADDRESSES` | the Approver line: "you or a configured approver" or "an independent approver (not you)" |
| `WARDEN_APPROVAL_TTL_SECONDS` | the Expires line |
| `WARDEN_RISK_ANALYST`, `WARDEN_RISK_REQUIRED` | whether a Risk line appears, `Risk (unavailable)` / `Risk (timed out)` in the trace, policy `WDN-006` |
| `WARDEN_REMOTE_AUDITOR` | `UNVERIFIED` outcomes when the remote attestation is missing; "Independently attested by the trusted remote auditor" in verification lines |
| `ASI_ONE_API_KEY` | whether the help text offers `RENAME` |

## Checking it locally

```powershell
.\.venv\Scripts\python.exe demo\preview_chat.py            # every outcome as text-only replies
.\.venv\Scripts\python.exe demo\preview_chat.py --cards    # the same with the card payloads
.\.venv\Scripts\python.exe -m pytest tests/integration/test_acp_presentation.py -v
```

`preview_chat.py` drives the real handler on a throwaway synthetic workspace, offline: allowed
create, protected read, approval request, refused and exact approval, rejection, expiry, help text
and a multi-action request. It shows what is sent, not how a client renders it.

## Checking the hosted configuration

1. `GET https://<host>/health` returns `"interactive_cards": true` (the hosted default), the
   approval mode and the Risk Analyst mode, and nothing secret.
2. In ASI:One (manual, needs the deployed or mailbox-connected agent):
   - `List the files in the WARDEN workspace` → **Action verified** with the listing.
   - `Read production.env` → **Action blocked**, `WDN-003`, no content.
   - `Delete cache.tmp` → **Approval required**, a review card (if rendered) and the typed commands.
     Press **Approve** (or paste the APPROVE line) → **Action verified**, a terminal card.
   - `Delete debug.log`, then **Reject** → **Action rejected**; the file is still listed afterwards.
   - Wait past the expiry and approve → **Approval expired**.
   - `What can you do?` → **No action taken** with examples.
3. The agent's log shows `Received ACP ChatMessage from …` for every message, and
   `.\scripts\mailbox.ps1 status` counts inbound chat messages (mailbox mode).

Record in DEPLOYMENT_READINESS.md whether the cards rendered and which form a click arrived in.
