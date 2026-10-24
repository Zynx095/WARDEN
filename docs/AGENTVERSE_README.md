# WARDEN: action security for AI agents

WARDEN checks every file action an AI proposes before anything happens, asks a human to
approve risky ones, and then independently confirms what actually changed on disk.

**This public demo runs on a synthetic sandbox.** Every file it can see is test data
created for the demonstration (`README.txt`, `cache.tmp`, `debug.log`, and a decoy
`production.env`). It never touches your files.

## What to try

- `List the files in the WARDEN workspace`
- `Read README.txt`
- `Delete cache.tmp` → WARDEN pauses and shows a review card. Press **Approve** or
  **Reject**, or reply with the exact `APPROVE <id> <digest>` / `REJECT <id> <digest>` line
  from its message. A button press is checked exactly like the typed line.
- `Delete production.env` → blocked by policy, no matter how the request is phrased.
- `Clean up temporary files`

## How it decides

1. Your request becomes a structured proposal (operation + target).
2. A Risk Analyst lists what could go wrong (destructive impact, protected or sensitive
   targets, scope, ambiguity). Its assessment is shown to you as advice; it decides nothing.
3. A deterministic policy engine, not the language model, decides: **allow**, **block**
   (protected files, paths outside the sandbox) or **require approval** (deletes, renames,
   overwriting an existing file).
4. An approval is bound to the exact action's digest, the file's state at the time you were
   asked, an expiry time, and the identity that may approve it. If the file changes, the
   request expires, or a different action is named, nothing runs.
5. A restricted executor runs only signed, unexpired authorizations.
6. WARDEN inspects the actual result before reporting it.

## Possible results

`VERIFIED` (done and confirmed) · `BLOCKED` · `AWAITING APPROVAL` · `REJECTED` ·
`EXPIRED` · `FAILED` · `UNVERIFIED` (it ran, but could not be independently confirmed).
WARDEN never reports success it has not confirmed.

## Limits of this demo

File actions only, on a sandbox. Each reply ends with a short trace of what every stage did.
Who may approve is bound to the chat identity (and, if the operator enabled independent
approval, must be someone other than the requester);
how ASI:One maps people to identities is controlled by ASI:One, not WARDEN.
