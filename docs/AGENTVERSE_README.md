# WARDEN: action security for AI agents

WARDEN checks every file action an AI proposes before anything happens, asks a human to
approve risky ones, and then independently confirms what actually changed on disk.

**This public demo runs on a synthetic sandbox.** Every file it can see is test data
created for the demonstration (`README.txt`, `cache.tmp`, `debug.log`, and a decoy
`production.env`). It never touches your files.

## What to try

- `List the files in the WARDEN workspace`
- `Read README.txt`
- `Delete cache.tmp` → WARDEN pauses and asks for approval. Reply with the exact
  `APPROVE <id> <digest>` line it gives you, or `REJECT <id> <digest>`.
- `Delete production.env` → blocked by policy, no matter how the request is phrased.
- `Clean up temporary files`

## How it decides

1. Your request becomes a structured proposal (operation + target).
2. A deterministic policy engine, not the language model, decides: **allow**, **block**
   (protected files, paths outside the sandbox) or **require approval** (deletes, renames).
3. An approval is bound to the exact action's digest, the file's state at the time you were
   asked, an expiry time, and the identity that may approve it. If the file changes, the
   request expires, or a different action is named, nothing runs.
4. A restricted executor runs only signed, unexpired authorizations.
5. WARDEN inspects the actual result before reporting it.

## Possible results

`VERIFIED` (done and confirmed) · `BLOCKED` · `AWAITING APPROVAL` · `REJECTED` ·
`EXPIRED` · `FAILED` · `UNVERIFIED` (it ran, but could not be independently confirmed).
WARDEN never reports success it has not confirmed.

## Limits of this demo

File actions only, on a sandbox. Who may approve is bound to the requesting chat identity;
how ASI:One maps people to identities is controlled by ASI:One, not WARDEN.
