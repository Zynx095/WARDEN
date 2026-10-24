# Presentation layer and UI/UX integration

## What was inspected

`feature/warden-uiux` (worktree `D:\AI\WARDEN_uiux`, tip `2d5474b`) was built on
`feature/interactive-cards` (`eae8eff`), not on the hosted branch. Its commits `e4463e9`,
`b06c92e`, `01518e8`, `ffda0de` and `2d5474b` exist as reported, with `docs/UIUX_POLISH.md` and the
package `warden.presentation` (`badges`, `sanitize`, `reports`, `workflow_trace`,
`card_builders`, `adapter`).

## What was integrated, and what was not

| Module | Decision | Why |
|---|---|---|
| `badges` | imported, then corrected | Policy descriptions did not match the engine (for example `WDN-001` was described as path traversal; `WDN-005` did not exist). `risk_from_operation`, a guess from the operation name shown as "Risk", was replaced by `risk_label`, which shows the real advisory assessment. |
| `sanitize` | imported, extended | Added `sanitize_block` for multi-line output (the original stripped newlines from read output). |
| `reports` | imported, rewritten around canonical results | Added the exact `APPROVE`/`REJECT` commands with the full digest, who may approve, the risk line, refusals vs execution failures, `REJECTED`/`EXPIRED`, and a fenced, sanitized output block. |
| `workflow_trace` | imported, stage logic rewritten | The original reported the Risk Analyst as "OK" using the policy reason and showed executor failures as "skipped". Stages now come only from result fields. An Approval stage was added. |
| `card_builders` | **not integrated** | Emits a payload (`sections`, `actions[].payload`, `requires_card_interaction="false"`) that does not match the ASI:One card schema, and imports the non-canonical `warden.cards` models. |
| `adapter` (`PolishedACPHandler`) | **not integrated** | A second ACP handler with its own approval path (via `warden.cards.validator`): approvals bound only through an in-memory owner map, rejection without a digest. Using it would reintroduce the problems documented in `INTERACTIVE_CARDS.md`. |

The imported files were first committed verbatim (`525cfd4`) so the adaptation is visible as
its own diff. The original branch is unchanged.

## How it is wired

```
WardenACPHandler (only ACP handler)
  ├─ text:  warden.presentation.reports.format_pipeline_report / format_decision_report / format_no_action
  │          └─ workflow_trace.stages_from_result + format_trace_line / format_workflow_trace
  └─ cards: warden.integrations.cards (canonical builders), using badges.op_icon and the same risk text
```

Public imports: `warden.presentation.badges` (`badge`, `op_icon`, `policy_description`,
`risk_label`), `warden.presentation.sanitize` (`sanitize`, `sanitize_block`, `scrub_paths`,
`truncate_report`), `warden.presentation.reports` (`format_pipeline_report`,
`format_decision_report`, `format_result_block`, `format_no_action`, `risk_line`),
`warden.presentation.workflow_trace` (`stages_from_result`, `format_trace_line`,
`format_workflow_trace`).

## Contract

- Presentation never decides. It reads the result dict that `WardenAgent` returns; no module in
  `warden.presentation` imports policy, authorization, executor or auditor code.
- Every reply leads with the text report; a card is an extra and may be dropped by ASI:One.
- Untrusted values (targets, risk text from another agent, errors, user text) are stripped of
  control characters and backticks and length-limited; local workspace paths are replaced with
  `<workspace>` by the adapter before sending; reports are truncated before the 4000-character
  chat limit. The action digest is shown in full in the approval command (it is not secret and
  sanitization of hex cannot change it).
- Trace states: done, pending, skipped (not configured/required), not reached, blocked,
  rejected, expired, timed out, unavailable, failed, unverified, verified.

## Tests

`tests/presentation/` (badges, sanitize, reports, workflow trace), plus the adapter and card
tests under `tests/unit`, `tests/integration` and `tests/acceptance`. Text assertions in older
tests that matched the bracketed format (`[VERIFIED]`) were updated to the new labels; what they
check is unchanged.
