# ASI:One Interactive Cards

Status: implemented and tested with simulated card interactions, including a card round
trip over real uAgents envelopes on loopback. **Not yet seen rendered in ASI:One**, and how
ASI:One's planner narrates a click has not been observed; both need a real conversation.

Protocol source: Fetch.ai Innovation Lab, "ASI:One Interactive Cards" (doc version 1.0.5).

## Flow

```
request ─▶ pipeline ─▶ AWAITING_APPROVAL ─▶ text report + review card (Approve / Reject)
click ─▶ chat message with the selection ─▶ WardenACPHandler.decide ─▶ WardenAgent
       ─▶ text report + terminal result card (VERIFIED | BLOCKED | REJECTED | EXPIRED | FAILED | UNVERIFIED)
```

What each card and reply contains, and how text and cards divide the details between them
(compact text with a valid card, complete text without one), is in
[CHAT_EXPERIENCE.md](CHAT_EXPERIENCE.md). Result cards are glanceable (status, its meaning, the
policy); the evidence stays in the text.

## Interface (small and documented)

| Piece | Where | Contract |
|---|---|---|
| Builders | `integrations/cards.py`: `build_review_card`, `build_multi_review_card`, `build_result_card`, `cards_for_results` | Input: the result dicts `WardenAgent` already returns. Output: a validated `MetadataContent`. |
| Validator | `validate_card_metadata` | Rejects anything outside the documented schema (keys, kinds, 64 KB, 8 levels, badge variants, text styles). The adapter re-validates every card after scrubbing and drops invalid ones; the text report is always sent. |
| Parser | `parse_card_decision(text)` | Returns `CardDecision(decision, action_id, digest)`, `None` (not a card response), or raises `CardResponseError` (malformed, unsupported or ambiguous: nothing is decided). |
| Decision path | `WardenACPHandler.decide` | The only way any decision is applied, for typed commands and clicks alike. |
| Switch | `WARDEN_INTERACTIVE_CARDS` | Off by default in the core; on by default in `warden.hosting.server`. When off, selections are not interpreted. |

Button selections are `{"warden": "warden.decision.v1", "decision": "approve"|"reject",
"action_id": <uuid>, "digest": <64 hex>}`. Extra keys (which ASI:One may merge in) are ignored,
never trusted.

## Security model

- A card is presentation. A click has exactly the authority of typing
  `APPROVE <id> <digest>`, and the visual state of a card is never consulted.
- The server-side pending record is authoritative. The digest from a click is compared to it;
  the action executed is the stored one, so a selection with a different `target` cannot
  redirect it.
- Every decision is checked for: authorized sender (bound into the record at request time),
  live and unexpired record, matching digest, unchanged target state (again at execution by
  the signed token), and single use (replays and double clicks find it already decided).
- Execution only happens through `WardenAgent.approve_and_execute`; there is no card-specific
  execution or policy code. Protected files are blocked before any card exists.
- Cards carry no tokens, signatures, absolute paths or file content; display text is
  single-line and length-limited.

## Not verified

- Rendering and the 64 KB / schema limits as enforced by ASI:One itself.
- Whether planner-mediated replies keep the 64-character digest intact. If they do not, the
  click is refused (fail safe) and the user can type the command from the text report.
- Whether a terminal card should keep `requires_card_interaction="true"`: the doc lists it as
  required and does not say otherwise for `is_terminal` cards, so it is always sent.
- The sender address ASI:One uses for clicks (see docs/HOSTING.md, residual risks).

## Implementation selection (2026-10-24)

Two implementations existed. This one (`warden.integrations.cards`, branch
`feature/asi-hosting`) is canonical. The alternative (`warden.cards`, branch
`feature/interactive-cards` at `eae8eff`, worktree `D:\AI\WARDEN_cards`) is kept unmodified
for comparison and was not merged, in whole or in part. Evidence, from running both:

| Check | `feature/asi-hosting` | `feature/interactive-cards` |
|---|---|---|
| Review payload matches the documented `review` schema (`approve_cta`/`reject_cta` with `selection`) | yes | no: `sections` + `actions[].payload`, so ASI:One would reject the card and show only text |
| Result card | `custom`, `is_terminal="true"`, `requires_card_interaction="true"` | `detail` with `requires_card_interaction="false"` (documented value is `"true"`) and non-schema `sections` |
| Decision path | one: `WardenACPHandler.decide` → `WardenAgent.reject_pending` / `approve_and_execute` | separate validator; REJECT deletes from `_pending_approvals` directly |
| Approver policy | bound into the pending record at request time; survives loss of adapter state | in-memory owner map only; a fresh handler let another sender approve and execute |
| Digest on REJECT | required and checked | not required |
| Reject outcome | `REJECTED`, final, remembered | recorded as `BLOCKED`; later decisions get "not found" |
| Decisions read from `MetadataContent` | no (documented route is chat text only) | yes (`card_action_payload`, `action`/`action_id` keys) |
| File contents in cards | never | read output (up to 500 chars) in the result card |
| Expiry | explicit `EXPIRED` | reported as generic "not found" |
| Tests at selection time | 461 (suite incl. loopback card round trip) | 356 |

Nothing from the alternative was retained: its protections (digest match, replay, state
check) already exist in the core path used here, and its models describe a non-documented
schema. Regression tests in `tests/integration/test_interactive_cards.py` cover the gaps above.

## Update on `integration/sentinel-final`

- The selection above stands. The UI/UX workstream's card builders and `PolishedACPHandler` were
  not integrated for the same reasons (see [UIUX_INTEGRATION.md](UIUX_INTEGRATION.md)); its
  presentation vocabulary was: card titles carry operation icons, the review card shows the
  advisory risk, the content hash (for writes), the expiry and who may approve.
- With `WARDEN_APPROVAL_MODE=independent`, a click by the requester is refused exactly like a
  typed command (`Independent approval is required`); an independent approver's click executes.
- Card and text approvals are asserted to reach the same `WardenAgent.approve_and_execute` call
  with the same arguments (`tests/acceptance/test_acceptance.py::test_03_04_*`).
- Approval consumption is durable, so a replayed click is refused after a restart too.
- Still not verified: rendering and button behaviour in ASI:One itself, the planner's narration of
  a click, and the sender address ASI:One uses for clicks. If ASI:One does not return the full
  digest or a stable sender, the click is refused and the text command remains the fallback.
