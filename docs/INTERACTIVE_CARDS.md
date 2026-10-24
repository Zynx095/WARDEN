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
