"""ASI:One Interactive Cards for WARDEN (card protocol version 1).

Cards are presentation only. A card button returns its ``selection`` to WARDEN as an
ordinary chat message; that message gets exactly the authority of a typed
``APPROVE|REJECT <id> <digest>`` command and goes through the same decision path, which
checks the sender, the authoritative pending record, expiry, digest and target state.
Nothing in a card, and no card interaction, can authorize or execute an action by itself.

Protocol facts used here (Fetch.ai Innovation Lab, "ASI:One Interactive Cards", doc 1.0.5):
- A card is a ``MetadataContent`` whose ``metadata`` (dict[str, str]) holds
  ``card_protocol_version="1"``, ``requires_card_interaction="true"``, ``card_kind`` and
  ``card_payload`` (JSON string); optional ``is_terminal="true"`` for informational cards.
- ``card_payload`` must be at most 64 KB; custom trees at most 8 levels deep.
- ``review`` payload: ``title``, ``summary_rows[{label,value}]``, ``approve_cta`` and
  ``reject_cta`` (``label``, ``selection``, optional ``primary``).
- ``custom`` payload: ``{"root": element}``; elements are identified by ``"type"``.
- A click comes back as text: JSON of the selection (direct @mention) or planner prose
  that mentions every identifier in the selection.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Dict, Iterable, List, Optional, Union

from uagents_core.contrib.protocols.chat import MetadataContent

from warden.models import ExecutionStatus
from warden.presentation.badges import policy_description
from warden.presentation.reports import (
    BRAND,
    RECOMMENDATION_TEXT,
    approver_text,
    effect_text,
    expiry_text,
    is_refused,
)

CARD_PROTOCOL_VERSION = "1"
CARD_KINDS = {"carousel", "detail", "form", "review", "custom"}
MAX_PAYLOAD_BYTES = 64 * 1024
MAX_DEPTH = 8
MAX_ACTIONS_PER_CARD = 10
SELECTION_SCHEMA = "warden.decision.v1"

BADGE_VARIANTS = {"info", "success", "warning"}
TEXT_STYLES = {"body", "muted", "emphasis"}
ELEMENT_TYPES = {"section", "group", "divider", "text", "heading", "image", "badge",
                 "button", "input", "list", "choice_grid"}

UUID_RE = re.compile(r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b", re.IGNORECASE)
DIGEST_RE = re.compile(r"\b[0-9a-f]{64}\b", re.IGNORECASE)
# The selection's own values are "approve"/"reject", which the planner repeats. Nouns such as
# "approval" are deliberately not decision words: "rejected the approval request" must read as a rejection.
APPROVE_WORDS = re.compile(r"\b(approve|approved)\b", re.IGNORECASE)
REJECT_WORDS = re.compile(r"\b(reject|rejected|decline|declined)\b", re.IGNORECASE)

# Final states a result card may show, with the badge colour used for each.
RESULT_VARIANTS = {
    ExecutionStatus.VERIFIED: "success",
    ExecutionStatus.BLOCKED: "warning",
    ExecutionStatus.REJECTED: "info",
    ExecutionStatus.EXPIRED: "warning",
    ExecutionStatus.FAILED: "warning",
    ExecutionStatus.UNVERIFIED: "warning",
}
RESULT_EXPLANATIONS = {
    ExecutionStatus.VERIFIED: "Executed, and the actual result was independently confirmed.",
    ExecutionStatus.BLOCKED: "Blocked by deterministic policy before anything ran.",
    ExecutionStatus.REJECTED: "Rejected by an authorized approver. Nothing was executed.",
    ExecutionStatus.EXPIRED: "The approval window closed before a decision. Nothing was executed.",
    ExecutionStatus.FAILED: "Not completed. No success is claimed.",
    ExecutionStatus.UNVERIFIED: "It ran, but the outcome could NOT be independently confirmed.",
}


class CardValidationError(ValueError):
    """A card does not match the documented protocol and must not be sent."""


class CardResponseError(ValueError):
    """An incoming card interaction is malformed or ambiguous; nothing may be decided from it."""


@dataclass(frozen=True)
class CardDecision:
    decision: str      # "APPROVE" or "REJECT"
    action_id: str
    digest: str


# --- helpers ------------------------------------------------------------------------------

def _clean(value: Any, limit: int = 120) -> str:
    """Single-line, printable, bounded text for display inside a card."""
    text = " ".join("".join(ch if ch.isprintable() else " " for ch in str(value)).split())
    return text if len(text) <= limit else text[: limit - 1] + "…"


def _status(value: Any) -> Optional[ExecutionStatus]:
    try:
        return value if isinstance(value, ExecutionStatus) else ExecutionStatus(str(value))
    except ValueError:
        return None


def _expiry_text(expires_at: Optional[str], now: Optional[datetime] = None) -> str:
    return expiry_text(expires_at, now)


def _policy_text(result: Dict[str, Any]) -> str:
    pid = result.get("policy_id")
    return _clean(f"{pid} — {policy_description(pid)}", 160) if pid else "No policy on record"


def _subject(result: Dict[str, Any], limit: int = 80) -> str:
    op = result.get("operation")
    if op:
        return _clean(f"{str(op).upper()} {result.get('target') or ''}", limit)
    return _clean(f"Action {str(result.get('pending_id') or result.get('action_id') or '')[:8]}", limit)


def _explanation(result: Dict[str, Any], status: ExecutionStatus) -> str:
    """What the final state means for this result; a FAILED one says whether anything ran."""
    if is_refused(result):
        return "The decision was refused. Nothing was executed."
    if status == ExecutionStatus.FAILED and result.get("executed"):
        return "It ran, but verification found a problem. No success is claimed."
    if status == ExecutionStatus.FAILED and result.get("execution_attempted"):
        return "Execution failed. No success is claimed."
    return RESULT_EXPLANATIONS[status]


def _capitalized(text: str) -> str:
    return text[:1].upper() + text[1:]


def risk_text(result: Dict[str, Any], limit: int = 160) -> str:
    """One line describing the advisory risk assessment of a result. Never an authorization."""
    risk = result.get("risk")
    if not isinstance(risk, dict):
        return "Not assessed"
    if risk.get("status") != "ASSESSED":
        return _clean(f"Unavailable: {risk.get('summary') or 'no assessment'}", limit)
    advice = RECOMMENDATION_TEXT.get(str(risk.get("recommendation")), "advisory")
    return _clean(f"{risk.get('risk_level')} ({advice}): {risk.get('summary') or ''}", limit)


def _selection(decision: str, result: Dict[str, Any]) -> Dict[str, str]:
    return {
        "warden": SELECTION_SCHEMA,
        "decision": decision,
        "action_id": str(result.get("pending_id") or result.get("action_id")),
        "digest": str(result.get("action_digest")),
    }


# --- validation ---------------------------------------------------------------------------

def _depth(element: Any) -> int:
    if not isinstance(element, dict):
        return 0
    children: List[Any] = list(element.get("children") or [])
    for item in element.get("items") or []:
        children.extend(item.get("children") or [] if isinstance(item, dict) else [])
    return 1 + max((_depth(c) for c in children), default=0)


def _check_element(element: Any) -> None:
    if not isinstance(element, dict) or element.get("type") not in ELEMENT_TYPES:
        raise CardValidationError("custom card element has an unknown or missing type")
    kind = element["type"]
    if kind == "badge" and element.get("variant", "info") not in BADGE_VARIANTS:
        raise CardValidationError("badge variant must be info, success or warning")
    if kind == "text":
        if not isinstance(element.get("value"), str):
            raise CardValidationError("text element needs a string value")
        if element.get("style", "body") not in TEXT_STYLES:
            raise CardValidationError("text style must be body, muted or emphasis")
    if kind == "heading" and element.get("level", 2) not in (1, 2, 3):
        raise CardValidationError("heading level must be 1-3")
    if kind == "button" and not isinstance((element.get("action") or {}).get("selection"), dict):
        raise CardValidationError("button needs action.selection")
    for child in element.get("children") or []:
        _check_element(child)
    for item in element.get("items") or []:
        for child in (item or {}).get("children") or []:
            _check_element(child)


def _check_rows(rows: Any) -> None:
    if not isinstance(rows, list) or not rows:
        raise CardValidationError("summary_rows must be a non-empty list")
    for row in rows:
        if not (isinstance(row, dict) and isinstance(row.get("label"), str) and isinstance(row.get("value"), str)):
            raise CardValidationError("each summary row needs string label and value")


def validate_card_metadata(metadata: Dict[str, Any]) -> None:
    """Raise CardValidationError unless ``metadata`` matches the documented card protocol."""
    if not isinstance(metadata, dict) or not all(isinstance(k, str) and isinstance(v, str) for k, v in metadata.items()):
        raise CardValidationError("card metadata must be dict[str, str]")
    if metadata.get("card_protocol_version") != CARD_PROTOCOL_VERSION:
        raise CardValidationError("card_protocol_version must be '1'")
    if metadata.get("requires_card_interaction") != "true":
        raise CardValidationError("requires_card_interaction must be 'true'")
    if metadata.get("is_terminal", "true") != "true":
        raise CardValidationError("is_terminal, when present, must be 'true'")
    kind = metadata.get("card_kind")
    if kind not in CARD_KINDS:
        raise CardValidationError("unknown card_kind")
    raw = metadata.get("card_payload", "")
    if len(raw.encode("utf-8")) > MAX_PAYLOAD_BYTES:
        raise CardValidationError("card_payload exceeds 64 KB")
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError:
        raise CardValidationError("card_payload is not valid JSON") from None
    if not isinstance(payload, dict):
        raise CardValidationError("card_payload must be a JSON object")
    if kind == "review":
        if not isinstance(payload.get("title"), str):
            raise CardValidationError("review card needs a title")
        _check_rows(payload.get("summary_rows"))
        for cta in ("approve_cta", "reject_cta"):
            spec = payload.get(cta)
            if not (isinstance(spec, dict) and isinstance(spec.get("label"), str)
                    and isinstance(spec.get("selection"), dict)):
                raise CardValidationError(f"{cta} needs label and selection")
    elif kind == "custom":
        root = payload.get("root")
        if set(payload) != {"root"}:
            raise CardValidationError("custom payload must be exactly {'root': element}")
        _check_element(root)
        if _depth(root) > MAX_DEPTH:
            raise CardValidationError("custom card is nested deeper than 8 levels")


def card_content(kind: str, payload: Dict[str, Any], terminal: bool = False) -> MetadataContent:
    metadata = {
        "card_protocol_version": CARD_PROTOCOL_VERSION,
        "requires_card_interaction": "true",
        "card_kind": kind,
        "card_payload": json.dumps(payload, separators=(",", ":"), ensure_ascii=False),
    }
    if terminal:
        metadata["is_terminal"] = "true"
    validate_card_metadata(metadata)
    return MetadataContent(metadata=metadata)


# --- builders -----------------------------------------------------------------------------

def _review_rows(result: Dict[str, Any]) -> List[Dict[str, str]]:
    """What would run, why it needs a decision, the advice, who decides by when, and the identifiers."""
    rows = [
        {"label": "Status", "value": "Awaiting an authorized decision. Nothing has run."},
        {"label": "Operation", "value": _clean(str(result.get("operation", "?")).upper(), 24)},
        {"label": "Target", "value": _clean(result.get("target", "?"))},
    ]
    if result.get("destination"):
        rows.append({"label": "Destination", "value": _clean(result["destination"])})
    rows += [
        {"label": "If approved", "value": _clean(_capitalized(effect_text(result, markup=False)), 160)},
        {"label": "Policy", "value": _policy_text(result)},
        {"label": "Risk (advisory)", "value": risk_text(result)},
    ]
    if result.get("content_sha256"):
        rows.append({"label": "Content SHA-256", "value": f"{str(result['content_sha256'])[:16]}…"})
    rows += [
        {"label": "Approver", "value": _capitalized(approver_text(result))},
        {"label": "Expires", "value": _expiry_text(result.get("expires_at"))},
        {"label": "Action ID", "value": _clean(result.get("pending_id") or result.get("action_id"), 64)},
        {"label": "Action digest", "value": f"{str(result.get('action_digest'))[:16]}…"},
    ]
    return rows


def build_review_card(result: Dict[str, Any]) -> MetadataContent:
    """Review card for one AWAITING_APPROVAL result, with Approve and Reject buttons."""
    return card_content("review", {
        "title": f"{BRAND} — Approval required",
        "summary_rows": _review_rows(result),
        "approve_cta": {"label": "Approve", "primary": True, "selection": _selection("approve", result)},
        "reject_cta": {"label": "Reject", "selection": _selection("reject", result)},
    })


def build_multi_review_card(results: List[Dict[str, Any]]) -> MetadataContent:
    """Several pending actions: one section per action, each with its own Approve/Reject buttons."""
    sections = []
    for r in results[:MAX_ACTIONS_PER_CARD]:
        rows = [{"type": "text", "value": f"{row['label']}: {row['value']}", "style": "muted"}
                for row in _review_rows(r) if row["label"] not in ("Status", "Operation", "Target")]
        sections.append({
            "type": "section",
            "title": _subject(r),
            "children": rows + [{"type": "group", "direction": "row", "children": [
                {"type": "button", "label": "Approve", "primary": True, "action": {"selection": _selection("approve", r)}},
                {"type": "button", "label": "Reject", "action": {"selection": _selection("reject", r)}},
            ]}],
        })
    return card_content("custom", {"root": {
        "type": "section",
        "title": f"{BRAND} — Approval required",
        "subtitle": f"{len(results)} actions are waiting and nothing has run. Each button decides only its own action.",
        "children": sections,
    }})


def build_result_card(results: Union[Dict[str, Any], List[Dict[str, Any]]]) -> Optional[MetadataContent]:
    """Terminal card stating the honest final state of each finished action.

    Glanceable only: the status, what it means and the governing policy. The evidence (advisory
    risk, verification details, errors, read output, trace, audit reference) is in the text that
    always accompanies the card, so it is not repeated here.
    """
    items = [results] if isinstance(results, dict) else list(results)
    sections = []
    for r in items[:MAX_ACTIONS_PER_CARD]:
        status = _status(r.get("status"))
        if status not in RESULT_VARIANTS:
            continue
        children: List[Dict[str, Any]] = [
            {"type": "badge", "label": status.value, "variant": RESULT_VARIANTS[status]},
            {"type": "text", "value": _explanation(r, status), "style": "emphasis"},
        ]
        if r.get("policy_id"):
            children.append({"type": "text", "value": f"Policy: {_policy_text(r)}", "style": "muted"})
        sections.append({"type": "section", "title": _subject(r), "children": children})
    if not sections:
        return None
    root = sections[0] if len(sections) == 1 else {"type": "section", "title": f"{BRAND} — Results",
                                                   "children": sections}
    return card_content("custom", {"root": root}, terminal=True)


# --- incoming interactions ----------------------------------------------------------------

def parse_card_decision(text: str) -> Optional[CardDecision]:
    """Turn a card interaction into a decision, or None if the text is not one.

    Raises CardResponseError when the text claims to be a WARDEN card response but is
    malformed or ambiguous; the caller must then decide nothing.
    """
    stripped = (text or "").strip()
    if stripped.startswith("{"):
        try:
            data = json.loads(stripped)
        except json.JSONDecodeError:
            data = None
        if isinstance(data, dict):
            if data.get("warden") != SELECTION_SCHEMA:
                raise CardResponseError("Unsupported card response; nothing was decided.")
            decision = str(data.get("decision", "")).lower()
            action_id, digest = str(data.get("action_id", "")), str(data.get("digest", "")).lower()
            if decision not in ("approve", "reject") or not UUID_RE.fullmatch(action_id) \
                    or not DIGEST_RE.fullmatch(digest):
                raise CardResponseError("Malformed card response; nothing was decided.")
            return CardDecision(decision.upper(), action_id, digest)

    # Planner-mediated prose: accept only when it names exactly one action and one digest
    # and states exactly one kind of decision.
    ids, digests = set(m.lower() for m in UUID_RE.findall(stripped)), set(m.lower() for m in DIGEST_RE.findall(stripped))
    marked = SELECTION_SCHEMA in stripped
    if not ids and not digests and not marked:
        return None
    if not (ids or digests):
        raise CardResponseError("Card response does not name an action; nothing was decided.")
    approve, reject = bool(APPROVE_WORDS.search(stripped)), bool(REJECT_WORDS.search(stripped))
    if not (ids and digests):
        if approve or reject or marked:
            raise CardResponseError("Card response is missing the action id or digest; nothing was decided.")
        return None
    if not (approve or reject):
        return None  # identifiers without a decision word are not a decision
    if len(ids) != 1 or len(digests) != 1 or approve == reject:
        raise CardResponseError("Card response is ambiguous; nothing was decided.")
    return CardDecision("APPROVE" if approve else "REJECT", ids.pop(), digests.pop())


def cards_for_results(results: Iterable[Dict[str, Any]]) -> List[MetadataContent]:
    """Cards for a pipeline reply: a review card for pending actions, a result card for the rest."""
    results = list(results)
    pending = [r for r in results if _status(r.get("status")) == ExecutionStatus.AWAITING_APPROVAL]
    finished = [r for r in results if _status(r.get("status")) in RESULT_VARIANTS]
    cards: List[MetadataContent] = []
    if len(pending) == 1:
        cards.append(build_review_card(pending[0]))
    elif pending:
        cards.append(build_multi_review_card(pending))
    elif finished:
        card = build_result_card(finished)
        if card is not None:
            cards.append(card)
    return cards
