"""Interactive-card builders, protocol validation and interaction parsing (mocked protocol inputs)."""

import json
from datetime import datetime, timedelta, timezone

import pytest

from warden.integrations.cards import (
    MAX_PAYLOAD_BYTES,
    SELECTION_SCHEMA,
    CardDecision,
    CardResponseError,
    CardValidationError,
    build_multi_review_card,
    build_result_card,
    build_review_card,
    card_content,
    parse_card_decision,
    validate_card_metadata,
)
from warden.models import ExecutionStatus

ACTION_ID = "1b4e28ba-2fa1-11d2-883f-0016d3cca427"
DIGEST = "ab" * 32


def pending(**over):
    r = {
        "status": ExecutionStatus.AWAITING_APPROVAL, "action_id": ACTION_ID, "pending_id": ACTION_ID,
        "operation": "DELETE", "target": "cache.tmp", "destination": None, "policy_id": "WDN-004",
        "reason": "Destructive operation requires approval.", "action_digest": DIGEST,
        "expires_at": (datetime.now(timezone.utc) + timedelta(minutes=5)).isoformat(),
        "correlation_id": "c0ffee00-0000-0000-0000-000000000000",
    }
    r.update(over)
    return r


def payload(card):
    return json.loads(card.metadata["card_payload"])


# --- review card ----------------------------------------------------------------------------

def test_review_card_matches_documented_protocol():
    card = build_review_card(pending())
    md = card.metadata
    assert card.type == "metadata"
    assert md["card_protocol_version"] == "1" and md["requires_card_interaction"] == "true"
    assert md["card_kind"] == "review" and "is_terminal" not in md
    p = payload(card)
    assert set(p) == {"title", "summary_rows", "approve_cta", "reject_cta"}
    assert all(set(row) == {"label", "value"} for row in p["summary_rows"])
    validate_card_metadata(md)


def test_review_card_shows_short_digest_but_binds_full_digest_in_selection():
    p = payload(build_review_card(pending()))
    rows = {r["label"]: r["value"] for r in p["summary_rows"]}
    assert rows["Operation"] == "🗑️ DELETE" and rows["Target"] == "cache.tmp"
    assert rows["Action digest"] == DIGEST[:16] + "…"
    assert rows["Expires"].startswith("in ") and "UTC" in rows["Expires"]
    assert "WDN-004" in rows["Policy"] and rows["Risk (advisory)"] == "Not assessed"
    for cta, decision in (("approve_cta", "approve"), ("reject_cta", "reject")):
        assert p[cta]["selection"] == {"warden": SELECTION_SCHEMA, "decision": decision,
                                       "action_id": ACTION_ID, "digest": DIGEST}


def test_review_card_carries_no_secret_token_or_content():
    r = pending(auth_token="SECRET-TOKEN", content="FILE CONTENT", observed_state={"x": 1})
    raw = build_review_card(r).metadata["card_payload"]
    for leaked in ("SECRET-TOKEN", "FILE CONTENT", "signature", "secret_key"):
        assert leaked not in raw


def test_untrusted_target_text_is_neutralised():
    raw = build_review_card(pending(target="evil\nname\x00.tmp" + "x" * 500)).metadata["card_payload"]
    rows = {r["label"]: r["value"] for r in json.loads(raw)["summary_rows"]}
    assert "\n" not in rows["Target"] and "\x00" not in rows["Target"] and len(rows["Target"]) <= 120


def test_multi_review_card_buttons_each_bind_only_their_own_action():
    second = pending(action_id="2b4e28ba-2fa1-11d2-883f-0016d3cca427",
                     pending_id="2b4e28ba-2fa1-11d2-883f-0016d3cca427", action_digest="cd" * 32, target="debug.log")
    p = payload(build_multi_review_card([pending(), second]))
    sections = p["root"]["children"]
    bound = []
    for section in sections:
        buttons = section["children"][-1]["children"]
        ids = {b["action"]["selection"]["action_id"] for b in buttons}
        digests = {b["action"]["selection"]["digest"] for b in buttons}
        assert len(ids) == 1 and len(digests) == 1
        bound.append((ids.pop(), digests.pop()))
    assert bound == [(ACTION_ID, DIGEST), ("2b4e28ba-2fa1-11d2-883f-0016d3cca427", "cd" * 32)]


# --- result card ----------------------------------------------------------------------------

@pytest.mark.parametrize("status,variant", [
    (ExecutionStatus.VERIFIED, "success"), (ExecutionStatus.BLOCKED, "warning"),
    (ExecutionStatus.REJECTED, "info"), (ExecutionStatus.EXPIRED, "warning"),
    (ExecutionStatus.FAILED, "warning"), (ExecutionStatus.UNVERIFIED, "warning"),
])
def test_result_card_states_the_actual_status(status, variant):
    card = build_result_card({"status": status, "operation": "DELETE", "target": "cache.tmp",
                              "correlation_id": "c0ffee00-1111"})
    md = card.metadata
    assert md["card_kind"] == "custom" and md["is_terminal"] == "true"
    root = payload(card)["root"]
    badge = root["children"][0]
    assert badge == {"type": "badge", "label": status.value, "variant": variant}
    assert any("Audit reference: c0ffee00" == c.get("value") for c in root["children"])


def test_unverified_result_is_never_presented_as_success():
    root = payload(build_result_card({"status": ExecutionStatus.UNVERIFIED, "verification_details": "timeout"}))["root"]
    badges = [c for c in root["children"] if c["type"] == "badge"]
    assert badges == [{"type": "badge", "label": "UNVERIFIED", "variant": "warning"}]
    assert "could NOT be independently confirmed" in json.dumps(root)


def test_result_card_skips_non_final_states():
    assert build_result_card({"status": ExecutionStatus.AWAITING_APPROVAL}) is None
    assert build_result_card({"status": "NOT_A_STATUS"}) is None


# --- validator ------------------------------------------------------------------------------

def good():
    return dict(build_review_card(pending()).metadata)


@pytest.mark.parametrize("mutate", [
    lambda m: m.update(card_protocol_version="2"),
    lambda m: m.update(requires_card_interaction="false"),
    lambda m: m.update(card_kind="banner"),
    lambda m: m.update(card_payload="not json"),
    lambda m: m.update(card_payload="[1,2]"),
    lambda m: m.update(card_payload=json.dumps({"title": "x"})),
    lambda m: m.update(is_terminal="yes"),
    lambda m: m.update(extra=5),
])
def test_validator_rejects_protocol_violations(mutate):
    md = good()
    mutate(md)
    with pytest.raises(CardValidationError):
        validate_card_metadata(md)


def test_validator_rejects_oversized_payload():
    big = {"root": {"type": "text", "value": "x" * (MAX_PAYLOAD_BYTES + 1)}}
    with pytest.raises(CardValidationError):
        card_content("custom", big)


def test_validator_rejects_bad_custom_elements_and_depth():
    for root in ({"type": "badge", "label": "x", "variant": "danger"},
                 {"type": "text", "value": "x", "style": "loud"},
                 {"type": "unknown"},
                 {"type": "button", "label": "x"}):
        with pytest.raises(CardValidationError):
            card_content("custom", {"root": root})
    deep = {"type": "text", "value": "leaf"}
    for _ in range(8):
        deep = {"type": "section", "children": [deep]}
    with pytest.raises(CardValidationError):
        card_content("custom", {"root": deep})


# --- interaction parsing --------------------------------------------------------------------

def selection(**over):
    s = {"warden": SELECTION_SCHEMA, "decision": "approve", "action_id": ACTION_ID, "digest": DIGEST}
    s.update(over)
    return json.dumps(s)


def test_direct_json_selection_is_parsed():
    assert parse_card_decision(selection()) == CardDecision("APPROVE", ACTION_ID, DIGEST)
    assert parse_card_decision(selection(decision="reject")).decision == "REJECT"


def test_extra_fields_in_selection_are_ignored_not_trusted():
    d = parse_card_decision(selection(target="production.env", operation="DELETE"))
    assert d == CardDecision("APPROVE", ACTION_ID, DIGEST)


@pytest.mark.parametrize("bad", [
    selection(decision="execute"), selection(action_id="not-a-uuid"), selection(digest="ab" * 8),
    selection(digest=""), json.dumps({"offer_id": "off_123"}), json.dumps({"warden": "other.v9"}),
])
def test_malformed_or_unsupported_json_is_refused(bad):
    with pytest.raises(CardResponseError):
        parse_card_decision(bad)


def test_planner_prose_with_one_action_is_parsed():
    text = f"The user chose to approve WARDEN action {ACTION_ID} (digest {DIGEST}, {SELECTION_SCHEMA})."
    assert parse_card_decision(text) == CardDecision("APPROVE", ACTION_ID, DIGEST)
    text = f"The user rejected the approval request {ACTION_ID} with digest {DIGEST}."
    assert parse_card_decision(text).decision == "REJECT"


@pytest.mark.parametrize("text", [
    f"approve {ACTION_ID} {DIGEST} but reject it too",
    f"approve {ACTION_ID} and 2b4e28ba-2fa1-11d2-883f-0016d3cca427 with {DIGEST}",
    f"approve {ACTION_ID} digest {DIGEST} or {'cd' * 32}",
    f"approve {ACTION_ID}",
    f"{SELECTION_SCHEMA} approve",
])
def test_ambiguous_or_incomplete_prose_is_refused(text):
    with pytest.raises(CardResponseError):
        parse_card_decision(text)


@pytest.mark.parametrize("text", ["delete cache.tmp", "read README.txt", f"what is {ACTION_ID} {DIGEST}?", ""])
def test_ordinary_messages_are_not_decisions(text):
    assert parse_card_decision(text) is None
