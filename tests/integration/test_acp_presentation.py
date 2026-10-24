"""The conversational contract of every outcome, through the real chat path (offline, synthetic workspace).

Each reply leads with a text report that states the operation, target, policy, what actually
happened at the executor and the auditor, the trace and an audit reference that resolves to
the action's audit events. Cards, when enabled, are protocol-valid extras: with a valid card
the text is compact, and without one it is complete. Security behaviour is asserted alongside:
nothing here may run what policy or approval did not allow.
"""

import json
import re
from datetime import datetime, timedelta, timezone

import pytest
from uagents_core.contrib.protocols.chat import ChatMessage, MetadataContent, TextContent

from warden.agents.intent_engine import IntentEngine
from warden.agents.warden_agent import WardenAgent
from warden.execution.workspace import Workspace
from warden.hosting.demo_workspace import prepare_demo_workspace
from warden.integrations import acp_adapter
from warden.integrations.acp_adapter import WardenACPHandler
from warden.integrations.cards import validate_card_metadata
from warden.models import ExecutionResult, ExecutionStatus, VerificationResult

USER, OTHER = "agent1qpresentuser", "agent1qpresentother"


@pytest.fixture
def root(tmp_path):
    return prepare_demo_workspace(tmp_path / "ws")


def make(root, cards=False, engine=None):
    warden = WardenAgent(workspace=Workspace(root))
    handler = WardenACPHandler(warden=warden, intent_engine=engine or IntentEngine(api_key=None), approvers=[],
                               interactive_cards=cards)
    return warden, handler


def send(handler, text, sender=USER, msg=None):
    return handler.process_chat_message(msg or ChatMessage(content=[TextContent(type="text", text=text)]),
                                        sender=sender)[1]


def text(reply):
    assert isinstance(reply.content[0], TextContent)  # ACP: the readable report always comes first
    return reply.content[0].text


def cards(reply):
    found = [c for c in reply.content if isinstance(c, MetadataContent)]
    for card in found:
        validate_card_metadata(card.metadata)
    return found


def command(reply, verb="APPROVE"):
    action_id, digest = re.search(r"APPROVE ([a-f0-9\-]{36}) ([a-f0-9]{64})", text(reply)).groups()
    return f"{verb} {action_id} {digest}", action_id, digest


def audit_ref(reply):
    return re.search(r"\*\*Audit ref:\*\* `([a-f0-9\-]{36})`", text(reply)).group(1)


# --- 1-3: verified, blocked, awaiting -------------------------------------------------------

def test_create_is_reported_verified_with_an_audit_reference_that_resolves(root):
    warden, h = make(root)
    reply = send(h, 'create report.txt with content "Build complete"')
    body = text(reply)
    assert body.startswith("**WARDEN Sentinel — Action verified**") and "✅ VERIFIED" in body
    assert "- **Operation:** `CREATE`" in body and "- **Target:** `report.txt`" in body
    assert "`WDN-000` — Baseline policy: permitted without approval" in body
    assert "- **Execution:** completed (Created file: report.txt)" in body
    assert "- **Verification:** Outcome independently verified: 'report.txt' exists with exact expected content." in body
    events = warden.audit_logger.get_events(correlation_id=audit_ref(reply))
    assert [e.execution_status for e in events][-1] == ExecutionStatus.VERIFIED
    assert (root / "report.txt").read_text(encoding="utf-8") == "Build complete"


def test_protected_read_is_blocked_before_execution_and_reveals_nothing(root):
    warden, h = make(root)
    body = text(send(h, "read production.env"))
    assert body.startswith("**WARDEN Sentinel — Action blocked**") and "🚫 BLOCKED" in body
    assert "`WDN-003` — Protected resource" in body and "- **Reason:**" in body
    assert "prevented. Blocked by deterministic policy before execution" in body
    assert "CRITICAL" in body and "Policy (blocked) · not executed" in body
    assert "DEMO_ONLY" not in body  # the protected file's content never appears
    assert not [e for e in warden.audit_logger.get_events() if e.execution_status == ExecutionStatus.AUTHORIZED]


def test_destructive_action_awaits_approval_and_nothing_runs(root):
    _, h = make(root)
    reply = send(h, "delete cache.tmp")
    body = text(reply)
    assert body.startswith("**WARDEN Sentinel — Approval required**") and "🔒 AWAITING APPROVAL" in body
    assert "not started. Nothing runs until an authorized approver decides" in body
    assert "- **If approved:** permanently deletes `cache.tmp`" in body and "- **Expires:** in 5 min" in body
    full, action_id, _ = command(reply)
    assert f"`{full}`" in body and audit_ref(reply) == action_id
    assert (root / "cache.tmp").is_file()


# --- 4-8: decisions -------------------------------------------------------------------------

def test_authorized_approval_with_the_exact_digest_executes_and_is_verified(root):
    _, h = make(root)
    approve, _, _ = command(send(h, "delete cache.tmp"))
    body = text(send(h, approve))
    assert body.startswith("**WARDEN Sentinel — Action verified**")
    assert "- **Approval:** approved by an authorized approver" in body
    assert "`WDN-004` — Destructive action" in body  # the policy that required the approval
    assert "Approval (approved) → Executor → Auditor (verified)" in body
    assert not (root / "cache.tmp").exists()


def test_authorized_rejection_closes_the_request_without_running_it(root):
    _, h = make(root)
    reject, _, _ = command(send(h, "delete cache.tmp"), "REJECT")
    body = text(send(h, reject))
    assert body.startswith("**WARDEN Sentinel — Action rejected**") and "🚫 REJECTED" in body
    assert "`WDN-004`" in body and "Approval (rejected) · not executed" in body
    assert "nothing was executed and the request is closed" in body and (root / "cache.tmp").is_file()
    assert "Decision refused" in text(send(h, reject.replace("REJECT", "APPROVE", 1)))  # closed for good
    assert (root / "cache.tmp").is_file()


def test_unauthorized_approval_is_refused_and_nothing_runs(root):
    _, h = make(root)
    approve, _, _ = command(send(h, "delete cache.tmp"))
    body = text(send(h, approve, sender=OTHER))
    assert body.startswith("**WARDEN Sentinel — Decision refused**") and "Approval refused" in body
    assert "Nothing was executed" in body and (root / "cache.tmp").is_file()


def test_expired_approval_is_reported_expired_and_nothing_runs(root):
    warden, h = make(root)
    approve, action_id, _ = command(send(h, "delete cache.tmp"))
    warden.auth_manager.get_pending_approval(action_id).expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)
    body = text(send(h, approve))
    assert body.startswith("**WARDEN Sentinel — Approval expired**") and "⏱️ EXPIRED" in body
    assert "nothing was executed" in body and (root / "cache.tmp").is_file()


@pytest.mark.parametrize("tamper", [lambda d: "0" * 64, lambda d: d[:-1] + ("0" if d[-1] != "0" else "1")])
def test_mismatched_digest_is_refused_and_keeps_the_request_pending(root, tamper):
    _, h = make(root)
    approve, action_id, digest = command(send(h, "delete cache.tmp"))
    body = text(send(h, f"APPROVE {action_id} {tamper(digest)}"))
    assert body.startswith("**WARDEN Sentinel — Decision refused**") and "does not match" in body
    assert (root / "cache.tmp").is_file()
    assert "Action verified" in text(send(h, approve))  # the real request is still pending


# --- 9-11: duplicates, cards, fallbacks -----------------------------------------------------

def test_duplicate_delivery_returns_the_same_reply_and_runs_nothing_twice(root):
    warden, h = make(root)
    approve, action_id, _ = command(send(h, "delete cache.tmp"))
    msg = ChatMessage(content=[TextContent(type="text", text=approve)])
    first = send(h, "", msg=msg)
    (root / "cache.tmp").write_text("recreated", encoding="utf-8")
    assert send(h, "", msg=msg) is first and (root / "cache.tmp").is_file()
    verified = [e for e in warden.audit_logger.get_events(correlation_id=action_id)
                if e.execution_status == ExecutionStatus.VERIFIED]
    assert len(verified) == 1


def test_with_cards_the_text_is_compact_and_the_card_carries_the_details(root):
    _, h = make(root, cards=True)
    reply = send(h, "delete cache.tmp")
    body = text(reply)
    (card,) = cards(reply)
    rows = {r["label"]: r["value"] for r in json.loads(card.metadata["card_payload"])["summary_rows"]}
    assert "card's buttons" in body and "APPROVE " in body and "REJECT " in body  # typed fallback stays
    for field in ("If approved", "Approver", "Expires", "Risk (advisory)"):
        assert f"**{field}" not in body and field in rows


def test_an_invalid_card_is_dropped_and_the_full_text_report_is_sent(root, monkeypatch):
    _, h = make(root, cards=True)
    broken = MetadataContent(metadata={"card_protocol_version": "2", "card_kind": "review", "card_payload": "{}",
                                       "requires_card_interaction": "true"})
    monkeypatch.setattr(acp_adapter, "cards_for_results", lambda results: [broken])
    reply = send(h, "delete cache.tmp")
    assert cards(reply) == []
    body = text(reply)
    assert "- **If approved:**" in body and "- **Expires:**" in body and "**Decide**" in body


def test_with_cards_disabled_the_reply_is_one_complete_text_report(root):
    _, h = make(root, cards=False)
    reply = send(h, "delete cache.tmp")
    assert len(reply.content) == 1 and "- **Risk (advisory):**" in text(reply) and "**Decide**" in text(reply)


# --- 12-14: help, errors, redaction ---------------------------------------------------------

def test_unsupported_request_gets_scope_and_examples_not_an_error(root):
    _, h = make(root)
    body = text(send(h, "what's the weather like today?"))
    assert body.startswith("**WARDEN Sentinel — No action taken**")
    assert "`read README.txt`" in body and "`clean up temporary files`" in body
    assert "weather" not in body and "RENAME" not in body  # not echoed; rename needs the model parser


def test_rename_is_offered_only_when_the_model_parser_is_configured(root):
    class BrokenClient:  # any failure falls back to the deterministic parser
        pass
    engine = IntentEngine(api_key="test-key-not-real", client=BrokenClient())
    _, h = make(root, engine=engine)
    body = text(send(h, "what's the weather like today?"))
    assert "`rename report.txt to report-old.txt`" in body and "`RENAME`" in body


def test_unverified_outcome_is_never_presented_as_success(root, monkeypatch):
    warden, h = make(root)
    monkeypatch.setattr(warden.auditor, "verify_outcome", lambda action, result, pre: VerificationResult(
        action=action, status=ExecutionStatus.UNVERIFIED, verified=False, details="auditor timed out"))
    body = text(send(h, 'create report.txt with content "x"'))
    assert body.startswith("**WARDEN Sentinel — Outcome unverified**") and "⚠️ UNVERIFIED" in body
    assert "- **Execution:** completed" in body and "could NOT be independently confirmed: auditor timed out" in body
    assert "✅" not in body and "Auditor (unverified)" in body


def test_execution_failure_says_it_failed_without_claiming_prevention_or_success(root, monkeypatch):
    warden, h = make(root)
    monkeypatch.setattr(warden.executor, "execute", lambda r: ExecutionResult(
        action=r.action, status=ExecutionStatus.FAILED, success=False, error=f"disk error at {root / 'x'}"))
    body = text(send(h, 'create report.txt with content "x"'))
    assert body.startswith("**WARDEN Sentinel — Action failed**") and "No success is claimed" in body
    assert "prevented" not in body and "Executor (failed)" in body
    assert str(root) not in body and "<workspace>" in body  # local paths are scrubbed


def test_internal_errors_are_generic_and_leak_nothing(root, monkeypatch):
    warden, h = make(root, cards=True)
    monkeypatch.setattr(warden, "handle_action_request", lambda *a, **k: 1 / 0)
    reply = send(h, "delete debug.log")
    assert text(reply).startswith("**WARDEN Sentinel — Request not processed**")
    assert "ZeroDivision" not in text(reply) and cards(reply) == []


def test_no_reply_or_card_carries_the_workspace_path(root):
    _, h = make(root, cards=True)
    replies = [send(h, m) for m in ("read README.txt", "delete cache.tmp", "read production.env", "list the files")]
    blob = " ".join(text(r) + json.dumps([dict(c.metadata) for c in cards(r)]) for r in replies)
    assert str(root) not in blob and root.as_posix() not in blob and str(root).replace("\\", "\\\\") not in blob


# --- 15: protocol compatibility -------------------------------------------------------------

def test_typed_commands_and_card_selections_still_reach_the_same_decision_path(root):
    _, h = make(root, cards=True)
    reply = send(h, "delete cache.tmp")
    selection = json.loads(cards(reply)[0].metadata["card_payload"])["approve_cta"]["selection"]
    full, action_id, digest = command(reply)
    assert selection == {"warden": "warden.decision.v1", "decision": "approve", "action_id": action_id,
                         "digest": digest}
    result = send(h, json.dumps(selection))
    assert "Action verified" in text(result) and not (root / "cache.tmp").exists()
    (card,) = cards(result)
    assert card.metadata["is_terminal"] == "true" and card.metadata["card_kind"] == "custom"
