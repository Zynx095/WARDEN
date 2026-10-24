"""Approve/reject decisions: bound approvers, explicit REJECTED/EXPIRED outcomes, single-use, audited."""

import re
from datetime import datetime, timedelta, timezone

import pytest
from uagents_core.contrib.protocols.chat import ChatMessage, TextContent

from warden.agents.intent_engine import IntentEngine
from warden.agents.warden_agent import WardenAgent
from warden.execution.workspace import Workspace
from warden.integrations.acp_adapter import WardenACPHandler
from warden.models import Action, ExecutionStatus


@pytest.fixture
def ws(tmp_path) -> Workspace:
    w = Workspace(tmp_path / "ws")
    w.create_synthetic_file("cache.tmp", "junk")
    return w


@pytest.fixture
def warden(ws) -> WardenAgent:
    return WardenAgent(workspace=ws)


def request(warden, approvers=("alice",)):
    return warden.handle_action_request(Action(operation="DELETE", target="cache.tmp"), authorized_approvers=approvers)


def expire(warden, action_id):
    warden.auth_manager.get_pending_approval(action_id).expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)


def statuses(warden, correlation_id):
    return [e.execution_status for e in warden.audit_logger.get_events(correlation_id=correlation_id)]


# --- core: approver identity is bound into the pending record ------------------------------

def test_unauthorized_approver_is_refused_by_the_core_and_request_stays_pending(warden, ws):
    res = request(warden)
    out = warden.approve_and_execute(res["pending_id"], "mallory", expected_digest=res["action_digest"])
    assert out["status"] == ExecutionStatus.FAILED and out["executed"] is False
    assert "not an authorized approver" in out["error"]
    assert ws.exists("cache.tmp")
    ok = warden.approve_and_execute(res["pending_id"], "alice", expected_digest=res["action_digest"])
    assert ok["status"] == ExecutionStatus.VERIFIED


def test_unauthorized_party_cannot_reject_either(warden, ws):
    res = request(warden)
    out = warden.reject_pending(res["pending_id"], "mallory", expected_digest=res["action_digest"])
    assert out["status"] == ExecutionStatus.FAILED
    assert warden.auth_manager.get_pending_approval(res["pending_id"]) is not None


def test_configured_approver_set_is_respected(warden, ws):
    res = request(warden, approvers=("alice", "operator"))
    ok = warden.approve_and_execute(res["pending_id"], "operator", expected_digest=res["action_digest"])
    assert ok["status"] == ExecutionStatus.VERIFIED


# --- rejection ------------------------------------------------------------------------------

def test_rejection_closes_the_request_and_nothing_executes(warden, ws):
    res = request(warden)
    out = warden.reject_pending(res["pending_id"], "alice", expected_digest=res["action_digest"])
    assert out["status"] == ExecutionStatus.REJECTED and out["executed"] is False
    assert out["operation"] == "DELETE" and out["target"] == "cache.tmp"
    assert ws.exists("cache.tmp")

    later = warden.approve_and_execute(res["pending_id"], "alice", expected_digest=res["action_digest"])
    assert later["status"] == ExecutionStatus.FAILED and "rejected" in later["error"]
    assert ws.exists("cache.tmp")


def test_rejection_with_wrong_digest_is_refused(warden, ws):
    res = request(warden)
    out = warden.reject_pending(res["pending_id"], "alice", expected_digest="0" * 64)
    assert out["status"] == ExecutionStatus.FAILED
    assert warden.auth_manager.get_pending_approval(res["pending_id"]) is not None


def test_double_rejection_is_not_a_second_decision(warden):
    res = request(warden)
    warden.reject_pending(res["pending_id"], "alice", expected_digest=res["action_digest"])
    again = warden.reject_pending(res["pending_id"], "alice", expected_digest=res["action_digest"])
    assert again["status"] == ExecutionStatus.FAILED


# --- expiry ---------------------------------------------------------------------------------

def test_expired_request_reports_expired_for_approve_and_reject(warden, ws):
    res = request(warden)
    expire(warden, res["pending_id"])
    approve = warden.approve_and_execute(res["pending_id"], "alice", expected_digest=res["action_digest"])
    reject = warden.reject_pending(res["pending_id"], "alice", expected_digest=res["action_digest"])
    assert approve["status"] == ExecutionStatus.EXPIRED and reject["status"] == ExecutionStatus.EXPIRED
    assert approve["executed"] is False and ws.exists("cache.tmp")


def test_unknown_id_is_failed_not_expired(warden):
    out = warden.approve_and_execute("00000000-0000-0000-0000-000000000000", "alice")
    assert out["status"] == ExecutionStatus.FAILED and "No pending approval" in out["error"]


def test_approved_request_cannot_be_rejected_afterwards(warden, ws):
    res = request(warden)
    warden.approve_and_execute(res["pending_id"], "alice", expected_digest=res["action_digest"])
    out = warden.reject_pending(res["pending_id"], "alice", expected_digest=res["action_digest"])
    assert out["status"] == ExecutionStatus.FAILED and "already been approved" in out["error"]


# --- audit trail ----------------------------------------------------------------------------

def test_approval_rejection_and_expiry_are_audited(warden, ws):
    a = request(warden)
    warden.approve_and_execute(a["pending_id"], "alice", expected_digest=a["action_digest"])
    assert ExecutionStatus.AUTHORIZED in statuses(warden, a["correlation_id"])
    assert ExecutionStatus.VERIFIED in statuses(warden, a["correlation_id"])

    ws.create_synthetic_file("cache.tmp", "again")
    r = request(warden)
    warden.reject_pending(r["pending_id"], "alice", expected_digest=r["action_digest"])
    assert ExecutionStatus.REJECTED in statuses(warden, r["correlation_id"])

    e = request(warden)
    expire(warden, e["pending_id"])
    warden.approve_and_execute(e["pending_id"], "alice", expected_digest=e["action_digest"])
    assert ExecutionStatus.EXPIRED in statuses(warden, e["correlation_id"])


def test_execution_failure_after_approval_is_audited_and_honest(warden, ws, monkeypatch):
    from warden.models import ExecutionResult
    res = request(warden)
    monkeypatch.setattr(warden.executor, "execute", lambda r: ExecutionResult(
        action=r.action, status=ExecutionStatus.FAILED, success=False, error="disk unavailable"))
    out = warden.approve_and_execute(res["pending_id"], "alice", expected_digest=res["action_digest"])
    assert out["status"] == ExecutionStatus.FAILED and out["verified"] is False
    assert ExecutionStatus.FAILED in statuses(warden, res["correlation_id"])


# --- chat: REJECT command and approver binding through the adapter ---------------------------

def say(handler, text, sender):
    return handler.process_chat_message(ChatMessage(content=[TextContent(type="text", text=text)]), sender=sender)[1].content[0].text


def test_reject_command_over_chat(warden, ws):
    h = WardenACPHandler(warden=warden, intent_engine=IntentEngine(api_key=None), approvers=[])
    text = say(h, "delete cache.tmp", "alice")
    action_id, digest = re.search(r"APPROVE\s+([a-f0-9\-]+)\s+([a-f0-9]{64})", text).groups()

    reply = say(h, f"REJECT {action_id} {digest}", "alice")
    assert "REJECTED" in reply and ws.exists("cache.tmp")
    again = say(h, f"APPROVE {action_id} {digest}", "alice")
    assert "VERIFIED" not in again and ws.exists("cache.tmp")


def test_chat_reject_requires_digest(warden, ws):
    h = WardenACPHandler(warden=warden, intent_engine=IntentEngine(api_key=None), approvers=[])
    text = say(h, "delete cache.tmp", "alice")
    action_id = re.search(r"APPROVE\s+([a-f0-9\-]+)", text).group(1)
    assert "digest is required" in say(h, f"REJECT {action_id}", "alice")
    assert warden.auth_manager.get_pending_approval(action_id) is not None


def test_core_binding_holds_even_if_adapter_owner_map_is_lost(warden, ws):
    """The adapter's own owner map is a convenience; the core record is the authority."""
    h = WardenACPHandler(warden=warden, intent_engine=IntentEngine(api_key=None), approvers=[])
    text = say(h, "delete cache.tmp", "alice")
    action_id, digest = re.search(r"APPROVE\s+([a-f0-9\-]+)\s+([a-f0-9]{64})", text).groups()
    h._approval_owners.clear()

    reply = say(h, f"APPROVE {action_id} {digest}", "mallory")
    assert "VERIFIED" not in reply and ws.exists("cache.tmp")
