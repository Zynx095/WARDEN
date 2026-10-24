"""Approval is bound to the exact action shown, expires, is bounded, and dies if state changes."""

import re
from datetime import datetime, timedelta, timezone

import pytest
from uagents_core.contrib.protocols.chat import ChatMessage, TextContent

from warden.agents.intent_engine import IntentEngine
from warden.agents.warden_agent import WardenAgent
from warden.config import ConfigError, WardenConfig
from warden.execution.workspace import Workspace
from warden.integrations.acp_adapter import WardenACPHandler
from warden.models import Action, ExecutionStatus
from warden.security.authorization import AuthorizationManager


def say(handler, text, sender="alice"):
    return handler.process_chat_message(ChatMessage(content=[TextContent(type="text", text=text)]), sender=sender)


@pytest.fixture
def ws(tmp_path) -> Workspace:
    w = Workspace(tmp_path / "ws")
    w.create_synthetic_file("old.tmp", "junk")
    w.create_synthetic_file("other.tmp", "other junk")
    return w


@pytest.fixture
def warden(ws) -> WardenAgent:
    return WardenAgent(workspace=ws)


@pytest.fixture
def handler(warden) -> WardenACPHandler:
    return WardenACPHandler(warden=warden, intent_engine=IntentEngine(api_key=None))


def request_delete(handler, name="old.tmp") -> str:
    _, reply = say(handler, f"delete {name}")
    return reply.content[0].text


def command_of(text) -> tuple:
    m = re.search(r"APPROVE\s+([a-f0-9\-]+)\s+([a-f0-9]{64})", text)
    return m.group(1), m.group(2)


def test_prompt_shows_full_action_and_digest(handler):
    text = request_delete(handler)
    assert "**Operation:** `DELETE`" in text
    assert "**Target:** `old.tmp`" in text
    assert "**Action digest:**" in text
    assert "**Expires:**" in text
    _, digest = command_of(text)
    assert digest in text


def test_approval_without_digest_is_refused_and_keeps_request_pending(handler, ws):
    action_id, digest = command_of(request_delete(handler))

    _, reply = say(handler, f"APPROVE {action_id}")

    assert "digest is required" in reply.content[0].text
    assert ws.exists("old.tmp")
    _, ok = say(handler, f"APPROVE {action_id} {digest}")
    assert "VERIFIED" in ok.content[0].text
    assert not ws.exists("old.tmp")


def test_wrong_digest_is_refused_without_consuming_the_request(handler, ws):
    action_id, digest = command_of(request_delete(handler))
    wrong = ("0" if digest[0] != "0" else "1") + digest[1:]

    _, reply = say(handler, f"APPROVE {action_id} {wrong}")

    assert "does not match" in reply.content[0].text
    assert ws.exists("old.tmp")
    _, ok = say(handler, f"APPROVE {action_id} {digest}")
    assert not ws.exists("old.tmp")


def test_digest_of_a_different_action_cannot_authorize_this_one(handler, ws):
    id_a, _ = command_of(request_delete(handler, "old.tmp"))
    _, digest_b = command_of(request_delete(handler, "other.tmp"))

    _, reply = say(handler, f"APPROVE {id_a} {digest_b}")

    assert "does not match" in reply.content[0].text
    assert ws.exists("old.tmp") and ws.exists("other.tmp")


def test_expired_approval_cannot_be_used(handler, warden, ws):
    action_id, digest = command_of(request_delete(handler))
    warden.auth_manager.get_pending_approval(action_id).expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)

    _, reply = say(handler, f"APPROVE {action_id} {digest}")

    assert "No pending approval" in reply.content[0].text
    assert ws.exists("old.tmp")


def test_pending_queue_is_bounded_and_fails_closed(ws):
    warden = WardenAgent(workspace=ws)
    warden.auth_manager.max_pending = 1
    first = warden.handle_action_request(Action(operation="DELETE", target="old.tmp"))
    second = warden.handle_action_request(Action(operation="DELETE", target="other.tmp"))

    assert first["status"] == ExecutionStatus.AWAITING_APPROVAL
    assert second["status"] == ExecutionStatus.FAILED
    assert "Too many actions awaiting approval" in second["error"]
    assert ws.exists("old.tmp") and ws.exists("other.tmp")


def test_expired_entries_free_queue_slots(ws):
    warden = WardenAgent(workspace=ws)
    warden.auth_manager.max_pending = 1
    first = warden.handle_action_request(Action(operation="DELETE", target="old.tmp"))
    warden.auth_manager.get_pending_approval(first["pending_id"]).expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)

    second = warden.handle_action_request(Action(operation="DELETE", target="other.tmp"))

    assert second["status"] == ExecutionStatus.AWAITING_APPROVAL


def test_state_change_between_request_and_approval_invalidates_it(handler, ws):
    action_id, digest = command_of(request_delete(handler))
    (ws.root_path / "old.tmp").write_text("precious data written after the request")

    _, reply = say(handler, f"APPROVE {action_id} {digest}")

    assert "state changed" in reply.content[0].text
    assert (ws.root_path / "old.tmp").read_text() == "precious data written after the request"
    _, again = say(handler, f"APPROVE {action_id} {digest}")
    assert "No pending approval" in again.content[0].text
    assert ws.exists("old.tmp")


def test_file_swapped_for_a_directory_is_not_deleted(handler, ws):
    action_id, digest = command_of(request_delete(handler))
    (ws.root_path / "old.tmp").unlink()
    (ws.root_path / "old.tmp").mkdir()

    _, reply = say(handler, f"APPROVE {action_id} {digest}")

    assert "state changed" in reply.content[0].text
    assert (ws.root_path / "old.tmp").is_dir()


def test_token_state_binding_stops_change_after_approval_before_execution(warden, ws, monkeypatch):
    """Even if the file changes after approval is granted, the executor refuses stale authorization."""
    res = warden.handle_action_request(Action(operation="DELETE", target="old.tmp"))
    original = warden.executor.execute

    def tamper_then_execute(request):
        (ws.root_path / "old.tmp").write_text("changed in the race window")
        return original(request)

    monkeypatch.setattr(warden.executor, "execute", tamper_then_execute)
    result = warden.approve_and_execute(res["pending_id"], "alice", expected_digest=res["action_digest"])

    assert result["status"] == ExecutionStatus.FAILED
    assert ws.exists("old.tmp")


def test_programmatic_approval_with_wrong_digest_is_refused(warden, ws):
    res = warden.handle_action_request(Action(operation="DELETE", target="old.tmp"))

    result = warden.approve_and_execute(res["pending_id"], "alice", expected_digest="f" * 64)

    assert result["status"] == ExecutionStatus.FAILED
    assert ws.exists("old.tmp")


def test_refusals_are_audited(warden):
    res = warden.handle_action_request(Action(operation="DELETE", target="old.tmp"))
    warden.approve_and_execute(res["pending_id"], "alice", expected_digest="f" * 64)

    events = warden.audit_logger.get_events(correlation_id=res["correlation_id"])

    assert any(e.execution_status == ExecutionStatus.FAILED and "does not match" in (e.error or "") for e in events)


def test_approval_settings_are_validated(monkeypatch):
    monkeypatch.setenv("WARDEN_APPROVAL_TTL_SECONDS", "5")
    with pytest.raises(ConfigError):
        WardenConfig()
    monkeypatch.setenv("WARDEN_APPROVAL_TTL_SECONDS", "abc")
    with pytest.raises(ConfigError):
        WardenConfig()
    monkeypatch.setenv("WARDEN_APPROVAL_TTL_SECONDS", "120")
    monkeypatch.setenv("WARDEN_MAX_PENDING_APPROVALS", "7")
    cfg = WardenConfig()
    assert (cfg.approval_ttl_seconds, cfg.max_pending_approvals) == (120, 7)
    mgr = AuthorizationManager(secret_key="x" * 32, approval_ttl_seconds=cfg.approval_ttl_seconds, max_pending=3)
    assert mgr.max_pending == 3
