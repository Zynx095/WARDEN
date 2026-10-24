"""Phase 1 acceptance checks through the chat adapter on the hosted synthetic workspace."""

import re
from datetime import datetime, timedelta, timezone

import pytest
from uagents.crypto import Identity
from uagents_core.contrib.protocols.chat import ChatMessage, TextContent

from warden.agents.intent_engine import IntentEngine
from warden.agents.warden_agent import WardenAgent
from warden.audit.remote import RemoteAuditVerifier
from warden.execution.workspace import Workspace
from warden.hosting.demo_workspace import prepare_demo_workspace
from warden.integrations.acp_adapter import WardenACPHandler
from warden.models import ExecutionResult, ExecutionStatus

USER = "agent1qhosteduser"
AUDITOR = Identity.from_seed("hosted-flow-auditor-seed-not-a-real-id", 0)


@pytest.fixture
def root(tmp_path):
    return prepare_demo_workspace(tmp_path / "hosted")


def make(root, auditor=None):
    warden = WardenAgent(workspace=Workspace(root), auditor=auditor)
    return warden, WardenACPHandler(warden=warden, intent_engine=IntentEngine(api_key=None), approvers=[])


def say(handler, text, sender=USER):
    return handler.process_chat_message(ChatMessage(content=[TextContent(type="text", text=text)]), sender=sender)[1].content[0].text


def command(text):
    return re.search(r"APPROVE\s+([a-f0-9\-]+)\s+([a-f0-9]{64})", text).groups()


def test_1_harmless_permitted_action_is_verified(root):
    _, h = make(root)
    reply = say(h, "read README.txt")
    assert "✅ VERIFIED" in reply and "synthetic test data" in reply
    created = say(h, "create notes.txt")
    assert "✅ VERIFIED" in created and "exact expected content" in created
    assert (root / "notes.txt").is_file()


def test_2_protected_file_is_blocked(root):
    _, h = make(root)
    reply = say(h, "delete production.env")
    assert "🚫 BLOCKED" in reply and "WDN-003" in reply
    assert (root / "production.env").is_file()


def test_protected_file_contents_are_never_returned(root):
    _, h = make(root)
    reply = say(h, "read production.env")
    assert "🚫 BLOCKED" in reply and "DEMO_ONLY_PLACEHOLDER" not in reply


def test_3_risky_action_requires_approval(root):
    _, h = make(root)
    reply = say(h, "delete cache.tmp")
    assert "🔒 AWAITING APPROVAL" in reply and "`cache.tmp`" in reply
    assert (root / "cache.tmp").is_file()


def test_4_invalid_or_expired_approval_cannot_execute(root):
    warden, h = make(root)
    action_id, digest = command(say(h, "delete cache.tmp"))
    wrong = ("0" if digest[0] != "0" else "1") + digest[1:]
    assert "does not match" in say(h, f"APPROVE {action_id} {wrong}")
    assert "VERIFIED" not in say(h, f"APPROVE {action_id} {digest}", sender="agent1qsomeoneelse")
    assert (root / "cache.tmp").is_file()
    warden.auth_manager.get_pending_approval(action_id).expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)
    assert "EXPIRED" in say(h, f"APPROVE {action_id} {digest}")
    assert (root / "cache.tmp").is_file()


def test_5_changed_target_invalidates_the_approval(root):
    _, h = make(root)
    action_id, digest = command(say(h, "delete cache.tmp"))
    (root / "cache.tmp").write_text("someone changed this after the request")
    assert "state changed" in say(h, f"APPROVE {action_id} {digest}")
    assert (root / "cache.tmp").read_text() == "someone changed this after the request"


def test_6_auditor_unavailable_or_invalid_never_verifies(root):
    for transport in (lambda r, t: None, lambda r, t: {"verdict": "VERIFIED"}):
        ws = Workspace(root)
        verifier = RemoteAuditVerifier(ws, transport, AUDITOR.address, timeout_seconds=2)
        _, h = make(root, auditor=verifier)
        (root / "cache.tmp").write_text("junk")
        action_id, digest = command(say(h, "delete cache.tmp"))
        reply = say(h, f"APPROVE {action_id} {digest}")
        assert "UNVERIFIED" in reply and "Verified\n" not in reply


def test_7_execution_failure_is_reported_honestly(root, monkeypatch):
    warden, h = make(root)
    action_id, digest = command(say(h, "delete cache.tmp"))
    monkeypatch.setattr(warden.executor, "execute", lambda r: ExecutionResult(
        action=r.action, status=ExecutionStatus.FAILED, success=False, error="simulated disk failure"))
    reply = say(h, f"APPROVE {action_id} {digest}")
    assert "No success is claimed" in reply and "simulated disk failure" in reply and "VERIFIED" not in reply


def test_8_local_only_mode_works_when_remote_auditor_is_disabled(root):
    warden, h = make(root)
    assert type(warden.auditor).__name__ == "OutcomeAuditor"
    action_id, digest = command(say(h, "delete cache.tmp"))
    assert "VERIFIED" in say(h, f"APPROVE {action_id} {digest}")
    assert not (root / "cache.tmp").exists()


def test_rejection_is_reported_and_final(root):
    _, h = make(root)
    action_id, digest = command(say(h, "delete debug.log"))
    assert "REJECTED" in say(h, f"REJECT {action_id} {digest}")
    assert "VERIFIED" not in say(h, f"APPROVE {action_id} {digest}")
    assert (root / "debug.log").is_file()


def test_replies_never_reveal_the_workspace_location(root):
    _, h = make(root)
    for text in ("List the files in the WARDEN workspace", "delete cache.tmp", "delete production.env",
                 "read README.txt", "read missing.txt"):
        assert str(root) not in say(h, text)
