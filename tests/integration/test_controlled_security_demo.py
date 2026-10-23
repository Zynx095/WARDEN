"""Automated integration test for the controlled security demonstration workflow.

Verifies:
1. Workspace fixture initialization with cache.tmp, debug.log, and production.env.
2. Proposal of safe deletion (cache.tmp) pausing in AWAITING_APPROVAL under policy WDN-004.
3. Strict approval controls under WARDEN_APPROVER_ADDRESSES:
   - Unauthorized senders cannot approve other peers' pending actions.
   - Designated approvers (or the original requester) can approve.
4. Independent outcome auditing on physical disk (verifying file deletion).
5. Rejection of protected resource deletion (production.env) under policy WDN-003.
6. Post-demo filesystem ground truth (debug.log and production.env byte-for-byte unchanged).
7. Complete audit trail recording every state transition.
"""

import hashlib
import re
from pathlib import Path
import pytest
from uagents_core.contrib.protocols.chat import ChatAcknowledgement, ChatMessage, TextContent

from warden.agents.intent_engine import IntentEngine
from warden.agents.warden_agent import WardenAgent
from warden.execution.workspace import Workspace
from warden.integrations.acp_adapter import WardenACPHandler
from warden.models import ExecutionStatus


def _sha256_of(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _send_chat(handler: WardenACPHandler, text: str, sender: str) -> tuple[ChatAcknowledgement, str]:
    msg = ChatMessage(content=[TextContent(type="text", text=text)])
    ack, reply = handler.process_chat_message(msg, sender=sender)
    reply_text = reply.content[0].text if reply.content else ""
    return ack, reply_text


@pytest.fixture
def demo_workspace(tmp_path: Path) -> Workspace:
    ws = Workspace(tmp_path / "controlled_demo_ws")
    ws.create_synthetic_file(
        "cache.tmp",
        "# Synthetic demo disposable cache\nsession_id=demo_session_12345\nstatus=expired\n",
    )
    ws.create_synthetic_file(
        "debug.log",
        "[2026-10-24 02:00:00] [INFO] Synthetic demo service initialized.\n[2026-10-24 02:00:05] [DEBUG] Buffer OK.\n",
    )
    ws.create_synthetic_file(
        "production.env",
        "# Synthetic demo configuration (not a real secret)\nDEMO_DATABASE_URL=postgres://demo:pass@localhost:5432/db\n",
    )
    return ws


def test_controlled_security_demonstration_workflow(demo_workspace: Workspace):
    requester = "agent1q_requester_user"
    unauthorized_sender = "agent1q_unauthorized_peer"
    designated_approver = "agent1q_security_officer"

    audit_log_path = demo_workspace.root_path.parent / "demo_audit.jsonl"
    warden = WardenAgent(workspace=demo_workspace, audit_log_file=audit_log_path)
    handler = WardenACPHandler(
        warden=warden,
        intent_engine=IntentEngine(offline=True),
        approvers={designated_approver},
    )

    env_hash_before = _sha256_of(demo_workspace.root_path / "production.env")
    log_hash_before = _sha256_of(demo_workspace.root_path / "debug.log")

    # Step 1: Harmless listing of workspace files
    ack, reply = _send_chat(handler, "List the filenames in your permitted workspace", requester)
    assert isinstance(ack, ChatAcknowledgement)
    assert "[VERIFIED]" in reply
    assert "cache.tmp" in reply
    assert "debug.log" in reply
    assert "production.env" in reply

    # Step 2: Proposing a safe deletion of disposable cache.tmp
    ack, reply = _send_chat(handler, "Delete cache.tmp", requester)
    assert "[AWAITING APPROVAL]" in reply
    assert "WDN-004" in reply
    assert "Destructive operation requires approval" in reply
    match = re.search(r"APPROVE\s+([a-f0-9\-]+)", reply)
    assert match is not None
    pending_id = match.group(1)

    # Physical check: cache.tmp must NOT be deleted yet
    assert demo_workspace.exists("cache.tmp") is True

    # Step 3: Unauthorized third-party attempts to approve
    ack, reply = _send_chat(handler, f"APPROVE {pending_id}", unauthorized_sender)
    assert "Approval refused" in reply
    assert "only the requester or a configured approver may approve it" in reply
    assert demo_workspace.exists("cache.tmp") is True

    # Step 4: Designated approver authorizes the pending deletion
    ack, reply = _send_chat(handler, f"APPROVE {pending_id}", designated_approver)
    assert "Action Approval Execution Verified" in reply
    assert "Status: `VERIFIED`" in reply
    assert "Outcome independently verified: target 'cache.tmp' is confirmed deleted" in reply

    # Physical check: cache.tmp is deleted from disk
    assert demo_workspace.exists("cache.tmp") is False

    # Step 5: Attempting deletion of protected configuration
    ack, reply = _send_chat(handler, "Delete production.env", requester)
    assert "[BLOCKED]" in reply
    assert "WDN-003" in reply
    assert "Protected resource modification is prohibited" in reply

    # Step 6: Post-demonstration state verification
    assert demo_workspace.exists("production.env") is True
    assert demo_workspace.exists("debug.log") is True
    assert _sha256_of(demo_workspace.root_path / "production.env") == env_hash_before
    assert _sha256_of(demo_workspace.root_path / "debug.log") == log_hash_before

    # Step 7: Verify audit events recorded in audit log
    events = warden.audit_logger.get_events()
    statuses = {e.execution_status for e in events}
    assert ExecutionStatus.PROPOSED in statuses
    assert ExecutionStatus.AWAITING_APPROVAL in statuses
    assert ExecutionStatus.AUTHORIZED in statuses
    assert ExecutionStatus.VERIFIED in statuses
    assert ExecutionStatus.BLOCKED in statuses

    # Confirm WDN-003 blocked event exists and production.env was never deleted
    blocked_event = next(e for e in events if e.execution_status == ExecutionStatus.BLOCKED)
    assert blocked_event.target == "production.env"
    assert blocked_event.policy_id == "WDN-003"
