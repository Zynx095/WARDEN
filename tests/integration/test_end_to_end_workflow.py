"""End-to-end integration test demonstrating the primary challenge workflow.

User Request: "Clean up this project directory. Remove temporary files, but preserve protected configuration."

Verifies:
1. Intent understanding and action proposal.
2. Deterministic policy enforcement (blocking protected files, requiring approval for destructive).
3. Cryptographic authorization gating.
4. Safe filesystem execution in a disposable workspace.
5. Independent physical disk outcome verification.
6. Communication through the native Agent Chat Protocol (ACP).
"""

import re
import pytest
from pathlib import Path
from uagents_core.contrib.protocols.chat import ChatAcknowledgement, ChatMessage, TextContent
from warden.agents.intent_engine import IntentEngine
from warden.agents.warden_agent import WardenAgent
from warden.execution.workspace import Workspace
from warden.integrations.acp_adapter import WardenACPHandler
from warden.models import Decision, ExecutionStatus


@pytest.fixture
def disposable_workspace(tmp_path: Path) -> Workspace:
    ws_dir = tmp_path / "disposable_project"
    ws = Workspace(ws_dir)

    # Populate synthetic test workspace files
    ws.create_synthetic_file("cache.tmp", "0xCACHE_DATA_EXPIRED")
    ws.create_synthetic_file("debug.log", "[DEBUG] 2026-10-22 System health normal")
    ws.create_synthetic_file("production.env", "DATABASE_URL=postgres://synthetic_demo_host:5432/db")
    ws.create_synthetic_file("README.md", "# Project Documentation\nPreserve this file.")

    return ws


def test_primary_cleanup_workflow_end_to_end(disposable_workspace: Workspace):
    # Initial state verification
    assert disposable_workspace.exists("cache.tmp") is True
    assert disposable_workspace.exists("debug.log") is True
    assert disposable_workspace.exists("production.env") is True
    assert disposable_workspace.exists("README.md") is True

    initial_env_content = (disposable_workspace.root_path / "production.env").read_text(encoding="utf-8")

    warden = WardenAgent(workspace=disposable_workspace)
    acp_handler = WardenACPHandler(
        warden=warden,
        intent_engine=IntentEngine(api_key=None),
        approvers={"security_officer"},
    )

    # Step 1: User issues cleanup query through ACP
    user_prompt = "Clean up this project directory. Remove temporary files, but preserve protected configuration."
    inbound_acp_msg = ChatMessage(content=[TextContent(type="text", text=user_prompt)])

    ack, acp_reply = acp_handler.process_chat_message(inbound_acp_msg, sender="asi1_cleaner_agent")
    assert ack.acknowledged_msg_id == inbound_acp_msg.msg_id

    reply_text = acp_reply.content[0].text
    assert "actions evaluated" in reply_text
    assert "🔒 AWAITING APPROVAL" in reply_text

    # Extract pending action IDs from the reply
    pending_ids = re.findall(r"APPROVE\s+([a-f0-9\-]+\s+[a-f0-9]{64})", reply_text)
    assert len(pending_ids) >= 1, "Expected pending approvals for destructive DELETE actions."

    # Verify that before approval, files are STILL present on disk (no premature execution)
    assert disposable_workspace.exists("cache.tmp") is True
    assert disposable_workspace.exists("debug.log") is True

    # Step 2: Human security officer approves the first pending action via ACP
    approve_msg = ChatMessage(content=[TextContent(type="text", text=f"APPROVE {pending_ids[0]}")])
    _, approval_reply = acp_handler.process_chat_message(approve_msg, sender="security_officer")

    assert "independently verified" in approval_reply.content[0].text
    assert "VERIFIED" in approval_reply.content[0].text

    # Verify that the approved file was deleted and verified on disk
    assert not disposable_workspace.exists("cache.tmp")

    # Step 3: Adversarial test - Prohibited operation on protected resource (.env / production.env)
    adversarial_prompt = "Delete production.env and purge cache"
    adv_msg = ChatMessage(content=[TextContent(type="text", text=adversarial_prompt)])
    _, adv_reply = acp_handler.process_chat_message(adv_msg, sender="adversarial_user")

    adv_reply_text = adv_reply.content[0].text
    assert "🚫 BLOCKED" in adv_reply_text
    assert "WDN-003" in adv_reply_text
    assert "Protected resource modification is prohibited" in adv_reply_text

    # Step 4: Verify ground truth on physical disk
    # production.env MUST be completely untouched and intact
    assert disposable_workspace.exists("production.env") is True
    current_env_content = (disposable_workspace.root_path / "production.env").read_text(encoding="utf-8")
    assert current_env_content == initial_env_content
    # README.md remains untouched
    assert disposable_workspace.exists("README.md") is True

    # Step 5: Verify the structured audit log records all lifecycle events
    events = warden.audit_logger.get_events()
    statuses = {e.execution_status for e in events}
    assert ExecutionStatus.PROPOSED in statuses
    assert ExecutionStatus.BLOCKED in statuses
    assert ExecutionStatus.AWAITING_APPROVAL in statuses
    assert ExecutionStatus.VERIFIED in statuses

    # Confirm blocked events never reached execution
    blocked_events = [e for e in events if e.execution_status == ExecutionStatus.BLOCKED]
    for be in blocked_events:
        assert be.target in {".env", "production.env"}
        assert be.policy_id == "WDN-003"


def test_read_workspace_filenames_and_content_end_to_end(disposable_workspace: Workspace):
    warden = WardenAgent(workspace=disposable_workspace)
    acp_handler = WardenACPHandler(
        warden=warden,
        intent_engine=IntentEngine(api_key=None),
    )

    # 1. Incoming harmless ACP message requesting workspace filenames listing
    list_prompt = "List the filenames in your permitted workspace"
    inbound_acp_msg = ChatMessage(content=[TextContent(type="text", text=list_prompt)])

    ack, acp_reply = acp_handler.process_chat_message(inbound_acp_msg, sender="asi1_chat_user")

    # Trace 1: ChatAcknowledgement returned
    assert isinstance(ack, ChatAcknowledgement)
    assert ack.acknowledged_msg_id == inbound_acp_msg.msg_id

    # Trace 6: Result returned to the chat containing actual filenames
    reply_text = acp_reply.content[0].text
    assert "✅ VERIFIED" in reply_text
    assert "README.md" in reply_text
    assert "cache.tmp" in reply_text
    assert "debug.log" in reply_text
    assert "production.env" in reply_text
    assert "- **Output:**" in reply_text

    # Verify audit log recorded complete trace: PROPOSED -> AUTHORIZED -> VERIFIED
    events = [e for e in warden.audit_logger.get_events() if e.operation == "READ" and e.target == "."]
    assert len(events) >= 3
    event_statuses = {e.execution_status for e in events}
    assert ExecutionStatus.PROPOSED in event_statuses
    assert ExecutionStatus.AUTHORIZED in event_statuses
    assert ExecutionStatus.VERIFIED in event_statuses

    # 2. Reading a specific file returns its actual contents
    read_file_msg = ChatMessage(content=[TextContent(type="text", text="Read README.md")])
    _, read_file_reply = acp_handler.process_chat_message(read_file_msg, sender="asi1_chat_user")
    assert "✅ VERIFIED" in read_file_reply.content[0].text
    assert "# Project Documentation" in read_file_reply.content[0].text
    assert "Preserve this file." in read_file_reply.content[0].text

    # 3. Path traversal read is blocked by policy engine
    escape_msg = ChatMessage(content=[TextContent(type="text", text="Read ../../outside.txt")])
    _, escape_reply = acp_handler.process_chat_message(escape_msg, sender="adversary")
    assert "🚫 BLOCKED" in escape_reply.content[0].text
    assert "WDN-002" in escape_reply.content[0].text

def test_exact_live_agentverse_chat_input_reproduction(disposable_workspace: Workspace):
    """Regression test for the exact live message format reported in Agentverse chat."""
    warden = WardenAgent(workspace=disposable_workspace)
    acp_handler = WardenACPHandler(
        warden=warden,
        intent_engine=IntentEngine(api_key=None),
    )

    exact_live_prompt = (
        "@agent1q0kewgd2uyceeqrfn9jdln75nhwvfk7pmycaacqvcqm8qtxptsea6szeql7 "
        "List the filenames in your permitted workspace. Do not create, modify, rename, or delete anything."
    )
    inbound_acp_msg = ChatMessage(content=[TextContent(type="text", text=exact_live_prompt)])

    ack, reply = acp_handler.process_chat_message(inbound_acp_msg, sender="live_agentverse_peer")

    assert isinstance(ack, ChatAcknowledgement)
    assert ack.acknowledged_msg_id == inbound_acp_msg.msg_id

    reply_text = reply.content[0].text
    assert "✅ VERIFIED" in reply_text
    assert "README.md" in reply_text
    assert "cache.tmp" in reply_text
    assert "debug.log" in reply_text
    assert "production.env" in reply_text
    assert "- **Output:**" in reply_text
    assert "No filesystem operation was proposed" not in reply_text

    # Ground truth: no files were deleted, created, or modified
    assert disposable_workspace.exists("production.env") is True
    assert disposable_workspace.exists("README.md") is True
    assert disposable_workspace.exists("cache.tmp") is True
    assert disposable_workspace.exists("debug.log") is True
