"""Unit tests for WardenACPHandler using official uagents_core ACP models."""

import pytest
from pathlib import Path
from uagents_core.contrib.protocols.chat import (
    ChatAcknowledgement,
    ChatMessage,
    TextContent,
)
from warden.agents.intent_engine import IntentEngine
from warden.agents.warden_agent import WardenAgent
from warden.execution.workspace import Workspace
from warden.integrations.acp_adapter import WardenACPHandler
from warden.models import Action, Decision, ExecutionStatus


@pytest.fixture
def acp_workspace(tmp_path: Path) -> Workspace:
    ws_dir = tmp_path / "acp_ws"
    return Workspace(ws_dir)


@pytest.fixture
def warden(acp_workspace: Workspace) -> WardenAgent:
    return WardenAgent(workspace=acp_workspace)


@pytest.fixture
def acp_handler(warden: WardenAgent) -> WardenACPHandler:
    return WardenACPHandler(warden=warden, intent_engine=IntentEngine(api_key=None))


def test_empty_message_returns_ack_and_guidance(acp_handler: WardenACPHandler):
    in_msg = ChatMessage(content=[])
    ack, reply = acp_handler.process_chat_message(in_msg, sender="user_123")

    assert isinstance(ack, ChatAcknowledgement)
    assert ack.acknowledged_msg_id == in_msg.msg_id
    assert len(reply.content) == 1
    assert "empty message" in reply.content[0].text.lower()


def test_safe_create_via_acp(acp_handler: WardenACPHandler, acp_workspace: Workspace):
    user_text = "Create doc.txt with content 'Verified through ACP'"
    in_msg = ChatMessage(content=[TextContent(type="text", text=user_text)])

    ack, reply = acp_handler.process_chat_message(in_msg, sender="asi1_user")

    assert ack.acknowledged_msg_id == in_msg.msg_id
    reply_text = reply.content[0].text
    assert "✅ VERIFIED" in reply_text
    assert acp_workspace.exists("doc.txt") is True


def test_destructive_action_and_subsequent_approval_via_acp(
    acp_handler: WardenACPHandler,
    acp_workspace: Workspace,
):
    # Setup target file
    acp_workspace.create_synthetic_file("obsolete.tmp", "temp data")
    assert acp_workspace.exists("obsolete.tmp") is True

    # 1. Propose deletion
    user_text = "Delete obsolete.tmp"
    in_msg = ChatMessage(content=[TextContent(type="text", text=user_text)])
    ack1, reply1 = acp_handler.process_chat_message(in_msg, sender="asi1_user")

    reply_text1 = reply1.content[0].text
    assert "🔒 AWAITING APPROVAL" in reply_text1
    assert "APPROVE" in reply_text1
    # File still exists on disk
    assert acp_workspace.exists("obsolete.tmp") is True

    # Extract pending action_id
    import re
    match = re.search(r"APPROVE\s+([a-f0-9\-]+\s+[a-f0-9]{64})", reply_text1)
    assert match is not None
    pending_id = match.group(1)

    # 2. User approves via conversational reply
    approval_msg = ChatMessage(content=[TextContent(type="text", text=f"APPROVE {pending_id}")])
    ack2, reply2 = acp_handler.process_chat_message(approval_msg, sender="asi1_user")

    reply_text2 = reply2.content[0].text
    assert "independently confirmed" in reply_text2
    assert "VERIFIED" in reply_text2
    # File is now deleted and verified on disk
    assert not acp_workspace.exists("obsolete.tmp")


def test_prohibited_operation_blocked_via_acp(acp_handler: WardenACPHandler):
    user_text = "Write to .env with content 'EXPLOIT=true'"
    in_msg = ChatMessage(content=[TextContent(type="text", text=user_text)])

    ack, reply = acp_handler.process_chat_message(in_msg, sender="asi1_user")

    reply_text = reply.content[0].text
    assert "🚫 BLOCKED" in reply_text
    assert "WDN-003" in reply_text
    assert "Protected resource modification is prohibited" in reply_text


def test_list_filenames_via_acp(acp_handler: WardenACPHandler, acp_workspace: Workspace):
    acp_workspace.create_synthetic_file("alpha.txt", "Alpha content")
    acp_workspace.create_synthetic_file("beta.log", "Beta log entry")

    user_text = "List the filenames in your permitted workspace"
    in_msg = ChatMessage(content=[TextContent(type="text", text=user_text)])

    ack, reply = acp_handler.process_chat_message(in_msg, sender="asi1_user")

    assert isinstance(ack, ChatAcknowledgement)
    assert ack.acknowledged_msg_id == in_msg.msg_id

    reply_text = reply.content[0].text
    assert "✅ VERIFIED" in reply_text
    assert "alpha.txt" in reply_text
    assert "beta.log" in reply_text
    assert "Output:" in reply_text


def test_read_file_content_via_acp(acp_handler: WardenACPHandler, acp_workspace: Workspace):
    acp_workspace.create_synthetic_file("README.md", "Project documentation content.")

    user_text = "Read README.md"
    in_msg = ChatMessage(content=[TextContent(type="text", text=user_text)])

    ack, reply = acp_handler.process_chat_message(in_msg, sender="asi1_user")

    assert ack.acknowledged_msg_id == in_msg.msg_id
    reply_text = reply.content[0].text
    assert "✅ VERIFIED" in reply_text
    assert "Project documentation content." in reply_text

def test_list_filenames_with_leading_mention_and_negative_constraints(
    acp_handler: WardenACPHandler,
    acp_workspace: Workspace,
):
    acp_workspace.create_synthetic_file("README.txt", "Synthetic demo workspace.")
    acp_workspace.create_synthetic_file("app_settings.json", "{}")
    acp_workspace.create_synthetic_file("debug_output.log", "debug")

    # Exact live input format reported from Agentverse ACP chat
    user_text = (
        "@agent1q0kewgd2uyceeqrfn9jdln75nhwvfk7pmycaacqvcqm8qtxptsea6szeql7 "
        "List the filenames in your permitted workspace. Do not create, modify, rename, or delete anything."
    )
    in_msg = ChatMessage(content=[TextContent(type="text", text=user_text)])

    ack, reply = acp_handler.process_chat_message(in_msg, sender="live_chat_user")

    assert isinstance(ack, ChatAcknowledgement)
    assert ack.acknowledged_msg_id == in_msg.msg_id

    reply_text = reply.content[0].text
    assert "✅ VERIFIED" in reply_text
    assert "README.txt" in reply_text
    assert "app_settings.json" in reply_text
    assert "debug_output.log" in reply_text
    assert "Output:" in reply_text
    assert "No filesystem operation was proposed" not in reply_text


def test_approve_with_leading_mention(
    acp_handler: WardenACPHandler,
    acp_workspace: Workspace,
):
    acp_workspace.create_synthetic_file("junk.tmp", "to delete")
    # Request deletion
    _, rep1 = acp_handler.process_chat_message(
        ChatMessage(content=[TextContent(type="text", text="Delete junk.tmp")]),
        sender="bob",
    )
    import re
    match = re.search(r"APPROVE\s+([a-f0-9\-]+\s+[a-f0-9]{64})", rep1.content[0].text)
    assert match is not None
    pending_id = match.group(1)

    # Approve with leading @agent mention
    approve_msg = ChatMessage(content=[TextContent(
        type="text",
        text=f"@agent1q0kewgd2uyceeqrfn9jdln75nhwvfk7pmycaacqvcqm8qtxptsea6szeql7 APPROVE {pending_id}",
    )])
    _, rep2 = acp_handler.process_chat_message(approve_msg, sender="bob")
    assert "independently confirmed" in rep2.content[0].text
    assert "VERIFIED" in rep2.content[0].text
    assert not acp_workspace.exists("junk.tmp")
