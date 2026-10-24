"""Integration tests for single action proposals, deduplication, and replay protection.

Verifies:
1. One specific user request produces exactly one proposed action / pending approval under WDN-004,
   even when workspace context contains multiple other temporary files.
2. The exact live Agentverse request with leading agent mention (@agent...) proposes only the requested target.
3. Repeated distinct requests behave correctly and independently.
4. Duplicate message delivery (identical msg_id from transport retries) returns cached responses idempotently
   without re-executing actions or failing approvals.
5. Legitimate multi-action requests (e.g., explicit multiple files or general cleanup) are preserved and not suppressed.
6. Core security invariants remain intact (WDN-004 approvals, WDN-003 protected blocking, independent outcome verification).
"""

import re
from pathlib import Path
import pytest
from uagents_core.contrib.protocols.chat import ChatAcknowledgement, ChatMessage, TextContent

from warden.agents.intent_engine import IntentEngine
from warden.agents.warden_agent import WardenAgent
from warden.execution.workspace import Workspace
from warden.integrations.acp_adapter import WardenACPHandler
from warden.models import ExecutionStatus


@pytest.fixture
def workspace_with_fixtures(tmp_path: Path) -> Workspace:
    ws = Workspace(tmp_path / "dedup_workspace")
    ws.create_synthetic_file("cache.tmp", "session_cache_data_expired\n")
    ws.create_synthetic_file("debug.log", "[2026-10-24 02:00:00] [DEBUG] worker log\n")
    ws.create_synthetic_file(
        "production.env",
        "DEMO_DATABASE_URL=postgres://demo_user:demo_pass@localhost:5432/demo_db\n",
    )
    return ws


def test_live_agentverse_request_proposes_single_action(workspace_with_fixtures: Workspace):
    """The live request '@agent... Delete cache.tmp' must propose only 1 action for cache.tmp."""
    warden = WardenAgent(workspace=workspace_with_fixtures)
    handler = WardenACPHandler(
        warden=warden,
        intent_engine=IntentEngine(offline=True),
    )

    live_prompt = (
        "@agent1q0kewgd2uyceeqrfn9jdln75nhwvfk7pmycaacqvcqm8qtxptsea6szeql7 "
        "Delete cache.tmp"
    )
    msg = ChatMessage(content=[TextContent(type="text", text=live_prompt)])
    ack, reply = handler.process_chat_message(msg, sender="live_chat_operator")

    assert isinstance(ack, ChatAcknowledgement)
    assert ack.acknowledged_msg_id == msg.msg_id

    reply_text = reply.content[0].text
    assert "actions evaluated" not in reply_text  # one action: a single report
    assert "🔒 AWAITING APPROVAL" in reply_text
    assert "WDN-004" in reply_text
    assert "debug.log" not in reply_text

    pending_ids = re.findall(r"APPROVE\s+([a-f0-9\-]+\s+[a-f0-9]{64})", reply_text)
    assert len(pending_ids) == 1

    # Neither file should be deleted yet
    assert workspace_with_fixtures.exists("cache.tmp") is True
    assert workspace_with_fixtures.exists("debug.log") is True
    assert workspace_with_fixtures.exists("production.env") is True


def test_repeated_distinct_requests_behave_correctly(workspace_with_fixtures: Workspace):
    """Repeated distinct requests with unique msg_ids must execute independently."""
    warden = WardenAgent(workspace=workspace_with_fixtures)
    handler = WardenACPHandler(
        warden=warden,
        intent_engine=IntentEngine(offline=True),
    )

    # Request 1: Delete cache.tmp
    msg1 = ChatMessage(content=[TextContent(type="text", text="Delete cache.tmp")])
    _, reply1 = handler.process_chat_message(msg1, sender="operator")
    assert "actions evaluated" not in reply1.content[0].text  # one action: a single report
    pending1 = re.search(r"APPROVE\s+([a-f0-9\-]+\s+[a-f0-9]{64})", reply1.content[0].text).group(1)

    # Approve Request 1
    approve_msg1 = ChatMessage(content=[TextContent(type="text", text=f"APPROVE {pending1}")])
    _, approve_reply1 = handler.process_chat_message(approve_msg1, sender="operator")
    assert "- **Approval:** approved by an authorized approver" in approve_reply1.content[0].text
    assert "VERIFIED" in approve_reply1.content[0].text
    assert not workspace_with_fixtures.exists("cache.tmp")
    assert workspace_with_fixtures.exists("debug.log") is True

    # Request 2: Distinct request to delete debug.log
    msg2 = ChatMessage(content=[TextContent(type="text", text="Delete debug.log")])
    _, reply2 = handler.process_chat_message(msg2, sender="operator")
    assert "actions evaluated" not in reply2.content[0].text  # one action: a single report
    pending2 = re.search(r"APPROVE\s+([a-f0-9\-]+\s+[a-f0-9]{64})", reply2.content[0].text).group(1)
    assert pending2 != pending1

    # Approve Request 2
    approve_msg2 = ChatMessage(content=[TextContent(type="text", text=f"APPROVE {pending2}")])
    _, approve_reply2 = handler.process_chat_message(approve_msg2, sender="operator")
    assert "- **Approval:** approved by an authorized approver" in approve_reply2.content[0].text
    assert "VERIFIED" in approve_reply2.content[0].text
    assert not workspace_with_fixtures.exists("debug.log")


def test_duplicate_message_delivery_does_not_execute_action_twice(workspace_with_fixtures: Workspace):
    """Duplicate message delivery with the same msg_id must be idempotent."""
    warden = WardenAgent(workspace=workspace_with_fixtures)
    handler = WardenACPHandler(
        warden=warden,
        intent_engine=IntentEngine(offline=True),
    )

    # Propose deletion of cache.tmp
    prep_msg = ChatMessage(content=[TextContent(type="text", text="Delete cache.tmp")])
    _, prep_reply = handler.process_chat_message(prep_msg, sender="operator")
    pending_id = re.search(r"APPROVE\s+([a-f0-9\-]+\s+[a-f0-9]{64})", prep_reply.content[0].text).group(1)

    # Create the approval message
    approve_msg = ChatMessage(content=[TextContent(type="text", text=f"APPROVE {pending_id}")])

    # First delivery: normal execution
    ack1, reply1 = handler.process_chat_message(approve_msg, sender="operator")
    assert "- **Approval:** approved by an authorized approver" in reply1.content[0].text
    assert "VERIFIED" in reply1.content[0].text
    assert not workspace_with_fixtures.exists("cache.tmp")

    # Simulate recreating the file on disk to verify duplicate delivery does not re-delete
    workspace_with_fixtures.create_synthetic_file("cache.tmp", "recreated_data")

    # Second delivery: exact same ChatMessage (same msg_id) due to network transport retry
    ack2, reply2 = handler.process_chat_message(approve_msg, sender="operator")

    # Must return identical cached acknowledgement and verified response without re-execution
    assert ack2.acknowledged_msg_id == approve_msg.msg_id
    assert reply2.content[0].text == reply1.content[0].text
    assert "- **Approval:** approved by an authorized approver" in reply2.content[0].text

    # File on disk was NOT touched or deleted by the duplicate delivery
    assert workspace_with_fixtures.exists("cache.tmp") is True
    assert (workspace_with_fixtures.root_path / "cache.tmp").read_text(encoding="utf-8") == "recreated_data"


def test_duplicate_proposal_message_returns_cached_proposal(workspace_with_fixtures: Workspace):
    """Duplicate delivery of a proposal message does not create multiple pending actions."""
    warden = WardenAgent(workspace=workspace_with_fixtures)
    handler = WardenACPHandler(
        warden=warden,
        intent_engine=IntentEngine(offline=True),
    )

    proposal_msg = ChatMessage(content=[TextContent(type="text", text="Delete cache.tmp")])

    # Delivery 1
    _, reply1 = handler.process_chat_message(proposal_msg, sender="operator")
    id1 = re.search(r"APPROVE\s+([a-f0-9\-]+\s+[a-f0-9]{64})", reply1.content[0].text).group(1)

    # Delivery 2 (same msg_id)
    _, reply2 = handler.process_chat_message(proposal_msg, sender="operator")
    id2 = re.search(r"APPROVE\s+([a-f0-9\-]+\s+[a-f0-9]{64})", reply2.content[0].text).group(1)

    # Must return the identical cached proposal, not create a second pending action
    assert id1 == id2
    assert reply1.content[0].text == reply2.content[0].text


def test_legitimate_multi_action_requests_are_not_suppressed(workspace_with_fixtures: Workspace):
    """Explicit multi-target requests and general cleanup must still propose all applicable actions."""
    warden = WardenAgent(workspace=workspace_with_fixtures)
    handler = WardenACPHandler(
        warden=warden,
        intent_engine=IntentEngine(offline=True),
    )

    # Explicit multi-target request
    multi_msg = ChatMessage(content=[TextContent(type="text", text="Delete cache.tmp and debug.log")])
    _, multi_reply = handler.process_chat_message(multi_msg, sender="operator")
    assert "2 actions evaluated" in multi_reply.content[0].text

    # General workspace cleanup request
    cleanup_msg = ChatMessage(content=[TextContent(type="text", text="Clean up temporary files in workspace")])
    _, cleanup_reply = handler.process_chat_message(cleanup_msg, sender="operator")
    assert "2 actions evaluated" in cleanup_reply.content[0].text


def test_protected_configuration_rejection_preserved(workspace_with_fixtures: Workspace):
    """Protected targets like production.env remain blocked under WDN-003 with zero execution."""
    warden = WardenAgent(workspace=workspace_with_fixtures)
    handler = WardenACPHandler(
        warden=warden,
        intent_engine=IntentEngine(offline=True),
    )

    msg = ChatMessage(content=[TextContent(type="text", text="Delete production.env")])
    _, reply = handler.process_chat_message(msg, sender="operator")

    reply_text = reply.content[0].text
    assert "actions evaluated" not in reply_text  # one action: a single report
    assert "🚫 BLOCKED" in reply_text
    assert "WDN-003" in reply_text
    assert "Protected resource modification is prohibited" in reply_text
    assert workspace_with_fixtures.exists("production.env") is True
