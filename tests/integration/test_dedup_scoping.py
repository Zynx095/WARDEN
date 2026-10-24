"""Deduplication is scoped per sender and replay beyond the cache cannot re-execute an approval."""

import re

import pytest
from uagents_core.contrib.protocols.chat import ChatMessage, TextContent

from warden.agents.intent_engine import IntentEngine
from warden.agents.warden_agent import WardenAgent
from warden.execution.workspace import Workspace
from warden.integrations.acp_adapter import WardenACPHandler


def msg(text, msg_id=None):
    content = [TextContent(type="text", text=text)]
    return ChatMessage(content=content) if msg_id is None else ChatMessage(msg_id=msg_id, content=content)


@pytest.fixture
def ws(tmp_path) -> Workspace:
    w = Workspace(tmp_path / "ws")
    w.create_synthetic_file("old.tmp", "junk")
    w.create_synthetic_file("README.md", "readme text")
    return w


@pytest.fixture
def handler(ws) -> WardenACPHandler:
    return WardenACPHandler(warden=WardenAgent(workspace=ws), intent_engine=IntentEngine(api_key=None))


def test_same_message_id_from_another_sender_is_processed_independently(handler):
    first = msg("read README.md")
    _, reply_a = handler.process_chat_message(first, sender="alice")

    colliding = msg("delete old.tmp", msg_id=first.msg_id)
    _, reply_b = handler.process_chat_message(colliding, sender="mallory")

    assert reply_b is not reply_a
    assert "AWAITING APPROVAL" in reply_b.content[0].text
    assert "readme text" not in reply_b.content[0].text


def test_duplicate_delivery_from_same_sender_still_returns_cached_reply(handler, ws):
    first = msg("delete old.tmp")
    _, r1 = handler.process_chat_message(first, sender="alice")
    _, r2 = handler.process_chat_message(first, sender="alice")

    assert r1 is r2
    assert len(handler.warden.auth_manager._pending_approvals) == 1


def test_redelivered_approval_after_cache_eviction_does_not_execute_twice(handler, ws):
    _, reply = handler.process_chat_message(msg("delete old.tmp"), sender="alice")
    cmd = re.search(r"APPROVE\s+[a-f0-9\-]+\s+[a-f0-9]{64}", reply.content[0].text).group(0)
    approve = msg(cmd)
    handler.process_chat_message(approve, sender="alice")
    assert not ws.exists("old.tmp")

    for i in range(1001):  # push the approval out of the bounded dedup cache
        handler.process_chat_message(msg("read README.md"), sender="alice")
    ws.create_synthetic_file("old.tmp", "new file with the same name")
    _, replay = handler.process_chat_message(approve, sender="alice")

    assert "VERIFIED" not in replay.content[0].text
    assert (ws.root_path / "old.tmp").read_text() == "new file with the same name"
