"""ACP hardening: approval binding, error containment, input limits, protocol registration."""

import re
from pathlib import Path

import pytest
from uagents_core.contrib.protocols.chat import (
    ChatAcknowledgement,
    ChatMessage,
    TextContent,
    chat_protocol_spec,
)

from warden.agents.intent_engine import IntentEngine
from warden.agents.warden_agent import WardenAgent
from warden.execution.workspace import Workspace
from warden.integrations.acp_adapter import MAX_MESSAGE_CHARS, WardenACPHandler, create_acp_protocol


def say(handler, text, sender):
    return handler.process_chat_message(ChatMessage(content=[TextContent(type="text", text=text)]), sender=sender)


@pytest.fixture
def ws(tmp_path) -> Workspace:
    w = Workspace(tmp_path / "ws")
    w.create_synthetic_file("old.tmp", "junk")
    return w


@pytest.fixture
def warden(ws) -> WardenAgent:
    return WardenAgent(workspace=ws)


def make_handler(warden, **kw):
    return WardenACPHandler(warden=warden, intent_engine=IntentEngine(api_key=None), **kw)


def request_cleanup(handler) -> str:
    _, reply = say(handler, "clean up old.tmp", "alice")
    text = reply.content[0].text
    assert "AWAITING APPROVAL" in text
    return re.search(r"APPROVE\s+([a-f0-9\-]+)", text).group(1)


def test_other_sender_cannot_approve(warden, ws):
    h = make_handler(warden, approvers=[])
    pending = request_cleanup(h)
    _, reply = say(h, f"APPROVE {pending}", "mallory")
    assert "refused" in reply.content[0].text.lower()
    assert ws.exists("old.tmp")
    _, reply = say(h, f"APPROVE {pending}", "alice")
    assert "VERIFIED" in reply.content[0].text
    assert not ws.exists("old.tmp")


def test_configured_approver_can_approve_other_senders_action(warden, ws):
    h = make_handler(warden, approvers=["operator"])
    pending = request_cleanup(h)
    _, reply = say(h, f"APPROVE {pending}", "operator")
    assert "VERIFIED" in reply.content[0].text
    assert not ws.exists("old.tmp")


def test_approvers_read_from_environment(warden, monkeypatch):
    monkeypatch.setenv("WARDEN_APPROVER_ADDRESSES", " op1 , op2 ,, ")
    assert make_handler(warden).approvers == {"op1", "op2"}


def test_replayed_approval_does_not_raise_or_reexecute(warden, ws):
    h = make_handler(warden)
    pending = request_cleanup(h)
    say(h, f"APPROVE {pending}", "alice")
    ws.create_synthetic_file("old.tmp", "recreated by someone else")
    _, reply = say(h, f"APPROVE {pending}", "alice")
    assert "Failed" in reply.content[0].text or "FAILED" in reply.content[0].text
    assert ws.exists("old.tmp")


def test_unknown_approval_id_reports_failure(warden):
    _, reply = say(make_handler(warden), "APPROVE deadbeef-0000", "alice")
    assert "No pending approval" in reply.content[0].text


def test_oversized_message_rejected_without_action(warden, ws):
    _, reply = say(make_handler(warden), "delete old.tmp " + "x" * MAX_MESSAGE_CHARS, "alice")
    assert "exceeds" in reply.content[0].text
    assert ws.exists("old.tmp")


def test_internal_error_returns_safe_reply_and_ack(warden, ws, caplog):
    class Exploding(IntentEngine):
        def parse_intent(self, text, context=None):
            raise RuntimeError(f"secret detail in {ws.root_path}")

    h = WardenACPHandler(warden=warden, intent_engine=Exploding(api_key=None))
    msg = ChatMessage(content=[TextContent(type="text", text="clean up")])
    ack, reply = h.process_chat_message(msg, sender="alice")
    assert isinstance(ack, ChatAcknowledgement) and ack.acknowledged_msg_id == msg.msg_id
    body = reply.content[0].text
    assert "No action was taken" in body
    assert "secret detail" not in body and str(ws.root_path) not in body
    assert "secret detail" not in caplog.text
    assert ws.exists("old.tmp")


def test_llm_network_error_falls_back_to_deterministic_parser(warden):
    class BrokenClient:
        class chat:
            class completions:
                @staticmethod
                def create(**kw):
                    raise ConnectionError("network down")

    h = WardenACPHandler(warden=warden, intent_engine=IntentEngine(api_key="k", client=BrokenClient()))
    _, reply = say(h, "clean up old.tmp", "alice")
    assert "AWAITING APPROVAL" in reply.content[0].text


def test_workspace_paths_scrubbed_from_replies(warden, ws):
    h = make_handler(warden)
    scrubbed = h._scrub(f"Filesystem error at {ws.root_path}/x and {ws.root_path.as_posix()}/y")
    assert str(ws.root_path) not in scrubbed and ws.root_path.as_posix() not in scrubbed
    assert "<workspace>" in scrubbed


def test_content_without_text_is_treated_as_empty(warden):
    _, reply = make_handler(warden).process_chat_message(ChatMessage(content=[]), sender="alice")
    assert "empty message" in reply.content[0].text.lower()


def test_protocol_registers_chat_spec_and_handlers(warden):
    proto = create_acp_protocol(warden=warden)
    assert proto.name == chat_protocol_spec.name
    assert proto.version == chat_protocol_spec.version
    assert proto.digest == chat_protocol_spec.digest


class _FakeCtx:
    """Records what the registered ACP handler sends, without any network."""

    def __init__(self):
        self.sent = []

        class _L:
            def info(self, *a, **k): pass
            def warning(self, *a, **k): pass
            def error(self, *a, **k): pass

        self.logger = _L()

    async def send(self, destination, message):
        self.sent.append((destination, message))


def test_registered_handler_acks_then_replies_to_sender(warden):
    import asyncio
    proto = create_acp_protocol(warden=warden)
    digest = ChatMessage.build_schema_digest(ChatMessage)
    assert digest in proto.signed_message_handlers or digest in proto.unsigned_message_handlers
    handler = {**proto.signed_message_handlers, **proto.unsigned_message_handlers}[digest]

    ctx = _FakeCtx()
    msg = ChatMessage(content=[TextContent(type="text", text="show README.md")])
    asyncio.run(handler(ctx, "agent1qsender", msg))

    assert [type(m).__name__ for _, m in ctx.sent] == ["ChatAcknowledgement", "ChatMessage"]
    assert all(dest == "agent1qsender" for dest, _ in ctx.sent)
    assert ctx.sent[0][1].acknowledged_msg_id == msg.msg_id


def test_acknowledgement_handler_registered(warden):
    proto = create_acp_protocol(warden=warden)
    digest = ChatAcknowledgement.build_schema_digest(ChatAcknowledgement)
    assert digest in {**proto.signed_message_handlers, **proto.unsigned_message_handlers}


def test_reply_never_contains_agent_seed(warden, ws, monkeypatch):
    seed = "unit-test-seed-should-never-appear-0001"
    monkeypatch.setenv("AGENT_SEED", seed)
    _, reply = say(make_handler(warden), "clean up old.tmp and read .env", "alice")
    assert seed not in reply.content[0].text
