"""Unit tests for Auditor uAgent and Protocol construction."""

import asyncio
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock
import pytest

from warden.auditor.agent import (
    AUDITOR_PROTOCOL_NAME,
    AUDITOR_PROTOCOL_VERSION,
    build_auditor_agent,
    create_auditor_protocol,
)
from warden.auditor.config import AuditorConfig
from warden.auditor.models import AuditRequest, AuditVerdict
from warden.auditor.service import AuditorService
from warden.identity import derive_agent_address
from warden.models import Action


def test_build_auditor_agent_distinct_identity(tmp_path: Path):
    custom_seed = "auditor_secure_test_seed_12345678"
    cfg = AuditorConfig(
        enabled=True,
        port=8088,
        seed=custom_seed,
    )

    agent, service = build_auditor_agent(config=cfg)

    expected_address = derive_agent_address(custom_seed)
    assert agent.address == expected_address
    assert service.auditor_address == expected_address
    assert agent.name == "warden-auditor-agent"
    assert agent.address.startswith("agent1")


def test_create_auditor_protocol_spec():
    service = AuditorService(auditor_address="agent1q_test")
    proto = create_auditor_protocol(service)

    assert proto.name == AUDITOR_PROTOCOL_NAME
    assert proto.version == AUDITOR_PROTOCOL_VERSION
    assert AuditRequest in proto.models.values()


def test_protocol_message_handler_invocation(tmp_path: Path):
    ws = tmp_path / "agent_ws"
    ws.mkdir()

    service = AuditorService(auditor_address="agent1q_auditor")
    proto = create_auditor_protocol(service)

    # Prepare an audit request for a non-existent file
    action = Action(operation="DELETE", target="cache.tmp")
    req = AuditRequest.from_action(
        action=action,
        workspace_root=ws,
        executor_claimed_success=True,
    )

    # Mock context and sender
    ctx = MagicMock()
    ctx.logger = MagicMock()
    ctx.send = AsyncMock()

    # Find registered handler for AuditRequest
    handler = list(proto.signed_message_handlers.values())[0]

    async def _run():
        await handler(ctx, "agent1q_coordinator", req)

    asyncio.run(_run())

    ctx.send.assert_awaited_once()
    sent_recipient, sent_attestation = ctx.send.await_args[0]
    assert sent_recipient == "agent1q_coordinator"
    assert sent_attestation.verdict == AuditVerdict.VERIFIED.value
    assert sent_attestation.action_id == action.action_id
