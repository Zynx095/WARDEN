"""Unit tests for Agentverse deployment runner and uAgent initialization."""

import pytest
from pathlib import Path
from warden.agents.run_agent import build_warden_agent


def test_build_warden_agent_initialization(tmp_path: Path):
    ws = tmp_path / "agent_ws"
    agent = build_warden_agent(
        name="test-warden-agent",
        seed="deterministic_test_seed_alpha",
        port=8001,
        workspace_dir=ws,
    )

    assert agent.name == "test-warden-agent"
    assert agent.address.startswith("agent1")
    # Verify AgentChatProtocol is registered and verified
    assert len(agent.protocols) == 1
    proto = list(agent.protocols.values())[0]
    assert proto.name == "AgentChatProtocol"
    assert proto.version == "0.3.0"


def test_build_warden_agent_deterministic_address(tmp_path: Path):
    ws = tmp_path / "agent_ws"
    agent1 = build_warden_agent(seed="same_seed_phrase", workspace_dir=ws)
    agent2 = build_warden_agent(seed="same_seed_phrase", workspace_dir=ws)
    assert agent1.address == agent2.address


def test_build_warden_agent_mailbox_configured(tmp_path: Path):
    ws = tmp_path / "agent_ws"
    agent = build_warden_agent(
        mailbox_key="sample-agentverse-key-12345",
        workspace_dir=ws,
    )
    assert agent._use_mailbox is True
