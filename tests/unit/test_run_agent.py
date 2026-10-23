"""Unit tests for hardened agent identity configuration, validation, and endpoint setup."""

import asyncio
import logging
import os
import pytest
from pathlib import Path
from unittest.mock import AsyncMock, patch

from uagents.registration import AgentStatusUpdate
import uagents.registration as registration_mod

from warden.agents.run_agent import (
    AgentIdentityError,
    build_warden_agent,
    derive_agent_address,
    enable_inspector_pna_cors,
    main,
)


def test_missing_seed_raises_agent_identity_error(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    # Ensure AGENT_SEED is not in environment
    monkeypatch.delenv("AGENT_SEED", raising=False)
    ws = tmp_path / "agent_ws"

    with pytest.raises(AgentIdentityError) as exc_info:
        build_warden_agent(seed=None, workspace_dir=ws)

    assert "Agent seed is not configured" in str(exc_info.value)
    assert "Fallback to predictable hardcoded seeds is prohibited" in str(exc_info.value)


def test_empty_or_whitespace_seed_raises_agent_identity_error(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.delenv("AGENT_SEED", raising=False)
    ws = tmp_path / "agent_ws"

    with pytest.raises(AgentIdentityError):
        build_warden_agent(seed="   ", workspace_dir=ws)


def test_explicit_seed_initializes_agent(tmp_path: Path):
    ws = tmp_path / "agent_ws"
    test_seed = "test_entropy_seed_alpha_001"
    agent = build_warden_agent(
        name="test-warden-agent",
        seed=test_seed,
        port=8001,
        workspace_dir=ws,
    )

    assert agent.name == "test-warden-agent"
    assert agent.address.startswith("agent1")
    # Verify AgentChatProtocol is registered
    assert len(agent.protocols) == 1
    proto = list(agent.protocols.values())[0]
    assert proto.name == "AgentChatProtocol"
    assert proto.version == "0.3.0"


def test_agent_seed_from_environment(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("AGENT_SEED", "test_env_seed_phrase_secure_xyz")
    ws = tmp_path / "agent_ws"

    agent = build_warden_agent(workspace_dir=ws)
    assert agent.address.startswith("agent1")


def test_deterministic_identity_across_repeated_runs(tmp_path: Path):
    ws = tmp_path / "agent_ws"
    seed = "fixed_test_reproducibility_seed_789"

    addr1 = derive_agent_address(seed)
    addr2 = derive_agent_address(seed)
    assert addr1 == addr2

    agent1 = build_warden_agent(seed=seed, workspace_dir=ws)
    agent2 = build_warden_agent(seed=seed, workspace_dir=ws)
    assert agent1.address == agent2.address
    assert agent1.address == addr1


def test_different_seeds_produce_distinct_addresses():
    addr1 = derive_agent_address("seed_instance_one")
    addr2 = derive_agent_address("seed_instance_two")
    assert addr1 != addr2


def test_derive_agent_address_validation():
    with pytest.raises(AgentIdentityError):
        derive_agent_address("")

    with pytest.raises(AgentIdentityError):
        derive_agent_address("   ")


def test_mailbox_key_configuration(tmp_path: Path):
    ws = tmp_path / "agent_ws"
    agent = build_warden_agent(
        seed="mailbox_test_seed_123",
        mailbox_key="sample-agentverse-key-12345",
        workspace_dir=ws,
    )
    assert agent._use_mailbox is True


def test_mailbox_flag_configuration(tmp_path: Path):
    ws = tmp_path / "agent_ws"
    agent = build_warden_agent(
        seed="mailbox_test_seed_456",
        mailbox=True,
        workspace_dir=ws,
    )
    assert agent._use_mailbox is True


def test_local_mode_without_mailbox(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.delenv("AGENTVERSE_MAILBOX_KEY", raising=False)
    ws = tmp_path / "agent_ws"
    agent = build_warden_agent(
        seed="local_mode_seed_789",
        mailbox=False,
        mailbox_key=None,
        workspace_dir=ws,
    )
    assert agent._use_mailbox is False


def test_seed_not_leaked_in_logs_or_attributes(tmp_path: Path, caplog: pytest.LogCaptureFixture):
    ws = tmp_path / "agent_ws"
    secret_seed = "super_secret_unexposed_seed_value_999"

    with caplog.at_level(logging.INFO):
        agent = build_warden_agent(
            seed=secret_seed,
            mailbox_key="dummy_key_12345678",
            workspace_dir=ws,
        )

    # The seed must NOT appear anywhere in logged output
    for record in caplog.records:
        assert secret_seed not in record.message
        assert secret_seed not in str(record.args)

    # The agent public representation must not contain the seed
    assert secret_seed not in str(agent.address)
    assert secret_seed not in str(agent.name)


def test_placeholder_seed_from_env_template_rejected(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("AGENT_SEED", "your_secure_agent_seed_phrase_here")
    with pytest.raises(AgentIdentityError):
        build_warden_agent(workspace_dir=tmp_path / "ws")


def test_default_mode_is_local_only():
    from warden.agents.run_agent import describe_mode
    assert describe_mode(False, None) == "local-only"
    assert "not verified" in describe_mode(True, None)
    assert "not verified" in describe_mode(False, "https://example.invalid/submit")


def test_restrict_bind_host_sets_sdk_constant():
    from uagents import asgi
    from warden.agents.run_agent import restrict_bind_host
    original = asgi.HOST
    try:
        assert restrict_bind_host("127.0.0.1") is True
        assert asgi.HOST == "127.0.0.1"
    finally:
        asgi.HOST = original


def test_main_show_address_uses_repo_env_file_not_cwd(tmp_path, monkeypatch, capsys):
    from warden.identity import generate_seed
    seed = generate_seed()
    env = tmp_path / "custom.env"
    env.write_text(f"AGENT_SEED={seed}\n", encoding="utf-8")
    other = tmp_path / "other"
    other.mkdir()
    monkeypatch.chdir(other)
    monkeypatch.delenv("AGENT_SEED", raising=False)
    monkeypatch.setenv("WARDEN_ENV_FILE", str(env))
    assert main(["--show-address"]) == 0
    out = capsys.readouterr().out
    assert derive_agent_address(seed) in out and seed not in out
    monkeypatch.delenv("AGENT_SEED", raising=False)


def test_main_missing_seed_exits_nonzero_without_traceback(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("WARDEN_ENV_FILE", str(tmp_path / "absent.env"))
    monkeypatch.delenv("AGENT_SEED", raising=False)
    assert main(["--show-address"]) == 1
    assert "CONFIGURATION ERROR" in capsys.readouterr().err


def test_local_mode_disables_telemetry_reporting(tmp_path: Path):
    agent = build_warden_agent(seed="telemetry_test_seed_0001", workspace_dir=tmp_path / "ws")
    assert agent._report_events is False
    assert agent._endpoints == []


def test_mailbox_mode_keeps_default_reporting(tmp_path: Path):
    agent = build_warden_agent(seed="telemetry_test_seed_0002", mailbox=True, workspace_dir=tmp_path / "ws")
    assert agent._report_events is True


def test_publish_manifest_option(tmp_path: Path):
    with patch("uagents.agent.Agent.publish_manifest", new_callable=AsyncMock) as mock_pub:
        agent = build_warden_agent(
            seed="publish_manifest_seed_123",
            workspace_dir=tmp_path / "ws",
            publish_manifest=True,
        )
        assert agent is not None


def test_agent_description_and_readme_configuration(tmp_path: Path):
    readme = tmp_path / "AGENT_README.md"
    readme.write_text("# WARDEN Verification Agent\nAutonomous verification core.", encoding="utf-8")
    agent = build_warden_agent(
        seed="desc_readme_seed_456",
        workspace_dir=tmp_path / "ws",
        description="Autonomous verification system for ASI:One",
        readme_path=str(readme),
    )
    assert agent._description == "Autonomous verification system for ASI:One"
    assert agent._readme is not None
    assert "Autonomous verification core" in agent._readme


def test_sdk_startup_active_status_update_behavior(tmp_path: Path):
    """Source-verified test confirming SDK startup Almanac active-status behavior.

    Verifies:
    1. AgentStatusUpdate signs only public identifier, timestamp and is_active flag.
    2. Private key and seed are never transmitted in the payload.
    3. update_agent_status suppresses network/service errors without raising.
    """
    seed = "startup_active_probe_seed_789"
    agent = build_warden_agent(seed=seed, workspace_dir=tmp_path / "ws")

    status = AgentStatusUpdate(agent_identifier=agent.identifier, is_active=True)
    status.sign(agent._identity)
    dumped = status.model_dump_json()

    assert agent.address in dumped
    assert "is_active" in dumped
    assert "signature" in dumped
    assert seed not in dumped

    # Verify that errors in the Almanac status update call are non-fatal and suppressed
    with patch("uagents.registration.almanac_api_post", side_effect=ConnectionError("offline")):
        asyncio.run(registration_mod.update_agent_status(status, agent._almanac_api_url))


def test_main_mailbox_mode_prints_inspector_and_advisory(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys):
    monkeypatch.setenv("AGENT_SEED", "mailbox_probe_seed_unique_999")
    monkeypatch.delenv("WARDEN_APPROVER_ADDRESSES", raising=False)

    with patch("uagents.agent.Agent.run"):
        assert main(["--mailbox", "--port", "8008"]) == 0

    out = capsys.readouterr().out
    assert "Inspector:" in out
    assert "8008" in out
    assert "WARDEN_APPROVER_ADDRESSES is unset" in out
    assert "Browser tip:" in out


def test_enable_inspector_pna_cors():
    from uagents import asgi
    assert enable_inspector_pna_cors() is True
    assert getattr(asgi.ASGIServer, "_pna_cors_enabled", False) is True


def test_endpoint_overrides_and_disables_mailbox_in_sdk(tmp_path: Path, caplog: pytest.LogCaptureFixture):
    """Verifies that setting endpoint when mailbox=True is passed causes the SDK
    to disable mailbox mode and unset MailboxClient, proving endpoint should NOT be added.
    """
    with caplog.at_level(logging.WARNING):
        agent = build_warden_agent(
            seed="endpoint_override_seed_123",
            workspace_dir=tmp_path / "ws",
            mailbox=True,
            endpoint="http://127.0.0.1:8000/submit",
        )
    assert agent._use_mailbox is False
    assert agent._mailbox_client is None
    assert agent.agent_type == "custom"
    assert any("Endpoint configuration overrides mailbox setting" in r.message for r in caplog.records)
