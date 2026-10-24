"""Unit tests for hardened agent identity configuration, validation, and endpoint setup."""

import asyncio
import json
import logging
import os
import socket
import pytest
from pathlib import Path
from unittest.mock import AsyncMock, patch

from uagents.registration import AgentStatusUpdate
import uagents.registration as registration_mod

from warden.agents.run_agent import (
    INSPECTOR_ORIGINS,
    AgentIdentityError,
    InspectorOriginGuard,
    build_warden_agent,
    derive_agent_address,
    enable_inspector_pna_cors,
    inspector_url,
    main,
)
from warden.config import ConfigError
from warden.hosting.config import DEFAULT_DESCRIPTION, DEFAULT_README
from warden.hosting.demo_workspace import MARKER


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

    port = _free_port()
    with patch("uagents.agent.Agent.run"):
        assert main(["--mailbox", "--port", str(port)]) == 0

    out = capsys.readouterr().out
    assert "Inspector:" in out
    assert f"uri=http%3A//127.0.0.1%3A{port}" in out
    assert "WARDEN_APPROVER_ADDRESSES is unset" in out
    # The Inspector is blocked by the browser's Local Network Access permission, not by mixed
    # content: the guidance names the right setting and how to reach it after dismissed prompts.
    assert "Apps on device" in out
    assert "siteDetails?site=https%3A%2F%2Fagentverse.ai" in out
    assert "allow 'Insecure content'" not in out
    assert "mailbox.ps1 status" in out or "warden.agents.mailbox status" in out
    assert "not enough funds" in out  # the expected Almanac-contract warning is explained


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


# --- Agentverse Inspector discovery and mailbox mode -------------------------------------

AGENTVERSE = "https://agentverse.ai"
CHAT_DIGEST = "proto:30a801ed3a83f9a0ff0a9f1e6fe958cb91da1fc2218b153df7b6cbf87bd33d62"


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _asgi(app, method: str, path: str, origin=None, body: bytes = b"", content_type=None):
    """Drive an ASGI app once; return (status, headers, JSON body or raw bytes)."""
    headers = [(b"user-agent", b"pytest")]
    if origin is not None:
        headers.append((b"origin", origin.encode()))
    if content_type:
        headers.append((b"content-type", content_type.encode()))
    scope = {"type": "http", "method": method, "path": path, "headers": headers,
             "client": ("127.0.0.1", 50000), "query_string": b""}
    sent = []

    async def receive():
        return {"type": "http.request", "body": body, "more_body": False}

    async def send(message):
        sent.append(message)

    asyncio.run(app(scope, receive, send))
    start = next(m for m in sent if m["type"] == "http.response.start")
    raw = b"".join(m.get("body", b"") for m in sent if m["type"] == "http.response.body")
    try:
        payload = json.loads(raw) if raw else None
    except ValueError:
        payload = raw
    return start["status"], dict(start["headers"]), payload


def test_inspector_url_matches_what_the_sdk_prints():
    url = inspector_url("agent1qexample", 8001)
    assert url == "https://agentverse.ai/inspect/?uri=http%3A//127.0.0.1%3A8001&address=agent1qexample"


def test_agent_info_reports_what_the_inspector_needs_in_mailbox_mode(tmp_path: Path):
    agent = build_warden_agent(seed="inspector_info_seed_0001", mailbox=True, workspace_dir=tmp_path / "ws")
    status, _, info = _asgi(InspectorOriginGuard(agent._server), "GET", "/agent_info", origin=AGENTVERSE)
    assert status == 200
    assert info["address"] == agent.address
    assert info["agent_type"] == "mailbox"
    assert [e["url"] for e in info["endpoints"]] == ["https://agentverse.ai/v2/agents/mailbox/submit"]
    assert CHAT_DIGEST in info["protocols"]


def test_inspector_routes_refuse_other_web_origins(tmp_path: Path):
    agent = build_warden_agent(seed="inspector_guard_seed_0002", mailbox=True, workspace_dir=tmp_path / "ws")
    guard = InspectorOriginGuard(agent._server)
    for path in ("/agent_info", "/messages"):
        status, _, body = _asgi(guard, "GET", path, origin="https://evil.example")
        assert status == 403 and body == {"error": "origin not allowed"}
        assert _asgi(guard, "OPTIONS", path, origin="https://evil.example")[0] == 403
    # Non-browser local clients (no Origin) and the Agentverse Inspector itself are served.
    assert _asgi(guard, "GET", "/messages")[0] == 200
    assert _asgi(guard, "GET", "/messages", origin=AGENTVERSE)[0] == 200
    assert _asgi(guard, "OPTIONS", "/agent_info", origin=AGENTVERSE)[0] == 204
    assert INSPECTOR_ORIGINS == {AGENTVERSE}


def test_cross_site_text_plain_connect_cannot_register_the_agent(tmp_path: Path):
    """A page on another site can POST text/plain without a CORS preflight; the SDK would parse it."""
    agent = build_warden_agent(seed="inspector_guard_seed_0003", mailbox=True, workspace_dir=tmp_path / "ws")
    body = json.dumps({"user_token": "attacker-token", "agent_type": "mailbox"}).encode()
    with patch("uagents.agent.register_in_agentverse", new_callable=AsyncMock) as register:
        register.return_value = {"success": False}
        status, _, _ = _asgi(InspectorOriginGuard(agent._server), "POST", "/connect", origin="https://evil.example",
                             body=body, content_type="text/plain")
        assert status == 403
        register.assert_not_called()
        # The same request without the guard reaches the SDK's registration call.
        _asgi(agent._server, "POST", "/connect", origin="https://evil.example", body=body, content_type="text/plain")
        register.assert_called_once()


def test_runner_server_wraps_the_sdk_app_and_trusts_proxy_headers_only_from_loopback(monkeypatch):
    import uvicorn
    from uagents import asgi

    monkeypatch.setattr(asgi.ASGIServer, "serve", asgi.ASGIServer.serve)
    monkeypatch.setattr(asgi.ASGIServer, "_pna_cors_enabled", False, raising=False)
    captured = {}

    class FakeConfig:
        def __init__(self, app, **kwargs):
            captured.update(kwargs, app=app)

    class FakeServer:
        def __init__(self, config):
            pass

        async def serve(self):
            return None

    monkeypatch.setattr(uvicorn, "Config", FakeConfig)
    monkeypatch.setattr(uvicorn, "Server", FakeServer)
    assert enable_inspector_pna_cors() is True
    server = asgi.ASGIServer(port=1, loop=asyncio.new_event_loop(), queries={})
    asyncio.run(server.serve())
    assert isinstance(captured["app"], InspectorOriginGuard) and captured["app"].app is server
    assert captured["forwarded_allow_ips"] == "127.0.0.1"  # the SDK's "*" lets anyone claim to be loopback
    assert ("Access-Control-Allow-Private-Network", "true") in captured["headers"]


def test_origin_guard_leaves_message_delivery_untouched(tmp_path: Path):
    agent = build_warden_agent(seed="inspector_guard_seed_0004", mailbox=True, workspace_dir=tmp_path / "ws")
    status, _, body = _asgi(InspectorOriginGuard(agent._server), "POST", "/submit", origin="https://evil.example",
                            body=b"not json", content_type="application/json")
    assert status == 400 and body == {"error": "empty or invalid payload"}  # the SDK's own answer


def test_mailbox_mode_publishes_the_utf8_agentverse_profile_by_default(tmp_path: Path, monkeypatch):
    monkeypatch.delenv("AGENTVERSE_DESCRIPTION", raising=False)
    monkeypatch.delenv("AGENTVERSE_README_PATH", raising=False)
    agent = build_warden_agent(seed="profile_default_seed_0005", mailbox=True, workspace_dir=tmp_path / "ws")
    readme = DEFAULT_README.read_text(encoding="utf-8")
    assert "→" in readme  # the SDK's locale-encoding read would garble this on Windows
    profile = agent._build_registration_profile()  # what the Inspector's Connect -> Mailbox publishes
    assert profile.readme == readme
    assert profile.description == DEFAULT_DESCRIPTION


def test_local_mode_keeps_an_empty_profile(tmp_path: Path, monkeypatch):
    monkeypatch.delenv("AGENTVERSE_DESCRIPTION", raising=False)
    monkeypatch.delenv("AGENTVERSE_README_PATH", raising=False)
    agent = build_warden_agent(seed="profile_local_seed_0006", workspace_dir=tmp_path / "ws")
    assert agent._readme is None and agent._description is None


def test_missing_profile_readme_is_a_configuration_error(tmp_path: Path):
    with pytest.raises(ConfigError, match="README"):
        build_warden_agent(seed="profile_missing_seed_0007", mailbox=True, workspace_dir=tmp_path / "ws",
                           readme_path=str(tmp_path / "missing.md"))


def test_main_refuses_mailbox_together_with_endpoint(monkeypatch, capsys):
    monkeypatch.setenv("AGENT_SEED", "mailbox_endpoint_conflict_seed_08")
    with patch("uagents.agent.Agent.run") as run:
        assert main(["--mailbox", "--endpoint", "https://example.com/submit", "--port", str(_free_port())]) == 1
    run.assert_not_called()
    assert "mutually exclusive" in capsys.readouterr().err


def test_main_refuses_an_occupied_port_instead_of_racing_a_stale_agent(monkeypatch, capsys):
    monkeypatch.setenv("AGENT_SEED", "occupied_port_probe_seed_0009")
    with socket.socket() as holder:
        holder.bind(("127.0.0.1", 0))
        holder.listen(1)
        port = holder.getsockname()[1]
        with patch("uagents.agent.Agent.run") as run:
            assert main(["--mailbox", "--port", str(port)]) == 1
    run.assert_not_called()
    err = capsys.readouterr().err
    assert f"Port {port} is already in use" in err and "Get-NetTCPConnection" in err


def test_main_demo_workspace_runs_on_synthetic_fixtures(tmp_path: Path, monkeypatch, capsys):
    monkeypatch.setenv("AGENT_SEED", "demo_workspace_probe_seed_0010")
    demo = tmp_path / "demo"
    with patch("uagents.agent.Agent.run"):
        assert main(["--mailbox", "--demo-workspace", "--workspace", str(demo), "--port", str(_free_port())]) == 0
    assert (demo / MARKER).is_file() and (demo / "cache.tmp").is_file() and (demo / "production.env").is_file()
    assert "synthetic demo workspace" in capsys.readouterr().out


def test_main_demo_workspace_refuses_a_directory_with_real_files(tmp_path: Path, monkeypatch, capsys):
    monkeypatch.setenv("AGENT_SEED", "demo_workspace_probe_seed_0011")
    real = tmp_path / "real"
    real.mkdir()
    (real / "notes.txt").write_text("mine", encoding="utf-8")
    with patch("uagents.agent.Agent.run") as run:
        assert main(["--demo-workspace", "--workspace", str(real), "--port", str(_free_port())]) == 1
    run.assert_not_called()
    assert (real / "notes.txt").read_text(encoding="utf-8") == "mine"
    assert "not a WARDEN demo workspace" in capsys.readouterr().err
