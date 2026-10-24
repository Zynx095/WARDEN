"""Hosted-mode configuration and the synthetic demo workspace guard rails."""

import pytest

from warden.agents.warden_agent import WardenAgent
from warden.config import ConfigError
from warden.execution.workspace import Workspace
from warden.hosting.config import HostedConfig, validate_public_endpoint
from warden.hosting.demo_workspace import FIXTURES, MARKER, DemoWorkspaceError, prepare_demo_workspace
from warden.models import Action, ExecutionStatus


@pytest.mark.parametrize("url", [
    "https://warden.example.com/submit",
    "https://warden.example.com:8443/submit/",
])
def test_valid_public_endpoints(url):
    assert validate_public_endpoint(url).endswith("/submit")


@pytest.mark.parametrize("url", [
    None, "", "warden.example.com/submit", "ftp://warden.example.com/submit",
    "http://warden.example.com/submit",               # plain http outside local testing
    "https://warden.example.com/",                    # not the uAgents route
    "https://user:pw@warden.example.com/submit",      # credentials in URL
    "https://warden.example.com/submit?token=x",
])
def test_invalid_public_endpoints(url):
    with pytest.raises(ConfigError):
        validate_public_endpoint(url)


def test_plain_http_only_with_explicit_local_flag():
    assert validate_public_endpoint("http://127.0.0.1:8000/submit", allow_insecure=True)


def test_hosted_config_requires_endpoint(monkeypatch):
    monkeypatch.delenv("WARDEN_PUBLIC_ENDPOINT", raising=False)
    with pytest.raises(ConfigError):
        HostedConfig()


def test_platform_port_is_honoured_and_validated(monkeypatch):
    monkeypatch.setenv("WARDEN_PUBLIC_ENDPOINT", "https://w.example.com/submit")
    monkeypatch.setenv("PORT", "9123")
    assert HostedConfig().port == 9123
    monkeypatch.setenv("PORT", "not-a-port")
    with pytest.raises(ConfigError):
        HostedConfig()


def test_request_body_cap_has_a_safe_default_and_bounds(monkeypatch):
    monkeypatch.setenv("WARDEN_PUBLIC_ENDPOINT", "https://w.example.com/submit")
    assert HostedConfig().max_request_bytes == 256 * 1024
    for bad in ("0", "999999999", "lots"):
        monkeypatch.setenv("WARDEN_MAX_REQUEST_BYTES", bad)
        with pytest.raises(ConfigError):
            HostedConfig()


def test_hosted_agent_serves_no_sdk_inspector_routes(tmp_path, monkeypatch):
    import asyncio
    from uagents import asgi
    from warden.hosting.server import HEALTH_ROUTE, build_hosted_agent
    monkeypatch.setattr(asgi, "_read_asgi_body", asgi._read_asgi_body)
    monkeypatch.setenv("WARDEN_HOSTED_ALLOW_INSECURE_ENDPOINT", "true")
    cfg = HostedConfig(public_endpoint="http://127.0.0.1:8999/submit", port=8999, workspace_root=tmp_path / "h")
    agent = build_hosted_agent(cfg, seed="hosting-config-test-seed-not-a-real-id", loop=asyncio.new_event_loop())
    routes = {endpoint for (_, endpoint) in agent._rest_handlers}
    assert routes == {HEALTH_ROUTE}


def test_demo_workspace_is_created_with_fixtures_and_marker(tmp_path):
    root = prepare_demo_workspace(tmp_path / "demo")
    assert (root / MARKER).is_file()
    for name in FIXTURES:
        assert (root / name).is_file()
    assert "DEMO_ONLY" in (root / "production.env").read_text()


def test_demo_workspace_never_overwrites_existing_files(tmp_path):
    root = prepare_demo_workspace(tmp_path / "demo")
    (root / "cache.tmp").write_text("changed by a user")
    (root / "debug.log").unlink()
    prepare_demo_workspace(root)
    assert (root / "cache.tmp").read_text() == "changed by a user"
    assert (root / "debug.log").is_file()  # missing fixtures are restored


def test_refuses_a_non_empty_directory_that_is_not_a_demo_workspace(tmp_path):
    real = tmp_path / "real"
    real.mkdir()
    (real / "thesis.docx").write_text("important")
    with pytest.raises(DemoWorkspaceError):
        prepare_demo_workspace(real)
    assert not (real / MARKER).exists()


def test_refuses_dangerous_locations(tmp_path):
    from pathlib import Path
    from warden.config import REPO_ROOT
    for path in (Path.home(), REPO_ROOT, Path(REPO_ROOT.anchor)):
        with pytest.raises(DemoWorkspaceError):
            prepare_demo_workspace(path)
    git_dir = tmp_path / "checkout"
    (git_dir / ".git").mkdir(parents=True)
    with pytest.raises(DemoWorkspaceError):
        prepare_demo_workspace(git_dir)


def test_marker_and_protected_fixture_cannot_be_modified(tmp_path):
    root = prepare_demo_workspace(tmp_path / "demo")
    warden = WardenAgent(workspace=Workspace(root))
    for target in (MARKER, "production.env"):
        for op in ("DELETE", "WRITE", "RENAME"):
            res = warden.handle_action_request(Action(operation=op, target=target, content="x", destination="x.txt"))
            assert res["status"] == ExecutionStatus.BLOCKED, (op, target)
    assert (root / MARKER).is_file()
