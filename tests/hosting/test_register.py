"""Agentverse registration tool: dry-run sends nothing, publishing needs explicit credentials."""

import re

import pytest
from uagents_core.contrib.protocols.chat import ChatMessage, TextContent

from warden.agents.intent_engine import IntentEngine
from warden.agents.warden_agent import WardenAgent
from warden.execution.workspace import Workspace
from warden.hosting import register
from warden.hosting.demo_workspace import prepare_demo_workspace
from warden.integrations.acp_adapter import WardenACPHandler

SEED = "register-test-seed-not-a-real-identity-01"


@pytest.fixture
def env(monkeypatch):
    monkeypatch.setenv("AGENT_SEED", SEED)
    monkeypatch.setenv("WARDEN_PUBLIC_ENDPOINT", "https://warden.example.com/submit")
    calls = []
    import uagents_core.utils.registration as reg
    monkeypatch.setattr(reg, "register_chat_agent", lambda **kw: calls.append(kw) or True)
    return calls


def test_dry_run_validates_and_sends_nothing(env, capsys):
    assert register.main(["--dry-run"]) == 0
    out = capsys.readouterr().out
    assert env == [] and "nothing was sent" in out
    assert SEED not in out


def test_confirm_without_api_key_refuses(env, capsys):
    assert register.main(["--confirm"]) == 1
    assert env == []


def test_confirm_with_key_publishes_profile_without_echoing_secrets(env, monkeypatch, capsys):
    monkeypatch.setenv("AGENTVERSE_API_KEY", "test-api-key-not-real")
    assert register.main(["--confirm"]) == 0
    out = capsys.readouterr().out
    assert len(env) == 1
    sent = env[0]
    assert sent["endpoint"] == "https://warden.example.com/submit" and sent["active"] is True
    assert sent["credentials"].agentverse_api_key == "test-api-key-not-real"
    assert "test-api-key-not-real" not in out and SEED not in out
    assert "synthetic" in sent["readme"].lower()


def test_plain_http_endpoint_is_never_registered(env, monkeypatch):
    monkeypatch.setenv("WARDEN_HOSTED_ALLOW_INSECURE_ENDPOINT", "true")
    monkeypatch.setenv("WARDEN_PUBLIC_ENDPOINT", "http://127.0.0.1:8000/submit")
    monkeypatch.setenv("AGENTVERSE_API_KEY", "test-api-key-not-real")
    assert register.main(["--confirm"]) == 1
    assert env == []


def test_requires_an_explicit_mode():
    with pytest.raises(SystemExit):
        register.main([])


def test_every_advertised_starter_prompt_behaves_as_described(tmp_path):
    root = prepare_demo_workspace(tmp_path / "hosted")
    handler = WardenACPHandler(warden=WardenAgent(workspace=Workspace(root)),
                               intent_engine=IntentEngine(api_key=None), approvers=[])
    expected = {
        "List the files in the WARDEN workspace": "✅ VERIFIED",
        "Delete cache.tmp": "🔒 AWAITING APPROVAL",
        "Clean up temporary files": "🔒 AWAITING APPROVAL",
        "Delete production.env": "🚫 BLOCKED",
    }
    assert set(expected) == set(register.STARTER_PROMPTS)
    for prompt, pattern in expected.items():
        reply = handler.process_chat_message(
            ChatMessage(content=[TextContent(type="text", text=prompt)]), sender="agent1qjudge")[1].content[0].text
        assert pattern in reply, (prompt, reply[:200])
