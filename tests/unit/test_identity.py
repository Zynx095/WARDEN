"""Tests for agent identity validation, derivation and safe initialization."""

import asyncio

import pytest
from uagents import Agent

from warden import identity
from warden.identity import (
    AgentIdentityError,
    derive_agent_address,
    generate_seed,
    initialize_identity,
    validate_seed,
)

TEMPLATE = (
    "# comment\nWARDEN_ENV=development\n"
    "# AGENT_SEED=commented_out_value\n"
    "AGENT_SEED=your_secure_agent_seed_phrase_here\n"
    "AGENTVERSE_AGENT_NAME=warden-verification-agent\n"
)


@pytest.mark.parametrize("bad", [None, "", "   "])
def test_missing_seed_rejected(bad):
    with pytest.raises(AgentIdentityError, match="not configured"):
        validate_seed(bad)


@pytest.mark.parametrize("bad", [
    "your_secure_agent_seed_phrase_here", "CHANGEME-CHANGEME-CHANGEME", "<paste seed here please>",
])
def test_placeholder_seed_rejected_without_echo(bad):
    with pytest.raises(AgentIdentityError) as exc:
        validate_seed(bad)
    assert bad not in str(exc.value)


def test_short_seed_rejected():
    with pytest.raises(AgentIdentityError, match="too short"):
        validate_seed("short")


def test_address_is_stable_and_matches_installed_sdk():
    seed = generate_seed()
    assert derive_agent_address(seed) == derive_agent_address(seed)
    assert derive_agent_address(seed).startswith("agent1")
    loop = asyncio.new_event_loop()
    try:
        agent = Agent(name="whatever", seed=seed, port=8999, loop=loop)
        assert agent.address == derive_agent_address(seed)
    finally:
        loop.close()


def test_generated_seeds_are_unique_and_long():
    a, b = generate_seed(), generate_seed()
    assert a != b and len(a) == 64


def test_init_fills_placeholder_and_preserves_other_lines(tmp_path):
    env = tmp_path / ".env"
    env.write_text(TEMPLATE, encoding="utf-8")
    address = initialize_identity(env)
    text = env.read_text(encoding="utf-8")
    lines = text.splitlines()
    assert "WARDEN_ENV=development" in lines
    assert "# AGENT_SEED=commented_out_value" in lines
    assert "AGENTVERSE_AGENT_NAME=warden-verification-agent" in lines
    assert "your_secure_agent_seed_phrase_here" not in text
    seed = next(l for l in lines if l.startswith("AGENT_SEED=")).split("=", 1)[1]
    assert derive_agent_address(seed) == address
    assert not list(tmp_path.glob(".env.*.tmp"))


def test_init_appends_when_no_seed_line(tmp_path):
    env = tmp_path / ".env"
    env.write_text("WARDEN_ENV=development\n", encoding="utf-8")
    initialize_identity(env)
    assert "AGENT_SEED=" in env.read_text(encoding="utf-8")


def test_init_never_replaces_existing_identity(tmp_path):
    env = tmp_path / ".env"
    env.write_text(TEMPLATE, encoding="utf-8")
    first = initialize_identity(env)
    before = env.read_text(encoding="utf-8")
    with pytest.raises(AgentIdentityError, match="already configured"):
        initialize_identity(env)
    assert env.read_text(encoding="utf-8") == before
    seed = [l for l in before.splitlines() if l.startswith("AGENT_SEED=")][0].split("=", 1)[1]
    assert derive_agent_address(seed) == first


def test_init_requires_existing_env_file(tmp_path):
    with pytest.raises(AgentIdentityError, match="does not exist"):
        initialize_identity(tmp_path / ".env")


def test_cli_init_and_address_never_print_seed(tmp_path, monkeypatch, capsys):
    env = tmp_path / ".env"
    env.write_text(TEMPLATE, encoding="utf-8")
    monkeypatch.setenv("WARDEN_ENV_FILE", str(env))
    monkeypatch.delenv("AGENT_SEED", raising=False)

    assert identity.main(["init"]) == 0
    seed = [l for l in env.read_text(encoding="utf-8").splitlines() if l.startswith("AGENT_SEED=")][0].split("=", 1)[1]
    init_out = capsys.readouterr().out
    assert seed not in init_out and "agent1" in init_out

    monkeypatch.setenv("AGENT_SEED", seed)
    assert identity.main(["address"]) == 0
    out = capsys.readouterr()
    assert seed not in out.out + out.err
    assert out.out.strip().split(": ", 1)[1] == derive_agent_address(seed)

    assert identity.main(["init"]) == 1
    assert seed not in capsys.readouterr().err
