"""Tests for environment loading, validation and secret-key handling."""

import os
from pathlib import Path

import pytest

from warden import config as cfg
from warden.config import ConfigError, WardenConfig


@pytest.fixture(autouse=True)
def clean_env(monkeypatch: pytest.MonkeyPatch):
    for name in (
        "WARDEN_ENV_FILE", "WARDEN_ENV", "WARDEN_LOG_LEVEL", "WARDEN_WORKSPACE_ROOT",
        "WARDEN_ENFORCE_WORKSPACE_CONTAINMENT", "WARDEN_REQUIRE_APPROVAL_FOR_DESTRUCTIVE",
        "WARDEN_SECRET_KEY",
    ):
        monkeypatch.delenv(name, raising=False)


def test_env_file_loaded_from_repo_root_regardless_of_cwd(tmp_path, monkeypatch):
    env_file = tmp_path / "custom.env"
    env_file.write_text("WARDEN_LOG_LEVEL=debug\n", encoding="utf-8")
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    monkeypatch.chdir(elsewhere)
    monkeypatch.setenv("WARDEN_ENV_FILE", str(env_file))
    try:
        assert cfg.load_environment() == env_file
        assert WardenConfig().log_level == "DEBUG"
    finally:
        os.environ.pop("WARDEN_LOG_LEVEL", None)


def test_default_env_path_is_anchored_at_repo_root(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    assert cfg.DEFAULT_ENV_FILE == cfg.REPO_ROOT / ".env"
    assert (cfg.REPO_ROOT / "pyproject.toml").is_file()


def test_real_environment_wins_over_env_file(tmp_path, monkeypatch):
    env_file = tmp_path / ".env"
    env_file.write_text("WARDEN_LOG_LEVEL=ERROR\n", encoding="utf-8")
    monkeypatch.setenv("WARDEN_LOG_LEVEL", "WARNING")
    cfg.load_environment(env_file)
    assert WardenConfig().log_level == "WARNING"


def test_missing_env_file_returns_none(tmp_path):
    assert cfg.load_environment(tmp_path / "nope.env") is None


def test_relative_workspace_anchored_at_repo_root_not_cwd(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("WARDEN_WORKSPACE_ROOT", "./temp_workspace")
    assert WardenConfig().workspace_root == (cfg.REPO_ROOT / "temp_workspace").resolve()


def test_absolute_workspace_preserved(tmp_path, monkeypatch):
    monkeypatch.setenv("WARDEN_WORKSPACE_ROOT", str(tmp_path / "ws"))
    assert WardenConfig().workspace_root == (tmp_path / "ws").resolve()


@pytest.mark.parametrize("value", ["ture", "2", "disabled"])
def test_malformed_boolean_is_an_error_not_false(monkeypatch, value):
    monkeypatch.setenv("WARDEN_ENFORCE_WORKSPACE_CONTAINMENT", value)
    with pytest.raises(ConfigError):
        WardenConfig()


def test_boolean_defaults_are_secure():
    c = WardenConfig()
    assert c.enforce_workspace_containment is True
    assert c.require_approval_for_destructive is True


def test_invalid_log_level_rejected(monkeypatch):
    monkeypatch.setenv("WARDEN_LOG_LEVEL", "LOUD")
    with pytest.raises(ConfigError):
        WardenConfig()


def test_secret_key_random_per_process_when_unset():
    a, b = WardenConfig().secret_key, WardenConfig().secret_key
    assert len(a) == 64 and a != b


@pytest.mark.parametrize("bad", ["short", "your_secret_key_here_" + "x" * 20, "changeme" + "0" * 30])
def test_weak_or_placeholder_secret_key_rejected(monkeypatch, bad):
    monkeypatch.setenv("WARDEN_SECRET_KEY", bad)
    with pytest.raises(ConfigError) as exc:
        WardenConfig()
    assert bad not in str(exc.value)


def test_strong_secret_key_accepted_and_not_in_repr(monkeypatch):
    key = "a1b2c3d4" * 8
    monkeypatch.setenv("WARDEN_SECRET_KEY", key)
    c = WardenConfig()
    assert c.secret_key == key
    assert key not in repr(c)


def test_tokens_from_different_secret_keys_do_not_verify(tmp_path):
    """Token verification depends on the signing key, so a restart with a new key invalidates old tokens."""
    from warden.models import Action
    from warden.security.authorization import AuthorizationManager

    ws = tmp_path.resolve()
    action = Action(operation="READ", target="a.txt", reason="t")
    target = ws / "a.txt"
    m1, m2 = AuthorizationManager("k" * 40), AuthorizationManager("j" * 40)
    token = m1.issue_token(action, target, None, ws, "WDN-000")
    assert m1.verify_token(token, action, target, None, ws)[0] is True
    ok, reason = m2.verify_token(token, action, target, None, ws)
    assert ok is False and "signature" in reason.lower()
