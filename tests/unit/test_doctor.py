"""Diagnostics must classify problems correctly and never print secrets."""

import os

import pytest

from warden import doctor
from warden.identity import derive_agent_address, generate_seed


def by_name(checks, name):
    return next(c for c in checks if c.name.startswith(name))


@pytest.fixture
def isolated_env(monkeypatch, tmp_path):
    """Private copy of os.environ so load_dotenv inside the doctor cannot leak into other tests."""
    monkeypatch.setattr(os, "environ", dict(os.environ))
    for n in ("AGENT_SEED", "WARDEN_SECRET_KEY", "WARDEN_LOG_LEVEL", "WARDEN_AGENT_PORT",
              "WARDEN_REQUIRE_APPROVAL_FOR_DESTRUCTIVE", "WARDEN_USE_MAILBOX", "AGENTVERSE_MAILBOX_KEY"):
        os.environ.pop(n, None)
    os.environ["WARDEN_ENV_FILE"] = str(tmp_path / "absent.env")
    os.environ["WARDEN_WORKSPACE_ROOT"] = str(tmp_path / "ws")
    os.environ["WARDEN_AUDIT_LOG"] = str(tmp_path / "logs" / "a.jsonl")
    return tmp_path


def test_missing_env_file_and_seed_fail(isolated_env):
    checks = doctor.check_configuration(isolated_env / "absent.env")
    assert by_name(checks, "Configuration file").status == doctor.FAIL
    assert by_name(checks, "Agent identity").status == doctor.FAIL


def test_placeholder_seed_fails_with_fix_hint(isolated_env, monkeypatch):
    env = isolated_env / ".env"
    env.write_text("AGENT_SEED=your_secure_agent_seed_phrase_here\n", encoding="utf-8")
    c = by_name(doctor.check_configuration(env), "Agent identity")
    assert c.status == doctor.FAIL and "identity init" in c.fix


def test_valid_seed_passes_and_only_address_is_shown(isolated_env, monkeypatch):
    seed = generate_seed()
    env = isolated_env / ".env"
    env.write_text(f"AGENT_SEED={seed}\n", encoding="utf-8")
    checks = doctor.check_configuration(env)
    c = by_name(checks, "Agent identity")
    assert c.status == doctor.PASS and derive_agent_address(seed) in c.detail
    assert all(seed not in f"{x.name}{x.detail}{x.fix}" for x in checks)


def test_weak_secret_key_fails_without_echo(isolated_env, monkeypatch):
    os.environ["WARDEN_SECRET_KEY"] = "hunter2"
    c = by_name(doctor.check_configuration(isolated_env / "absent.env"), "WARDEN_SECRET_KEY")
    assert c.status == doctor.FAIL and "hunter2" not in c.detail


def test_malformed_setting_fails(isolated_env, monkeypatch):
    os.environ["WARDEN_REQUIRE_APPROVAL_FOR_DESTRUCTIVE"] = "maybe"
    c = by_name(doctor.check_configuration(isolated_env / "absent.env"), "Settings parse")
    assert c.status == doctor.FAIL


def test_workspace_checks_pass_for_disposable_dir(isolated_env):
    checks = doctor.check_filesystem()
    assert by_name(checks, "Workspace is disposable").status == doctor.PASS
    assert by_name(checks, "Workspace writable").status == doctor.PASS
    assert by_name(checks, "Audit log directory").status == doctor.PASS


def test_repo_root_workspace_is_flagged(isolated_env, monkeypatch):
    os.environ["WARDEN_WORKSPACE_ROOT"] = str(doctor.REPO_ROOT)
    assert by_name(doctor.check_filesystem(), "Workspace is disposable").status == doctor.FAIL


def test_git_hygiene_for_this_repo():
    checks = doctor.check_git_hygiene()
    assert by_name(checks, ".env ignored").status in {doctor.PASS, doctor.WARN}
    assert by_name(checks, ".env not tracked").status != doctor.FAIL


def test_integration_readiness_never_claims_connectivity(isolated_env):
    os.environ["WARDEN_USE_MAILBOX"] = "true"
    c = by_name(doctor.check_integration_readiness(), "Agentverse mailbox")
    assert "NOT verified" in c.detail


def test_run_doctor_exit_code_and_output_are_secret_free(isolated_env, monkeypatch):
    seed = generate_seed()
    os.environ["AGENT_SEED"] = seed
    os.environ["ASI_ONE_API_KEY"] = "sk-test-very-secret-value"
    lines = []
    code = doctor.run_doctor(out=lines.append)
    text = "\n".join(lines)
    assert seed not in text and "sk-test-very-secret-value" not in text
    assert "Summary:" in text
    assert code in (0, 1)
