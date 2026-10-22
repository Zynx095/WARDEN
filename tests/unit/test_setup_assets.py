"""Setup assets: .env.example must stay in sync with the code and contain no secrets; scripts must parse."""

import re
import shutil
import subprocess
from pathlib import Path

import pytest
from dotenv import dotenv_values

from warden.config import REPO_ROOT
from warden.identity import AgentIdentityError, initialize_identity, validate_seed

ENV_NAMES = re.compile(r"\b((?:WARDEN|AGENT|AGENTVERSE|ASI_ONE)_[A-Z_]+|OPENAI_API_KEY)\b")
NOT_SETTINGS = {"WARDEN_ENV_FILE"}  # test/dev override documented in the README, not a user setting


def _env_names_used_in_source() -> set:
    names = set()
    for path in (REPO_ROOT / "src").rglob("*.py"):
        text = path.read_text(encoding="utf-8")
        for m in re.finditer(r"(?:getenv|environ\.get|env_bool|_always_on)\(\s*\"([A-Z_]+)\"", text):
            names.add(m.group(1))
        names.update(re.findall(r'os\.environ\[\s*"([A-Z_]+)"', text))
    return {n for n in names if ENV_NAMES.fullmatch(n)}


def test_every_setting_read_by_the_code_is_documented_in_env_example():
    example = (REPO_ROOT / ".env.example").read_text(encoding="utf-8")
    documented = set(ENV_NAMES.findall(example))
    missing = _env_names_used_in_source() - documented - NOT_SETTINGS
    assert not missing, f"undocumented settings: {sorted(missing)}"


def test_env_example_contains_placeholders_only():
    values = dotenv_values(REPO_ROOT / ".env.example")
    assert values["AGENT_SEED"] in (None, ""), "the template must not ship any seed"
    text = (REPO_ROOT / ".env.example").read_text(encoding="utf-8")
    assert not re.search(r"(?i)^\s*(WARDEN_SECRET_KEY|ASI_ONE_API_KEY|AGENTVERSE_MAILBOX_KEY)\s*=\s*\S", text, re.M)
    assert not re.search(r"[0-9a-f]{64}", text), "looks like a real 256-bit secret"


def test_template_seed_is_rejected_then_setup_flow_fills_it(tmp_path):
    env = tmp_path / ".env"
    shutil.copy(REPO_ROOT / ".env.example", env)
    with pytest.raises(AgentIdentityError):
        validate_seed(dotenv_values(env)["AGENT_SEED"])
    address = initialize_identity(env)
    assert address.startswith("agent1")
    assert dotenv_values(env)["WARDEN_WORKSPACE_ROOT"] == "./temp_workspace"  # other settings preserved
    with pytest.raises(AgentIdentityError, match="already configured"):
        initialize_identity(env)


def test_gitignore_excludes_secrets_and_runtime_data():
    lines = (REPO_ROOT / ".gitignore").read_text(encoding="utf-8").splitlines()
    for required in (".env", ".venv/", "logs/", "temp_demo_workspace/", "temp_workspace/", "private_keys.json"):
        assert required in lines, f"{required} missing from .gitignore"
    assert "!.env.example" in lines


POWERSHELL = shutil.which("pwsh") or shutil.which("powershell")


@pytest.mark.skipif(POWERSHELL is None, reason="PowerShell not available")
@pytest.mark.parametrize("script", sorted(p.name for p in (REPO_ROOT / "scripts").glob("*.ps1")))
def test_powershell_scripts_parse_cleanly(script):
    path = REPO_ROOT / "scripts" / script
    cmd = (
        "$e=$null;$t=$null;"
        f"[System.Management.Automation.Language.Parser]::ParseFile('{path}',[ref]$t,[ref]$e)|Out-Null;"
        "if($e.Count){$e|ForEach-Object{$_.Message};exit 1}"
    )
    proc = subprocess.run([POWERSHELL, "-NoProfile", "-Command", cmd], capture_output=True, text=True, timeout=60)
    assert proc.returncode == 0, proc.stdout + proc.stderr


def test_expected_scripts_exist():
    names = {p.name for p in (REPO_ROOT / "scripts").iterdir()}
    assert {"setup.ps1", "doctor.ps1", "run.ps1", "test.ps1", "demo.ps1", "_common.ps1"} <= names
