"""Unit tests for workspace path validation."""

import os
import pytest
from pathlib import Path
from warden.security.path_validation import PathValidator


@pytest.fixture
def workspace_dir(tmp_path: Path) -> Path:
    ws = tmp_path / "sandbox"
    ws.mkdir()
    (ws / "safe.txt").write_text("safe content", encoding="utf-8")
    (ws / "sub").mkdir()
    (ws / "sub" / "nested.txt").write_text("nested content", encoding="utf-8")
    return ws


def test_safe_relative_path(workspace_dir: Path):
    validator = PathValidator(workspace_dir)
    res = validator.validate_path("safe.txt")
    assert res.is_safe is True
    assert res.canonical_path == (workspace_dir / "safe.txt").resolve()
    assert res.relative_path == "safe.txt"


def test_safe_nested_relative_path(workspace_dir: Path):
    validator = PathValidator(workspace_dir)
    res = validator.validate_path("sub/nested.txt")
    assert res.is_safe is True
    assert res.canonical_path == (workspace_dir / "sub" / "nested.txt").resolve()


def test_parent_directory_traversal_blocked(workspace_dir: Path):
    validator = PathValidator(workspace_dir)
    res = validator.validate_path("../../outside.txt")
    assert res.is_safe is False
    assert res.policy_id == "WDN-002"
    assert "Parent directory traversal" in (res.error_reason or "")


def test_internal_parent_traversal_blocked(workspace_dir: Path):
    validator = PathValidator(workspace_dir)
    res = validator.validate_path("sub/../safe.txt")
    assert res.is_safe is False
    assert res.policy_id == "WDN-002"


def test_absolute_path_blocked(workspace_dir: Path):
    validator = PathValidator(workspace_dir)
    res = validator.validate_path("/etc/shadow")
    assert res.is_safe is False
    assert res.policy_id == "WDN-002"


def test_windows_drive_letter_blocked(workspace_dir: Path):
    validator = PathValidator(workspace_dir)
    res = validator.validate_path("C:\\Windows\\System32\\calc.exe")
    assert res.is_safe is False
    assert res.policy_id == "WDN-002"


def test_unc_path_blocked(workspace_dir: Path):
    validator = PathValidator(workspace_dir)
    res = validator.validate_path("\\\\192.168.1.1\\share\\secret.txt")
    assert res.is_safe is False
    assert res.policy_id == "WDN-002"
    assert "UNC paths are strictly prohibited" in (res.error_reason or "")


def test_null_byte_injection_blocked(workspace_dir: Path):
    validator = PathValidator(workspace_dir)
    res = validator.validate_path("safe.txt\x00.exe")
    assert res.is_safe is False
    assert res.policy_id == "WDN-002"
    assert "null byte" in (res.error_reason or "")


def test_alternate_data_stream_blocked(workspace_dir: Path):
    validator = PathValidator(workspace_dir)
    res = validator.validate_path("safe.txt:hidden_stream")
    assert res.is_safe is False
    assert res.policy_id == "WDN-002"


def test_reserved_windows_name_blocked(workspace_dir: Path):
    validator = PathValidator(workspace_dir)
    res = validator.validate_path("CON.txt")
    assert res.is_safe is False
    assert res.policy_id == "WDN-002"


def test_trailing_dot_or_space_blocked(workspace_dir: Path):
    validator = PathValidator(workspace_dir)
    res1 = validator.validate_path("file.txt.")
    assert res1.is_safe is False
    res2 = validator.validate_path("file.txt ")
    assert res2.is_safe is False


def test_must_exist_flag(workspace_dir: Path):
    validator = PathValidator(workspace_dir)
    res_nonexistent = validator.validate_path("new_file.txt", must_exist=True)
    assert res_nonexistent.is_safe is False
    assert res_nonexistent.policy_id == "WDN-005"

    res_allowed_nonexistent = validator.validate_path("new_file.txt", must_exist=False)
    assert res_allowed_nonexistent.is_safe is True


def test_symlink_breakout_blocked_if_supported(workspace_dir: Path, tmp_path: Path):
    external_secret = tmp_path / "external_secret.txt"
    external_secret.write_text("CLASSIFIED", encoding="utf-8")

    link_path = workspace_dir / "symlink_escape"
    try:
        os.symlink(external_secret, link_path)
    except (OSError, NotImplementedError):
        pytest.skip("Symlink creation not permitted or supported in this environment.")

    validator = PathValidator(workspace_dir)
    res = validator.validate_path("symlink_escape")
    assert res.is_safe is False
    assert res.policy_id == "WDN-002"
