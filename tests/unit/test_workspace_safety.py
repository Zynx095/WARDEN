"""Workspace wipe guards and persistent audit log wiring."""

import json
from pathlib import Path

import pytest

from warden.agents.warden_agent import WardenAgent
from warden.config import REPO_ROOT, WardenConfig
from warden.execution.workspace import Workspace, WorkspaceError
from warden.models import Action


@pytest.mark.parametrize("make_root", [
    lambda tmp: REPO_ROOT,
    lambda tmp: REPO_ROOT.parent,
    lambda tmp: Path(Path.home().anchor),
    lambda tmp: Path.home(),
])
def test_clean_and_teardown_refuse_dangerous_roots(make_root, tmp_path):
    ws = Workspace(make_root(tmp_path), auto_create=False)
    with pytest.raises(WorkspaceError):
        ws.clean()
    with pytest.raises(WorkspaceError):
        ws.teardown()


def test_clean_refuses_directory_with_git_metadata(tmp_path):
    (tmp_path / ".git").mkdir()
    (tmp_path / "keep.txt").write_text("x", encoding="utf-8")
    ws = Workspace(tmp_path)
    with pytest.raises(WorkspaceError, match="Git"):
        ws.clean()
    assert (tmp_path / "keep.txt").exists()


def test_clean_still_works_on_disposable_workspace(tmp_path):
    ws = Workspace(tmp_path / "ws")
    ws.create_synthetic_file("a.tmp", "x")
    ws.create_synthetic_file("sub/b.log", "y")
    ws.clean()
    assert list(ws.root_path.iterdir()) == []


def test_audit_log_default_path_and_disable(monkeypatch):
    monkeypatch.delenv("WARDEN_AUDIT_LOG", raising=False)
    assert WardenConfig().audit_log == (REPO_ROOT / "logs" / "audit.jsonl").resolve()
    monkeypatch.setenv("WARDEN_AUDIT_LOG", "")
    assert WardenConfig().audit_log is None


def test_audit_events_persist_as_jsonl_without_file_content(tmp_path):
    log = tmp_path / "logs" / "audit.jsonl"
    ws = Workspace(tmp_path / "ws")
    warden = WardenAgent(workspace=ws, audit_log_file=log)
    warden.handle_action_request(Action(operation="CREATE", target="n.txt", content="TOP-SECRET-BODY", reason="t"))
    warden.handle_action_request(Action(operation="WRITE", target=".env", content="x", reason="t"))
    raw = log.read_text(encoding="utf-8")
    records = [json.loads(line) for line in raw.splitlines()]
    statuses = {r["execution_status"] for r in records}
    assert {"PROPOSED", "AUTHORIZED", "VERIFIED", "BLOCKED"} <= statuses
    assert "TOP-SECRET-BODY" not in raw
