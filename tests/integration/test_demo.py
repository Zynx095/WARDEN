"""The disposable-workspace demo must be repeatable, offline and self-checking."""

import pytest

from warden import demo
from warden.agents.intent_engine import IntentEngine
from warden.config import REPO_ROOT
from warden.execution.workspace import WorkspaceError


def quiet(_: str) -> None:
    pass


def test_demo_passes_and_is_repeatable(tmp_path):
    ws, log = tmp_path / "ws", tmp_path / "audit.jsonl"
    first = demo.run_demo(ws, log, out=quiet)
    second = demo.run_demo(ws, log, out=quiet)
    assert len(first.checks) == len(second.checks) >= 10
    assert sorted(p.name for p in ws.iterdir()) == sorted(demo.KEEP_FILES + ["cleanup_report.txt"])
    # The audit log is reset each run, so it never accumulates across runs. 22 = 19 pipeline events
    # plus one AUTHORIZED record per human approval (the demo approves three deletions).
    assert len(log.read_text(encoding="utf-8").splitlines()) == 22


def test_demo_never_uses_network_even_if_api_key_is_set(tmp_path, monkeypatch):
    monkeypatch.setenv("ASI_ONE_API_KEY", "dummy-key-for-test")

    def forbidden(*a, **k):
        raise AssertionError("demo attempted an LLM/network call")

    monkeypatch.setattr(IntentEngine, "_call_llm", forbidden)
    demo.run_demo(tmp_path / "ws", tmp_path / "a.jsonl", out=quiet)


def test_demo_refuses_to_wipe_the_repository(tmp_path):
    with pytest.raises(WorkspaceError):
        demo.run_demo(REPO_ROOT, tmp_path / "a.jsonl", out=quiet)


def test_failed_expectation_raises_demo_failure(tmp_path):
    report = demo.DemoReport(workspace=tmp_path, audit_log=tmp_path / "a.jsonl")
    report.check(True, "ok")
    with pytest.raises(demo.DemoFailure, match="bad thing"):
        report.check(False, "bad thing")


def test_demo_fixtures_are_synthetic():
    blob = "".join(demo.SYNTHETIC_FILES.values())
    assert "SYNTHETIC" in blob or "demo" in blob.lower()
    assert ".git" not in demo.SYNTHETIC_FILES and ".env" not in demo.SYNTHETIC_FILES
