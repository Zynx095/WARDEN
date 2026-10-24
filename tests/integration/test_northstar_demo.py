"""The Northstar judge demo: every scripted prompt keeps its decision, file effect and audit record."""

import json
import sys
from pathlib import Path

import pytest

DEMO = Path(__file__).resolve().parents[2] / "demo"
sys.path.insert(0, str(DEMO))

import northstar  # noqa: E402
import northstar_validate  # noqa: E402


def test_every_scripted_prompt_behaves_as_the_judge_script_says():
    steps = northstar_validate.run(out=lambda _text: None)
    failures = [f"{s.name}: {f}" for s in steps for f in s.failures]
    assert failures == []
    assert sum(len(s.checks) for s in steps) >= 20


def test_prompt_cards_match_the_validated_prompts():
    cards = (DEMO / "PROMPT_CARDS.md").read_text(encoding="utf-8")
    for prompt in northstar_validate.PROMPTS.values():
        assert f"`{prompt}`" in cards


def test_setup_refuses_directories_it_did_not_create(tmp_path):
    foreign = tmp_path / "somebody_elses_project"
    foreign.mkdir()
    (foreign / "notes.txt").write_text("keep me", encoding="utf-8")
    with pytest.raises(SystemExit, match="REFUSED"):
        northstar.build(foreign)
    assert (foreign / "notes.txt").read_text(encoding="utf-8") == "keep me"


def test_setup_resets_its_own_workspace_and_records_a_baseline(tmp_path):
    root = tmp_path / "northstar_workspace"
    northstar.build(root)
    (root / "tmp" / "session_cache.tmp").unlink()
    (root / "notes").mkdir()
    (root / "notes" / "x.txt").write_text("x", encoding="utf-8")
    manifest = northstar.build(root)
    assert (root / "tmp" / "session_cache.tmp").is_file() and not (root / "notes").exists()
    assert json.loads((root / northstar.MANIFEST).read_text(encoding="utf-8")) == manifest
    assert "DEMO_ONLY_PLACEHOLDER" in (root / "production.env").read_text(encoding="utf-8")
    assert set(manifest["files"]) >= set(northstar.FIXTURES)
