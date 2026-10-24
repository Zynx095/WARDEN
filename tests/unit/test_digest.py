"""Unit tests for canonical action digests and state fingerprints."""

from pathlib import Path

from warden.security.digest import (
    capture_target_state,
    compute_action_digest,
    compute_state_digest,
    digest_matches,
)


def _d(ws: Path, **kw):
    base = dict(operation="DELETE", target_canonical=ws / "a.tmp", destination_canonical=None,
                content=None, workspace_root=ws)
    base.update(kw)
    return compute_action_digest(**base)


def test_digest_is_deterministic_and_case_insensitive_on_operation(tmp_path):
    assert _d(tmp_path) == _d(tmp_path)
    assert _d(tmp_path, operation="delete") == _d(tmp_path)


def test_digest_changes_with_every_bound_field(tmp_path):
    base = _d(tmp_path)
    assert _d(tmp_path, operation="WRITE") != base
    assert _d(tmp_path, target_canonical=tmp_path / "b.tmp") != base
    assert _d(tmp_path, destination_canonical=tmp_path / "c.tmp") != base
    assert _d(tmp_path, content="x") != base
    other_ws = tmp_path / "other"
    other_ws.mkdir()
    assert _d(tmp_path, workspace_root=other_ws) != base


def test_digest_content_none_equals_empty_string(tmp_path):
    assert _d(tmp_path, content=None) == _d(tmp_path, content="")


def test_state_digest_detects_content_change(tmp_path):
    f = tmp_path / "a.tmp"
    f.write_text("one")
    before = compute_state_digest(capture_target_state(f))
    f.write_text("two")
    assert compute_state_digest(capture_target_state(f)) != before


def test_state_digest_detects_creation_and_removal(tmp_path):
    f = tmp_path / "a.tmp"
    missing = compute_state_digest(capture_target_state(f))
    f.write_text("x")
    present = compute_state_digest(capture_target_state(f))
    assert missing != present
    f.unlink()
    assert compute_state_digest(capture_target_state(f)) == missing


def test_digest_matches_requires_long_prefix(tmp_path):
    d = _d(tmp_path)
    assert digest_matches(d, d)
    assert digest_matches(d, d[:16].upper())
    assert not digest_matches(d, d[:15])
    assert not digest_matches(d, "")
    assert not digest_matches(d, "0" * 16)
