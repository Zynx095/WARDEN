"""Canonical action digests and target-state fingerprints.

The action digest is the single identifier that binds an approval, an authorization
token and (later) an audit attestation to one exact operation. The state digest binds
an authorization to the filesystem state that was observed when it was granted.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Dict, Optional

ACTION_DIGEST_VERSION = "warden.action.v1"
STATE_DIGEST_VERSION = "warden.state.v1"

# Minimum prefix length an operator must echo back to approve an action.
MIN_DIGEST_PREFIX = 16


def canonical_path_str(p: Optional[Path | str]) -> str:
    """Canonical, case-folded absolute path string ('' for None)."""
    if p is None:
        return ""
    return str(Path(p).resolve()).lower()


def sha256_text(content: Optional[str]) -> str:
    """SHA-256 of UTF-8 content; ``None`` is treated as empty, matching the executor."""
    return hashlib.sha256((content or "").encode("utf-8")).hexdigest()


def sha256_file(path: Path) -> Optional[str]:
    """Streaming SHA-256 of a regular file, or None if unreadable."""
    try:
        hasher = hashlib.sha256()
        with open(path, "rb") as f:
            while chunk := f.read(65536):
                hasher.update(chunk)
        return hasher.hexdigest()
    except OSError:
        return None


def _digest(payload: Dict[str, Any]) -> str:
    blob = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


def compute_action_digest_from_hash(
    operation: str,
    target_canonical: Path | str,
    destination_canonical: Optional[Path | str],
    content_sha256: str,
    workspace_root: Path | str,
) -> str:
    """Action digest from an already-computed content hash (for parties that never see the content)."""
    return _digest({
        "v": ACTION_DIGEST_VERSION,
        "operation": operation.upper(),
        "target": canonical_path_str(target_canonical),
        "destination": canonical_path_str(destination_canonical),
        "content_sha256": content_sha256,
        "workspace": canonical_path_str(workspace_root),
    })


def compute_action_digest(
    operation: str,
    target_canonical: Path | str,
    destination_canonical: Optional[Path | str],
    content: Optional[str],
    workspace_root: Path | str,
) -> str:
    """Digest of the exact operation, canonical target/destination, content hash and workspace."""
    return compute_action_digest_from_hash(
        operation, target_canonical, destination_canonical, sha256_text(content), workspace_root
    )


def workspace_id(workspace_root: Path | str) -> str:
    """Stable identifier of a workspace that does not reveal its filesystem location."""
    return hashlib.sha256(canonical_path_str(workspace_root).encode("utf-8")).hexdigest()


def describe_path_state(path: Optional[Path]) -> Dict[str, Any]:
    """Observed state of one path: existence, kind, size and content hash."""
    state: Dict[str, Any] = {"exists": False, "kind": None, "size": None, "sha256": None}
    if path is None:
        return state
    try:
        if path.is_symlink():
            state.update(exists=True, kind="symlink")
        elif path.is_file():
            state.update(exists=True, kind="file", size=path.stat().st_size, sha256=sha256_file(path))
        elif path.is_dir():
            state.update(exists=True, kind="dir")
    except OSError:
        state["kind"] = "unreadable"
    return state


def capture_target_state(
    target_canonical: Path,
    destination_canonical: Optional[Path] = None,
) -> Dict[str, Any]:
    """State of the paths an action will touch, to be compared again immediately before execution."""
    return {
        "target": describe_path_state(target_canonical),
        "destination": describe_path_state(destination_canonical) if destination_canonical else None,
    }


def compute_state_digest(state: Dict[str, Any]) -> str:
    return _digest({"v": STATE_DIGEST_VERSION, "state": state})


def digest_matches(expected_digest: str, supplied: str) -> bool:
    """True when ``supplied`` is a long-enough hex prefix of ``expected_digest``."""
    s = (supplied or "").strip().lower()
    return len(s) >= MIN_DIGEST_PREFIX and expected_digest.lower().startswith(s)
