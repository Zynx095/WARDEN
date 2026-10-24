"""Synthetic workspace for the hosted public demonstration.

The hosted agent only ever operates on a directory that this module created and marked.
It refuses any location that could hold real data: a filesystem root, the home directory,
the repository, a Git checkout, or any non-empty directory without the WARDEN marker.
Fixtures are only created when missing and are never overwritten, so the workspace is
restored on restart but nothing a user did is silently undone mid-session.
"""

from __future__ import annotations

from pathlib import Path
from typing import Dict

from warden.execution.workspace import _unsafe_to_wipe_reason

MARKER = ".warden-demo-workspace"
MARKER_TEXT = "Synthetic WARDEN demo workspace. Contains fixtures only; never real data.\n"

# Every value is synthetic. production.env is a protected-file decoy, not a credential.
FIXTURES: Dict[str, str] = {
    "README.txt": "WARDEN demo workspace. Every file here is synthetic test data.\n",
    "cache.tmp": "DEMO_ONLY temporary cache entry\n",
    "debug.log": "DEMO_ONLY 2026-01-01T00:00:00Z debug: synthetic log line\n",
    "production.env": "DEMO_ONLY_PLACEHOLDER=not-a-real-secret\n",
}


class DemoWorkspaceError(RuntimeError):
    """The configured location is not safe to use as a public demo workspace."""


def prepare_demo_workspace(root: Path | str) -> Path:
    """Create (or reuse) the marked synthetic workspace and add any missing fixtures."""
    path = Path(root).expanduser().resolve()
    reason = _unsafe_to_wipe_reason(path)
    if reason:
        raise DemoWorkspaceError(f"Refusing to use {path.name or path} as the demo workspace: {reason}.")
    if path.exists():
        if not path.is_dir():
            raise DemoWorkspaceError("The demo workspace path exists and is not a directory.")
        if any(path.iterdir()) and not (path / MARKER).is_file():
            raise DemoWorkspaceError(
                "The demo workspace directory already contains files but is not a WARDEN demo "
                "workspace. Point WARDEN_WORKSPACE_ROOT at an empty or dedicated directory."
            )
    path.mkdir(parents=True, exist_ok=True)
    marker = path / MARKER
    if not marker.exists():
        marker.write_text(MARKER_TEXT, encoding="utf-8")
    for name, content in FIXTURES.items():
        fixture = path / name
        if not fixture.exists():
            fixture.write_text(content, encoding="utf-8")
    return path


def is_demo_workspace(root: Path | str) -> bool:
    return (Path(root) / MARKER).is_file()
