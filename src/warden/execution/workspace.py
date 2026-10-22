"""Controlled workspace abstraction for safe agent filesystem sandboxing."""

from __future__ import annotations

import os
import shutil
from pathlib import Path
from typing import Optional


class WorkspaceError(Exception):
    """Raised on workspace setup, teardown, or containment violations."""
    pass


def _unsafe_to_wipe_reason(root: Path) -> Optional[str]:
    """Explain why ``root`` must never be bulk-deleted, or None if it is acceptable."""
    from warden.config import REPO_ROOT

    if root == Path(root.anchor):
        return "it is a filesystem root"
    if root == Path.home().resolve():
        return "it is the user's home directory"
    if root == REPO_ROOT or root in REPO_ROOT.parents:
        return "it is the WARDEN repository or one of its parent directories"
    if (root / ".git").exists():
        return "it contains Git metadata"
    return None


class Workspace:
    """Manages an isolated directory sandbox for safe file operations."""

    def __init__(self, root_path: Path | str, auto_create: bool = True) -> None:
        self.root_path = Path(root_path).resolve()
        if auto_create:
            self.setup()

    def setup(self) -> None:
        """Ensure the workspace root directory exists."""
        self.root_path.mkdir(parents=True, exist_ok=True)

    def clean(self) -> None:
        """Safely remove all contents within the workspace root."""
        self._assert_disposable()
        if not self.root_path.exists():
            return
        for item in self.root_path.iterdir():
            if item.is_dir() and not item.is_symlink():
                shutil.rmtree(item, ignore_errors=True)
            else:
                try:
                    item.unlink()
                except OSError:
                    pass

    def teardown(self) -> None:
        """Completely delete the workspace root directory."""
        self._assert_disposable()
        if self.root_path.exists():
            shutil.rmtree(self.root_path, ignore_errors=True)

    def _assert_disposable(self) -> None:
        reason = _unsafe_to_wipe_reason(self.root_path)
        if reason:
            raise WorkspaceError(f"Refusing to delete workspace contents: {reason}.")

    def get_canonical_path(self, relative_str: str) -> Path:
        """Resolve a relative path inside the workspace."""
        clean_rel = relative_str.replace("\\", "/").lstrip("/")
        return (self.root_path / clean_rel).resolve()

    def exists(self, relative_str: str) -> bool:
        """Check if a path exists within the workspace."""
        target = self.get_canonical_path(relative_str)
        return target.exists()

    def create_synthetic_file(self, relative_str: str, content: str = "") -> Path:
        """Create a synthetic file inside the workspace for test/demo fixtures."""
        target = self.get_canonical_path(relative_str)
        # Ensure target is strictly inside workspace
        target.relative_to(self.root_path)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")
        return target
