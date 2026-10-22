"""Controlled workspace abstraction for safe agent filesystem sandboxing."""

from __future__ import annotations

import os
import shutil
from pathlib import Path
from typing import Optional


class WorkspaceError(Exception):
    """Raised on workspace setup, teardown, or containment violations."""
    pass


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
        if self.root_path.exists():
            shutil.rmtree(self.root_path, ignore_errors=True)

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
