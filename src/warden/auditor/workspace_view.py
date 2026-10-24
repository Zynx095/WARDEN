"""Read-only workspace view for the Auditor uAgent."""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Dict, Optional


class ReadOnlyWorkspaceView:
    """Read-only view into a workspace boundary for the independent Auditor.

    NOTE ON SECURITY BOUNDARIES:
    This class provides API-level read-only access (exposing no modification,
    creation, deletion, or truncation methods). It does not provide OS-level
    kernel privilege isolation; true security isolation between agents requires
    separate OS user accounts, containers, or process sandboxes.
    """

    def __init__(self, root_path: Path | str) -> None:
        self.root_path = Path(root_path).resolve()

    def get_canonical_path(self, relative_str: str, allow_root: bool = False) -> Optional[Path]:
        """Resolve a relative path string and verify strict containment within workspace_root."""
        clean_rel = relative_str.replace("\\", "/").strip().lstrip("/")
        if not clean_rel:
            return self.root_path if allow_root else None

        try:
            candidate = (self.root_path / clean_rel).resolve()
            candidate.relative_to(self.root_path)
            return candidate
        except (ValueError, RuntimeError):
            return None

    def exists(self, relative_str: str, allow_root: bool = False) -> bool:
        """Check if a path exists within the workspace."""
        path = self.get_canonical_path(relative_str, allow_root=allow_root)
        return path.exists() if path is not None else False

    def is_file(self, relative_str: str) -> bool:
        """Check if a path is a regular file within the workspace."""
        path = self.get_canonical_path(relative_str)
        return path.is_file() if path is not None else False

    def is_dir(self, relative_str: str, allow_root: bool = False) -> bool:
        """Check if a path is a directory within the workspace."""
        path = self.get_canonical_path(relative_str, allow_root=allow_root)
        return path.is_dir() if path is not None else False

    def read_bytes(self, relative_str: str) -> Optional[bytes]:
        """Read file bytes from disk without modifying any filesystem state."""
        path = self.get_canonical_path(relative_str)
        if path is None or not path.is_file():
            return None
        try:
            return path.read_bytes()
        except OSError:
            return None

    def compute_sha256(self, relative_str: str) -> Optional[str]:
        """Compute SHA-256 hash of a file within the workspace."""
        data = self.read_bytes(relative_str)
        return hashlib.sha256(data).hexdigest() if data is not None else None

    def capture_manifest(self) -> Dict[str, Optional[str]]:
        """Capture a manifest of all files and their SHA-256 hashes within the workspace."""
        manifest: Dict[str, Optional[str]] = {}
        if not self.root_path.exists():
            return manifest
        try:
            for item in sorted(self.root_path.rglob("*")):
                if item.is_file() and ".git" not in item.parts:
                    rel = item.relative_to(self.root_path).as_posix()
                    try:
                        manifest[rel] = hashlib.sha256(item.read_bytes()).hexdigest()
                    except OSError:
                        manifest[rel] = None
        except OSError:
            pass
        return manifest
