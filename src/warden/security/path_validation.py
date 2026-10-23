"""Canonical workspace path validation and boundary enforcement."""

from __future__ import annotations

import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Optional, Set

# Windows reserved device names
WINDOWS_RESERVED_NAMES = {
    "CON", "PRN", "AUX", "NUL",
    "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9",
    "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
}

# Protected sensitive filenames (case-insensitive)
DEFAULT_PROTECTED_FILES: Set[str] = {
    ".env",
    "production.env",
    "secrets.json",
    "credentials.json",
}


@dataclass(frozen=True)
class PathValidationResult:
    """Result of path validation against a workspace boundary."""
    is_safe: bool
    canonical_path: Optional[Path] = None
    relative_path: Optional[str] = None
    error_reason: Optional[str] = None
    policy_id: Optional[str] = None


class PathValidator:
    """Validates and enforces strict workspace containment and path safety."""

    def __init__(
        self,
        workspace_root: Path | str,
        protected_files: Optional[Set[str]] = None,
    ) -> None:
        self.workspace_root = Path(workspace_root).resolve()
        self.protected_files = {f.lower() for f in (protected_files or DEFAULT_PROTECTED_FILES)}

    def is_protected_filename(self, filename: str) -> bool:
        """Check if a filename is protected."""
        return filename.lower().strip() in self.protected_files

    def validate_path(
        self,
        target_str: str,
        must_exist: bool = False,
        allow_root: bool = False,
    ) -> PathValidationResult:
        """Validate that a target path is strictly inside the workspace boundary.
        
        Guards against:
        - Null bytes and illegal control characters
        - Windows drive letters and UNC paths
        - Windows reserved device names (CON, NUL, COM1, etc.)
        - Alternate Data Streams (colon in path)
        - Parent directory traversal (`..`)
        - Symlink and junction breakouts
        - Escapes beyond canonical workspace root
        """
        if not target_str or not isinstance(target_str, str):
            return PathValidationResult(
                is_safe=False,
                error_reason="Path cannot be empty or non-string.",
                policy_id="WDN-002",
            )

        # 1. Reject null bytes
        if "\x00" in target_str:
            return PathValidationResult(
                is_safe=False,
                error_reason="Path contains null byte injection.",
                policy_id="WDN-002",
            )

        # 2. Reject UNC paths (\\host\share or //host/share)
        if target_str.startswith(("\\\\", "//")):
            return PathValidationResult(
                is_safe=False,
                error_reason="UNC paths are strictly prohibited.",
                policy_id="WDN-002",
            )

        # Normalize slashes for lexical checks
        normalized_str = target_str.replace("\\", "/")

        # 3. Reject Windows drive letters (e.g. C:, D:) or Alternate Data Streams (file.txt:stream)
        if ":" in normalized_str:
            return PathValidationResult(
                is_safe=False,
                error_reason="Drive letters and Alternate Data Streams are prohibited.",
                policy_id="WDN-002",
            )

        # 4. Reject absolute paths that don't originate in our workspace concept
        if normalized_str.startswith("/"):
            return PathValidationResult(
                is_safe=False,
                error_reason="Absolute paths are prohibited; paths must be relative to workspace.",
                policy_id="WDN-002",
            )

        # Root reference handling ("." or "./")
        if normalized_str.strip() in {".", "./"}:
            if not allow_root:
                return PathValidationResult(
                    is_safe=False,
                    error_reason="Direct operations on the workspace root itself are prohibited.",
                    policy_id="WDN-002",
                )
            if must_exist and not self.workspace_root.exists():
                return PathValidationResult(
                    is_safe=False,
                    error_reason="Target resource does not exist.",
                    policy_id="WDN-005",
                )
            return PathValidationResult(
                is_safe=True,
                canonical_path=self.workspace_root,
                relative_path=".",
            )

        # 5. Check lexical directory traversal components
        parts = normalized_str.split("/")
        for part in parts:
            if not part:
                continue
            clean_part = part.strip()
            if clean_part in {"..", "."}:
                return PathValidationResult(
                    is_safe=False,
                    error_reason="Parent directory traversal ('..') is prohibited.",
                    policy_id="WDN-002",
                )
            if part.endswith(".") or part.endswith(" "):
                return PathValidationResult(
                    is_safe=False,
                    error_reason="Path components ending with dot or space are prohibited.",
                    policy_id="WDN-002",
                )
            # Check reserved device names on Windows
            base_name = clean_part.split(".")[0].upper()
            if base_name in WINDOWS_RESERVED_NAMES:
                return PathValidationResult(
                    is_safe=False,
                    error_reason=f"Path component '{part}' is a reserved device name.",
                    policy_id="WDN-002",
                )

        # 6. Resolve canonical path against the workspace root
        try:
            target_path = (self.workspace_root / normalized_str).resolve()
        except (ValueError, RuntimeError) as e:
            return PathValidationResult(
                is_safe=False,
                error_reason=f"Failed to resolve path: {e}",
                policy_id="WDN-002",
            )

        # 7. Verify containment within workspace root
        try:
            rel = target_path.relative_to(self.workspace_root)
        except ValueError:
            return PathValidationResult(
                is_safe=False,
                error_reason="Path resolves outside the designated workspace boundary.",
                policy_id="WDN-002",
            )

        # Disallow targeting workspace root itself unless explicitly permitted
        if not allow_root and target_path == self.workspace_root:
            return PathValidationResult(
                is_safe=False,
                error_reason="Direct operations on the workspace root itself are prohibited.",
                policy_id="WDN-002",
            )

        # 8. Existence check if required
        if must_exist and not target_path.exists():
            return PathValidationResult(
                is_safe=False,
                error_reason="Target resource does not exist.",
                policy_id="WDN-005",
            )

        # 9. Verify symlink target does not point outside workspace
        # If the target exists or parent exists, inspect path components for symlink escapes
        curr = target_path
        while curr != self.workspace_root and curr != curr.parent:
            if curr.is_symlink():
                try:
                    resolved_symlink = curr.resolve()
                    resolved_symlink.relative_to(self.workspace_root)
                except ValueError:
                    return PathValidationResult(
                        is_safe=False,
                        error_reason="Symbolic link traverses outside the workspace boundary.",
                        policy_id="WDN-002",
                    )
            curr = curr.parent

        return PathValidationResult(
            is_safe=True,
            canonical_path=target_path,
            relative_path=str(rel).replace("\\", "/"),
        )
