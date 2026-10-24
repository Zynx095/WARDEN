"""Cryptographic action digest computation binding action parameters and workspace."""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any, Optional


def _normalize_path_str(path_str: Optional[str]) -> str:
    if not path_str:
        return ""
    # Normalize slashes and strip leading/trailing whitespace and slashes
    clean = path_str.replace("\\", "/").strip().strip("/")
    return clean.lower()


def compute_action_digest(
    action: Any,
    workspace_root: str | Path,
) -> str:
    """Compute a deterministic SHA-256 digest binding action parameters and workspace root.

    Binds:
    - action_id
    - operation (uppercased)
    - target (normalized relative posix path)
    - destination (normalized relative posix path if present)
    - content_sha256 (SHA-256 of payload content if present)
    - workspace_root (canonical resolved path)

    Any tampering with target, operation, destination, content, action_id,
    or workspace root changes the digest and causes the Auditor to reject the request.
    """
    action_id = str(getattr(action, "action_id", "")).strip()
    operation = str(getattr(action, "operation", "")).upper().strip()
    target = _normalize_path_str(getattr(action, "target", ""))
    destination = _normalize_path_str(getattr(action, "destination", None))

    content = getattr(action, "content", None)
    if content is not None:
        content_str = str(content)
        content_sha256 = hashlib.sha256(content_str.encode("utf-8")).hexdigest()
    else:
        content_sha256 = ""

    ws_norm = str(Path(workspace_root).resolve()).replace("\\", "/").lower()

    payload = f"{action_id}:{operation}:{target}:{destination}:{content_sha256}:{ws_norm}"
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()
