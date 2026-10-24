"""Builds the AuditRequest WARDEN sends to a remote Auditor.

The request carries WARDEN's expectations and its own pre-execution observations. It
never includes the Executor's success claim, output, file content, or absolute paths.
"""

from __future__ import annotations

import secrets
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from warden.audit.attestation import AuditRequest
from warden.models import Action
from warden.security.digest import (
    canonical_path_str,
    compute_action_digest,
    sha256_text,
    workspace_id,
)
from warden.security.path_validation import PathValidator


class AuditRequestError(ValueError):
    """The request cannot be built from the available evidence; the caller must not claim VERIFIED."""


def _relative_dir_key(directory_key: str, root_key: str) -> str:
    if directory_key == root_key:
        return ""
    for sep in ("\\", "/"):
        prefix = root_key + sep
        if directory_key.startswith(prefix):
            return directory_key[len(prefix):].replace("\\", "/")
    raise AuditRequestError("Snapshot directory lies outside the workspace.")


def build_audit_request(
    action: Action,
    pre_state: Optional[Dict[str, Any]],
    workspace_root: Path,
    path_validator: PathValidator,
    ttl_seconds: int,
    now: Optional[datetime] = None,
) -> AuditRequest:
    if not pre_state or not pre_state.get("target_state") or not pre_state.get("snapshots"):
        raise AuditRequestError("Pre-execution state evidence is missing.")

    op = action.operation.upper()
    target_val = path_validator.validate_path(action.target, allow_root=(op == "READ"))
    if not target_val.is_safe or not target_val.canonical_path:
        raise AuditRequestError("Target path is not valid.")
    dest_path: Optional[Path] = None
    dest_rel: Optional[str] = None
    if action.destination:
        dest_val = path_validator.validate_path(action.destination)
        if not dest_val.is_safe or not dest_val.canonical_path:
            raise AuditRequestError("Destination path is not valid.")
        dest_path, dest_rel = dest_val.canonical_path, dest_val.relative_path or action.destination

    root_key = canonical_path_str(workspace_root)
    snapshots: Dict[str, Dict[str, List[Any]]] = {}
    for directory_key, snap in pre_state["snapshots"].items():
        if snap is None:
            raise AuditRequestError("A directory could not be snapshotted before execution.")
        snapshots[_relative_dir_key(directory_key, root_key)] = snap

    now = now or datetime.now(timezone.utc)
    return AuditRequest(
        request_id=str(uuid.uuid4()),
        nonce=secrets.token_hex(16),
        action_digest=compute_action_digest(op, target_val.canonical_path, dest_path, action.content, workspace_root),
        operation=op,
        target=target_val.relative_path or action.target,
        destination=dest_rel,
        expected_content_sha256=sha256_text(action.content),
        workspace_id=workspace_id(workspace_root),
        pre_state={"target": pre_state["target_state"], "destination": pre_state.get("destination_state")},
        pre_snapshots=snapshots,
        issued_at=now.isoformat(),
        expires_at=(now + timedelta(seconds=ttl_seconds)).isoformat(),
    )
