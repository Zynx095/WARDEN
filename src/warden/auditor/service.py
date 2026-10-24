"""Independent, read-only verification service behind the Auditor uAgent.

It speaks the core contract in ``warden.audit.attestation`` and uses the core digest helpers;
it defines no schema or digest of its own. It never imports the policy engine, authorization
manager, executor or WardenAgent, holds no WARDEN signing key or token, and has no mutating
filesystem calls.

Verdict rules: evidence problems (bad digest, wrong workspace, expired or malformed request,
missing snapshots) are UNVERIFIED; an observed state that contradicts the expected
post-condition, or any change outside the authorized paths, is FAILED; VERIFIED requires the
exact expected outcome and no collateral change.
"""

from __future__ import annotations

import logging
import os
from collections import OrderedDict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Optional, Set, Tuple

from warden.audit.attestation import (
    REQUEST_SCHEMA,
    AuditAttestation,
    AuditRequest,
    Verdict,
    signing_digest,
)
from warden.auditor.workspace_view import ReadOnlyWorkspaceView
from warden.security.digest import (
    canonical_path_str,
    compute_action_digest_from_hash,
    describe_path_state,
    workspace_id,
)

logger = logging.getLogger("warden.auditor.service")

MUTATING = {"CREATE", "WRITE", "DELETE", "RENAME"}


def _snapshot(directory: Path) -> Optional[Dict[str, List[Any]]]:
    snap: Dict[str, List[Any]] = {}
    try:
        with os.scandir(directory) as entries:
            for entry in entries:
                st = entry.stat(follow_symlinks=False)
                snap[entry.name.lower()] = [entry.is_dir(follow_symlinks=False), st.st_size, st.st_mtime_ns]
    except FileNotFoundError:
        return {}
    except OSError:
        return None
    return snap


class AuditorService:
    """Turns a validated AuditRequest into a signed AuditAttestation."""

    def __init__(
        self,
        workspace_root: Path | str,
        identity: Any,
        allowed_requesters: Iterable[str],
        clock: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
        max_cached: int = 1000,
    ) -> None:
        self.view = ReadOnlyWorkspaceView(workspace_root)
        self.identity = identity
        self.allowed_requesters: Set[str] = {a.strip() for a in allowed_requesters if a and a.strip()}
        if not self.allowed_requesters:
            raise ValueError("At least one allowed requester address is required.")
        self.clock = clock
        self.max_cached = max_cached
        # (sender, request_id) -> (nonce, attestation json): idempotent redelivery, conflicting reuse refused
        self._cache: "OrderedDict[Tuple[str, str], Tuple[str, str]]" = OrderedDict()

    @property
    def address(self) -> str:
        return self.identity.address

    def handle(self, payload: str, sender: str) -> Optional[str]:
        """Return a signed attestation as JSON, or None to stay silent (unauthorized or unparseable)."""
        if sender not in self.allowed_requesters:
            logger.warning("Ignoring audit request from a sender that is not an allowed requester")
            return None
        try:
            request = AuditRequest.model_validate_json(payload)
        except Exception:
            logger.warning("Ignoring malformed audit request")
            return None

        key = (sender, request.request_id)
        cached = self._cache.get(key)
        if cached is not None:
            if cached[0] == request.nonce:
                return cached[1]
            return self._sign(request, "UNVERIFIED", "request_id was reused with a different nonce.", {}, {}, []).model_dump_json()

        verdict, details, post_state, post_snapshots, unexpected = self._evaluate(request)
        attestation_json = self._sign(request, verdict, details, post_state, post_snapshots, unexpected).model_dump_json()
        if len(self._cache) >= self.max_cached:
            self._cache.popitem(last=False)
        self._cache[key] = (request.nonce, attestation_json)
        return attestation_json

    def _sign(
        self,
        request: AuditRequest,
        verdict: Verdict,
        details: str,
        post_state: Dict[str, Any],
        post_snapshots: Dict[str, Dict[str, List[Any]]],
        unexpected: List[str],
    ) -> AuditAttestation:
        unsigned = AuditAttestation(
            request_id=request.request_id,
            nonce=request.nonce,
            action_digest=request.action_digest,
            workspace_id=request.workspace_id,
            auditor_address=self.address,
            verdict=verdict,
            post_state=post_state,
            post_snapshots=post_snapshots,
            unexpected_changes=unexpected,
            details=details,
            observed_at=self.clock().isoformat(),
        )
        return unsigned.model_copy(update={"signature": self.identity.sign_digest(signing_digest(unsigned))})

    def _evaluate(self, req: AuditRequest):
        def unverified(why: str):
            return "UNVERIFIED", why, {}, {}, []

        if req.schema_version != REQUEST_SCHEMA:
            return unverified("Unsupported request schema version.")
        try:
            expires = datetime.fromisoformat(req.expires_at)
        except ValueError:
            return unverified("Request expiry is malformed.")
        if expires.tzinfo is None:
            expires = expires.replace(tzinfo=timezone.utc)
        if self.clock() > expires:
            return unverified("Request expired.")
        if req.workspace_id != workspace_id(self.view.root_path):
            return unverified("Request is for a different workspace.")

        op = req.operation.upper()
        if op not in MUTATING:
            return unverified(f"Unsupported operation '{op}'.")
        target = self.view.get_canonical_path(req.target)
        dest = self.view.get_canonical_path(req.destination) if req.destination else None
        if target is None or (req.destination and dest is None) or (op == "RENAME" and dest is None):
            return unverified("Target or destination is invalid or outside the workspace.")

        expected_sha = req.expected_content_sha256 or ""
        recomputed = compute_action_digest_from_hash(op, target, dest, expected_sha, self.view.root_path)
        if recomputed != req.action_digest:
            return unverified("Action digest does not match the request fields.")

        pre_target = (req.pre_state or {}).get("target")
        if not isinstance(pre_target, dict) or "exists" not in pre_target:
            return unverified("Request lacks pre-execution target state.")
        touched = [target] + ([dest] if dest is not None else [])
        needed_dirs = {self._dir_key(p) for p in touched}
        if not needed_dirs.issubset(set(req.pre_snapshots)):
            return unverified("Request lacks pre-execution directory snapshots for the touched paths.")

        post_target = describe_path_state(target)
        post_dest = describe_path_state(dest) if dest is not None else None
        post_state = {"target": post_target, "destination": post_dest}

        outcome = self._check_operation(op, req, pre_target, post_target, post_dest, expected_sha)
        post_snapshots: Dict[str, Dict[str, List[Any]]] = {}
        unexpected: List[str] = []
        allowed = {(self._dir_key(p), p.name.lower()) for p in touched}
        for dir_key, pre_snap in req.pre_snapshots.items():
            directory = self.view.get_canonical_path(dir_key, allow_root=True) if dir_key else self.view.root_path
            post_snap = _snapshot(directory) if directory is not None else None
            if post_snap is None:
                return "UNVERIFIED", "A directory could not be inspected.", post_state, post_snapshots, []
            post_snapshots[dir_key] = post_snap
            for name in sorted(set(pre_snap) | set(post_snap)):
                if (dir_key, name) in allowed:
                    continue
                if name not in post_snap:
                    unexpected.append(f"{name} removed")
                elif name not in pre_snap:
                    unexpected.append(f"{name} added")
                elif pre_snap[name] != post_snap[name]:
                    unexpected.append(f"{name} modified")

        if outcome is not None:
            return "FAILED", outcome, post_state, post_snapshots, unexpected
        if unexpected:
            details = "Unexpected changes outside the authorized paths: " + "; ".join(unexpected)
            return "FAILED", details, post_state, post_snapshots, unexpected
        return "VERIFIED", f"{op} outcome matches the expected post-condition with no collateral change.", \
            post_state, post_snapshots, []

    def _dir_key(self, path: Path) -> str:
        """Workspace-relative, lower-case directory of ``path`` ('' for the workspace root)."""
        root = canonical_path_str(self.view.root_path)
        parent = canonical_path_str(path.parent)
        if parent == root:
            return ""
        return parent[len(root) + 1:].replace("\\", "/")

    @staticmethod
    def _check_operation(
        op: str,
        req: AuditRequest,
        pre_target: Dict[str, Any],
        post_target: Dict[str, Any],
        post_dest: Optional[Dict[str, Any]],
        expected_sha: str,
    ) -> Optional[str]:
        """None when the observed state matches the expected post-condition, else the reason it does not."""
        if op == "DELETE":
            if not pre_target.get("exists"):
                return "Target did not exist before DELETE; nothing was removed."
            if post_target["exists"]:
                return "Target still exists after DELETE."
        elif op in {"CREATE", "WRITE"}:
            if op == "CREATE" and pre_target.get("exists"):
                return "Target already existed before CREATE."
            if post_target["kind"] != "file":
                return "Target is not a regular file after the operation."
            if post_target["sha256"] != expected_sha:
                return "File content does not match the expected content."
        else:  # RENAME
            if not pre_target.get("exists"):
                return "Source did not exist before RENAME."
            if post_target["exists"]:
                return "Source still exists after RENAME."
            if not post_dest or not post_dest["exists"]:
                return "Destination does not exist after RENAME."
            if pre_target.get("kind") == "file" and (
                post_dest["kind"] != "file" or post_dest["sha256"] != pre_target.get("sha256")
            ):
                return "Destination content differs from the original source."
        return None
