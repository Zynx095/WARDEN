"""Independent filesystem outcome verification for WARDEN."""

from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple
from warden.execution.workspace import Workspace
from warden.models import (
    Action,
    ActionType,
    ExecutionResult,
    ExecutionStatus,
    VerificationResult,
)
from warden.security.digest import canonical_path_str, describe_path_state, sha256_file, sha256_text
from warden.security.path_validation import PathValidator

MUTATING_OPERATIONS = {
    ActionType.CREATE.value,
    ActionType.WRITE.value,
    ActionType.DELETE.value,
    ActionType.RENAME.value,
}


def _compute_sha256(path: Path) -> Optional[str]:
    if not path.exists() or not path.is_file():
        return None
    return sha256_file(path)


def _snapshot_directory(directory: Path) -> Optional[Dict[str, List[Any]]]:
    """Shallow listing ``name -> [is_dir, size, mtime_ns]``; {} if absent, None if unreadable."""
    snap: Dict[str, List[Any]] = {}
    try:
        with os.scandir(directory) as entries:
            for entry in entries:
                st = entry.stat(follow_symlinks=False)
                entry_key = entry.name.lower() if sys.platform == "win32" else entry.name
                snap[entry_key] = [entry.is_dir(follow_symlinks=False), st.st_size, st.st_mtime_ns]
    except FileNotFoundError:
        return {}
    except OSError:
        return None
    return snap


class OutcomeAuditor:
    """Independently verifies actual filesystem state before and after action execution.

    Guarantees:
    - Never collapses execution status into a naive boolean flag.
    - An operation reported as executed that failed to produce the expected state is marked FAILED.
    - Prevents false claims of successful execution by checking disk state independently.
    - Mutating operations are verified against pre-execution evidence: without it, or when
      anything other than the authorized paths changed, the outcome is FAILED, never VERIFIED.

    Scope: this check runs in the same process and with the same privileges as the executor.
    It is an additional defense, not an isolated security boundary.
    """

    def __init__(
        self,
        workspace: Workspace,
        path_validator: Optional[PathValidator] = None,
    ) -> None:
        self.workspace = workspace
        self.path_validator = path_validator or PathValidator(self.workspace.root_path)

    def _resolve(self, action: Action) -> Tuple[Optional[Path], Optional[Path]]:
        allow_root = (action.operation.upper() == ActionType.READ.value)
        target_val = self.path_validator.validate_path(action.target, allow_root=allow_root)
        target = target_val.canonical_path if target_val.is_safe else None
        dest: Optional[Path] = None
        if action.destination:
            dest_val = self.path_validator.validate_path(action.destination)
            dest = dest_val.canonical_path if dest_val.is_safe else None
        return target, dest

    def _snapshots(self, paths: List[Path]) -> Dict[str, Optional[Dict[str, List[Any]]]]:
        dirs = {canonical_path_str(p.parent): p.parent for p in paths}
        return {key: _snapshot_directory(d) for key, d in dirs.items()}

    def capture_pre_state(self, action: Action) -> Dict[str, Any]:
        """Capture filesystem snapshot prior to an operation."""
        state: Dict[str, Any] = {
            "target": action.target,
            "target_exists": False,
            "target_is_file": False,
            "target_size": 0,
            "target_sha256": None,
            "target_state": describe_path_state(None),
            "destination_state": None,
            "snapshots": {},
        }

        target, dest = self._resolve(action)
        if target is not None:
            state["target_state"] = describe_path_state(target)
            if target.exists():
                state["target_exists"] = True
                state["target_is_file"] = target.is_file()
                state["target_is_dir"] = target.is_dir()
                if target.is_file():
                    state["target_size"] = target.stat().st_size
                    state["target_sha256"] = _compute_sha256(target)
            touched = [target] + ([dest] if dest is not None else [])
            state["snapshots"] = self._snapshots(touched)

        if action.operation.upper() == ActionType.RENAME.value and dest is not None:
            state["destination"] = action.destination
            state["destination_exists"] = dest.exists()
            state["destination_state"] = describe_path_state(dest)

        return state

    def _fail(self, action: Action, details: str, observed: Optional[Dict[str, Any]] = None) -> VerificationResult:
        return VerificationResult(
            action=action,
            status=ExecutionStatus.FAILED,
            verified=False,
            observed_state=observed or {},
            details=details,
        )

    def _collateral_changes(
        self,
        pre: Dict[str, Any],
        touched: List[Path],
    ) -> Optional[List[str]]:
        """Names that changed in the touched directories other than the authorized paths; None if unknowable."""
        pre_snaps = pre.get("snapshots") or {}
        post_snaps = self._snapshots(touched)
        allowed: Set[Tuple[str, str]] = {
            (canonical_path_str(p.parent), p.name.lower() if sys.platform == "win32" else p.name)
            for p in touched
        }
        changes: List[str] = []
        for directory, pre_snap in pre_snaps.items():
            post_snap = post_snaps.get(directory)
            if pre_snap is None or post_snap is None:
                return None
            for name in sorted(set(pre_snap) | set(post_snap)):
                if (directory, name) in allowed:
                    continue
                if name not in post_snap:
                    changes.append(f"{name} removed")
                elif name not in pre_snap:
                    changes.append(f"{name} added")
                elif pre_snap[name] != post_snap[name]:
                    changes.append(f"{name} modified")
        return changes

    def verify_outcome(
        self,
        action: Action,
        exec_result: ExecutionResult,
        pre_state: Optional[Dict[str, Any]] = None,
    ) -> VerificationResult:
        """Independently check disk state against the expected post-condition of the operation.

        Mutating operations require ``pre_state`` from :meth:`capture_pre_state`, taken before
        execution; without it verification fails because the change cannot be established.
        """
        op = action.operation.upper()

        # If execution was not successful, verification confirms that no unauthorized mutation occurred
        if not exec_result.success:
            return VerificationResult(
                action=action,
                status=ExecutionStatus.FAILED,
                verified=False,
                observed_state={"execution_success": False, "execution_error": exec_result.error},
                details=f"Execution failed; no successful modification to verify: {exec_result.error}",
            )

        target_path, dest_path = self._resolve(action)
        if target_path is None:
            return self._fail(action, "Target path invalid during verification.")

        observed: Dict[str, Any] = {
            "target_exists": target_path.exists(),
        }

        if op == ActionType.READ.value:
            if not target_path.exists():
                return self._fail(action, "Verified failure: read target does not exist.", observed)
            is_dir = target_path.is_dir()
            observed["target_is_dir"] = is_dir
            observed["target_is_file"] = target_path.is_file()
            details = (
                "Read verified: target directory exists and was accessible."
                if is_dir
                else "Read verified: target file exists and was accessible."
            )
            return VerificationResult(
                action=action,
                status=ExecutionStatus.VERIFIED,
                verified=True,
                observed_state=observed,
                details=details,
            )

        if op not in MUTATING_OPERATIONS:
            return self._fail(action, f"Unsupported operation for verification: {op}")

        if not pre_state or not pre_state.get("target_state") or not pre_state.get("snapshots"):
            return self._fail(
                action,
                "Missing pre-execution state evidence; the outcome cannot be verified.",
                observed,
            )
        pre_target = pre_state["target_state"]
        post_target = describe_path_state(target_path)
        observed["pre_target_state"] = pre_target
        observed["post_target_state"] = post_target

        touched = [target_path]

        if op == ActionType.DELETE.value:
            if not pre_target.get("exists"):
                return self._fail(
                    action,
                    f"Verified failure: target '{action.target}' did not exist before DELETE, so this action removed nothing.",
                    observed,
                )
            if target_path.exists():
                return self._fail(
                    action, f"Verified failure: target '{action.target}' still exists on disk after DELETE.", observed
                )
            success_details = f"Outcome independently verified: target '{action.target}' is confirmed deleted."

        elif op in {ActionType.CREATE.value, ActionType.WRITE.value}:
            if op == ActionType.CREATE.value and pre_target.get("exists"):
                return self._fail(
                    action, f"Verified failure: target '{action.target}' already existed before CREATE.", observed
                )
            if not target_path.exists():
                return self._fail(
                    action, f"Verified failure: target file '{action.target}' was not found after {op}.", observed
                )
            if not target_path.is_file():
                return self._fail(
                    action, f"Verified failure: target '{action.target}' is not a regular file.", observed
                )
            expected_sha = sha256_text(action.content)
            observed["expected_sha256"] = expected_sha
            observed["sha256"] = post_target.get("sha256")
            observed["content_matched"] = (post_target.get("sha256") == expected_sha)
            if not observed["content_matched"]:
                return self._fail(
                    action, "Verified failure: file content on disk does not match requested content.", observed
                )
            success_details = (
                f"Outcome independently verified: '{action.target}' exists with exact expected content."
            )

        else:  # RENAME
            if dest_path is None:
                return self._fail(action, "Destination path invalid during verification.", observed)
            touched.append(dest_path)
            if not pre_target.get("exists"):
                return self._fail(
                    action, f"Verified failure: source '{action.target}' did not exist before RENAME.", observed
                )
            if target_path.exists():
                return self._fail(
                    action,
                    f"Verified failure: original source file '{action.target}' still exists after RENAME.",
                    observed,
                )
            post_dest = describe_path_state(dest_path)
            observed["destination_exists"] = post_dest["exists"]
            observed["post_destination_state"] = post_dest
            if not post_dest["exists"]:
                return self._fail(
                    action,
                    f"Verified failure: destination file '{action.destination}' does not exist after RENAME.",
                    observed,
                )
            if pre_target.get("kind") == "file" and (
                post_dest.get("kind") != "file" or post_dest.get("sha256") != pre_target.get("sha256")
            ):
                return self._fail(
                    action,
                    f"Verified failure: content at '{action.destination}' differs from the original source.",
                    observed,
                )
            success_details = (
                f"Outcome independently verified: '{action.target}' moved to '{action.destination}'."
            )

        collateral = self._collateral_changes(pre_state, touched)
        if collateral is None:
            return self._fail(action, "Verified failure: could not establish that nothing else changed.", observed)
        observed["unexpected_changes"] = collateral
        if collateral:
            return self._fail(
                action,
                "Verified failure: unexpected changes outside the authorized target: " + "; ".join(collateral),
                observed,
            )

        return VerificationResult(
            action=action,
            status=ExecutionStatus.VERIFIED,
            verified=True,
            observed_state=observed,
            details=success_details,
        )
