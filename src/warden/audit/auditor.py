"""Independent filesystem outcome verification for WARDEN."""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any, Dict, Optional
from warden.execution.workspace import Workspace
from warden.models import (
    Action,
    ActionType,
    ExecutionResult,
    ExecutionStatus,
    VerificationResult,
)
from warden.security.path_validation import PathValidator


def _compute_sha256(path: Path) -> Optional[str]:
    if not path.exists() or not path.is_file():
        return None
    try:
        hasher = hashlib.sha256()
        with open(path, "rb") as f:
            while chunk := f.read(65536):
                hasher.update(chunk)
        return hasher.hexdigest()
    except OSError:
        return None


class OutcomeAuditor:
    """Independently verifies actual filesystem state before and after action execution.
    
    Guarantees:
    - Never collapses execution status into a naive boolean flag.
    - An operation reported as executed that failed to produce the expected state is marked FAILED.
    - Prevents false claims of successful execution by checking disk state independently.
    """

    def __init__(
        self,
        workspace: Workspace,
        path_validator: Optional[PathValidator] = None,
    ) -> None:
        self.workspace = workspace
        self.path_validator = path_validator or PathValidator(self.workspace.root_path)

    def capture_pre_state(self, action: Action) -> Dict[str, Any]:
        """Capture filesystem snapshot prior to an operation."""
        state: Dict[str, Any] = {
            "target": action.target,
            "target_exists": False,
            "target_is_file": False,
            "target_size": 0,
            "target_sha256": None,
        }

        allow_root = (action.operation.upper() == ActionType.READ.value)
        target_val = self.path_validator.validate_path(action.target, allow_root=allow_root)
        if target_val.is_safe and target_val.canonical_path:
            p = target_val.canonical_path
            if p.exists():
                state["target_exists"] = True
                state["target_is_file"] = p.is_file()
                state["target_is_dir"] = p.is_dir()
                if p.is_file():
                    state["target_size"] = p.stat().st_size
                    state["target_sha256"] = _compute_sha256(p)

        if action.operation.upper() == ActionType.RENAME.value and action.destination:
            dest_val = self.path_validator.validate_path(action.destination)
            if dest_val.is_safe and dest_val.canonical_path:
                dp = dest_val.canonical_path
                state["destination"] = action.destination
                state["destination_exists"] = dp.exists()

        return state

    def verify_outcome(
        self,
        action: Action,
        exec_result: ExecutionResult,
        pre_state: Optional[Dict[str, Any]] = None,
    ) -> VerificationResult:
        """Independently check disk state against the expected post-condition of the operation."""
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

        allow_root = (op == ActionType.READ.value)
        target_val = self.path_validator.validate_path(action.target, allow_root=allow_root)
        if not target_val.is_safe or not target_val.canonical_path:
            return VerificationResult(
                action=action,
                status=ExecutionStatus.FAILED,
                verified=False,
                details=f"Target path invalid during verification: {target_val.error_reason}",
            )
        target_path = target_val.canonical_path

        observed: Dict[str, Any] = {
            "target_exists": target_path.exists(),
        }

        # Verification logic per operation
        if op == ActionType.READ.value:
            if not target_path.exists():
                return VerificationResult(
                    action=action,
                    status=ExecutionStatus.FAILED,
                    verified=False,
                    observed_state=observed,
                    details="Verified failure: read target does not exist.",
                )
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

        elif op in {ActionType.CREATE.value, ActionType.WRITE.value}:
            if not target_path.exists():
                return VerificationResult(
                    action=action,
                    status=ExecutionStatus.FAILED,
                    verified=False,
                    observed_state=observed,
                    details=f"Verified failure: target file '{action.target}' was not found after {op}.",
                )
            if not target_path.is_file():
                return VerificationResult(
                    action=action,
                    status=ExecutionStatus.FAILED,
                    verified=False,
                    observed_state=observed,
                    details=f"Verified failure: target '{action.target}' is not a regular file.",
                )
            actual_content = target_path.read_text(encoding="utf-8", errors="replace")
            expected_content = action.content if action.content is not None else ""
            observed["content_matched"] = (actual_content == expected_content)
            observed["sha256"] = _compute_sha256(target_path)

            if actual_content != expected_content:
                return VerificationResult(
                    action=action,
                    status=ExecutionStatus.FAILED,
                    verified=False,
                    observed_state=observed,
                    details="Verified failure: file content on disk does not match requested content.",
                )

            return VerificationResult(
                action=action,
                status=ExecutionStatus.VERIFIED,
                verified=True,
                observed_state=observed,
                details=f"Outcome independently verified: '{action.target}' exists with exact expected content.",
            )

        elif op == ActionType.DELETE.value:
            if target_path.exists():
                return VerificationResult(
                    action=action,
                    status=ExecutionStatus.FAILED,
                    verified=False,
                    observed_state=observed,
                    details=f"Verified failure: target '{action.target}' still exists on disk after DELETE.",
                )
            return VerificationResult(
                action=action,
                status=ExecutionStatus.VERIFIED,
                verified=True,
                observed_state=observed,
                details=f"Outcome independently verified: target '{action.target}' is confirmed deleted.",
            )

        elif op == ActionType.RENAME.value:
            if target_path.exists():
                return VerificationResult(
                    action=action,
                    status=ExecutionStatus.FAILED,
                    verified=False,
                    observed_state=observed,
                    details=f"Verified failure: original source file '{action.target}' still exists after RENAME.",
                )
            assert action.destination is not None
            dest_val = self.path_validator.validate_path(action.destination)
            if not dest_val.is_safe or not dest_val.canonical_path:
                return VerificationResult(
                    action=action,
                    status=ExecutionStatus.FAILED,
                    verified=False,
                    details=f"Destination path invalid: {dest_val.error_reason}",
                )
            dest_path = dest_val.canonical_path
            observed["destination_exists"] = dest_path.exists()
            if not dest_path.exists():
                return VerificationResult(
                    action=action,
                    status=ExecutionStatus.FAILED,
                    verified=False,
                    observed_state=observed,
                    details=f"Verified failure: destination file '{action.destination}' does not exist after RENAME.",
                )

            return VerificationResult(
                action=action,
                status=ExecutionStatus.VERIFIED,
                verified=True,
                observed_state=observed,
                details=f"Outcome independently verified: '{action.target}' moved to '{action.destination}'.",
            )

        return VerificationResult(
            action=action,
            status=ExecutionStatus.FAILED,
            verified=False,
            details=f"Unsupported operation for verification: {op}",
        )
