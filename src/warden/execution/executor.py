"""Restricted filesystem executor enforcing mandatory authorization and containment."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Optional
from warden.models import (
    Action,
    ActionType,
    ExecutionRequest,
    ExecutionResult,
    ExecutionStatus,
)
from warden.execution.workspace import Workspace
from warden.security.authorization import AuthorizationManager
from warden.security.digest import capture_target_state, compute_state_digest
from warden.security.path_validation import PathValidator, DEFAULT_PROTECTED_FILES


class RestrictedExecutor:
    """Safely executes authorized filesystem operations inside a controlled workspace.
    
    Invariants:
    1. Rejects any operation without an unforgeable, unexpired, matching authorization token.
    2. Rejects operations on protected resources regardless of authorization claims.
    3. Rejects paths escaping the workspace boundary.
    4. Never reports success when an operation fails.
    """

    def __init__(
        self,
        workspace: Workspace,
        auth_manager: Optional[AuthorizationManager] = None,
        path_validator: Optional[PathValidator] = None,
    ) -> None:
        self.workspace = workspace
        self.auth_manager = auth_manager or AuthorizationManager()
        self.path_validator = path_validator or PathValidator(self.workspace.root_path)

    def execute(self, request: ExecutionRequest) -> ExecutionResult:
        """Execute a requested operation subject to strict authorization and boundary checks."""
        action = request.action
        op = action.operation.upper()

        # 1. Operation type verification
        if op not in {o.value for o in ActionType}:
            return ExecutionResult(
                action=action,
                status=ExecutionStatus.FAILED,
                success=False,
                error=f"Unsupported operation: {action.operation}",
            )

        # 2. Target path validation
        allow_root = (op == ActionType.READ.value)
        target_val = self.path_validator.validate_path(action.target, allow_root=allow_root)
        if not target_val.is_safe or not target_val.canonical_path:
            return ExecutionResult(
                action=action,
                status=ExecutionStatus.FAILED,
                success=False,
                error=f"Target path validation failed: {target_val.error_reason}",
            )
        target_path = target_val.canonical_path

        # 3. Destination path validation for RENAME
        destination_path: Optional[Path] = None
        if op == ActionType.RENAME.value:
            if not action.destination:
                return ExecutionResult(
                    action=action,
                    status=ExecutionStatus.FAILED,
                    success=False,
                    error="Rename operation requires destination path.",
                )
            dest_val = self.path_validator.validate_path(action.destination)
            if not dest_val.is_safe or not dest_val.canonical_path:
                return ExecutionResult(
                    action=action,
                    status=ExecutionStatus.FAILED,
                    success=False,
                    error=f"Destination path validation failed: {dest_val.error_reason}",
                )
            destination_path = dest_val.canonical_path

            # Protected resource check on destination
            if self.path_validator.is_protected_filename(destination_path.name):
                return ExecutionResult(
                    action=action,
                    status=ExecutionStatus.FAILED,
                    success=False,
                    error=f"Cannot overwrite protected resource '{destination_path.name}'.",
                )

        # 4. Protected resource check on target
        if op in {"CREATE", "WRITE", "DELETE", "RENAME"}:
            if self.path_validator.is_protected_filename(target_path.name):
                return ExecutionResult(
                    action=action,
                    status=ExecutionStatus.FAILED,
                    success=False,
                    error=f"Operation on protected resource '{target_path.name}' is prohibited.",
                )

        # 5. Mandatory independent authorization verification
        is_authorized, auth_err = self.auth_manager.verify_token(
            token=request.authorization,
            action=action,
            target_canonical=target_path,
            destination_canonical=destination_path,
            workspace_root=self.workspace.root_path,
            current_state_digest=compute_state_digest(capture_target_state(target_path, destination_path)),
        )
        if not is_authorized:
            return ExecutionResult(
                action=action,
                status=ExecutionStatus.FAILED,
                success=False,
                error=f"Authorization rejected: {auth_err}",
            )

        # 6. Controlled execution with fail-closed error handling
        try:
            if op == ActionType.READ.value:
                if not target_path.exists():
                    return ExecutionResult(
                        action=action,
                        status=ExecutionStatus.FAILED,
                        success=False,
                        error=f"File not found: {action.target}",
                    )
                if target_path.is_dir():
                    try:
                        filenames = sorted([
                            f.name for f in target_path.iterdir()
                            if not f.name.startswith(".git")
                        ])
                        output = "\n".join(filenames) if filenames else "(empty directory)"
                        return ExecutionResult(
                            action=action,
                            status=ExecutionStatus.EXECUTED,
                            success=True,
                            output=output,
                        )
                    except OSError as exc:
                        return ExecutionResult(
                            action=action,
                            status=ExecutionStatus.FAILED,
                            success=False,
                            error=f"Directory read error: {exc}",
                        )
                if not target_path.is_file():
                    return ExecutionResult(
                        action=action,
                        status=ExecutionStatus.FAILED,
                        success=False,
                        error=f"Target is not a regular file: {action.target}",
                    )
                content = target_path.read_text(encoding="utf-8", errors="replace")
                return ExecutionResult(
                    action=action,
                    status=ExecutionStatus.EXECUTED,
                    success=True,
                    output=content,
                )

            elif op == ActionType.CREATE.value:
                if target_path.exists():
                    return ExecutionResult(
                        action=action,
                        status=ExecutionStatus.FAILED,
                        success=False,
                        error=f"File already exists: {action.target}",
                    )
                target_path.parent.mkdir(parents=True, exist_ok=True)
                content = action.content if action.content is not None else ""
                target_path.write_bytes(content.encode("utf-8"))
                return ExecutionResult(
                    action=action,
                    status=ExecutionStatus.EXECUTED,
                    success=True,
                    output=f"Created file: {action.target}",
                )

            elif op == ActionType.WRITE.value:
                target_path.parent.mkdir(parents=True, exist_ok=True)
                content = action.content if action.content is not None else ""
                target_path.write_bytes(content.encode("utf-8"))
                return ExecutionResult(
                    action=action,
                    status=ExecutionStatus.EXECUTED,
                    success=True,
                    output=f"Wrote {len(content)} characters to: {action.target}",
                )

            elif op == ActionType.DELETE.value:
                if not target_path.exists():
                    return ExecutionResult(
                        action=action,
                        status=ExecutionStatus.FAILED,
                        success=False,
                        error=f"Target does not exist for deletion: {action.target}",
                    )
                if target_path.is_dir():
                    target_path.rmdir()
                else:
                    target_path.unlink()
                return ExecutionResult(
                    action=action,
                    status=ExecutionStatus.EXECUTED,
                    success=True,
                    output=f"Deleted: {action.target}",
                )

            elif op == ActionType.RENAME.value:
                if not target_path.exists():
                    return ExecutionResult(
                        action=action,
                        status=ExecutionStatus.FAILED,
                        success=False,
                        error=f"Source file does not exist: {action.target}",
                    )
                assert destination_path is not None
                destination_path.parent.mkdir(parents=True, exist_ok=True)
                target_path.rename(destination_path)
                return ExecutionResult(
                    action=action,
                    status=ExecutionStatus.EXECUTED,
                    success=True,
                    output=f"Renamed {action.target} to {action.destination}",
                )

            else:
                return ExecutionResult(
                    action=action,
                    status=ExecutionStatus.FAILED,
                    success=False,
                    error=f"Unhandled operation: {op}",
                )

        except (OSError, IOError, PermissionError, UnicodeError) as exc:
            return ExecutionResult(
                action=action,
                status=ExecutionStatus.FAILED,
                success=False,
                error=f"Filesystem error during execution: {exc}",
            )
