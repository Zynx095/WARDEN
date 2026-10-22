"""Deterministic security policy engine for WARDEN."""

from __future__ import annotations

from pathlib import Path
from typing import Optional, Set
from warden.config import get_config
from warden.models import (
    Action,
    ActionType,
    Decision,
    PolicyResult,
)
from warden.security.path_validation import PathValidator, DEFAULT_PROTECTED_FILES

# Default protected configuration and credential files
PROTECTED_FILES: Set[str] = DEFAULT_PROTECTED_FILES


class PolicyEngine:
    """Evaluates requested actions against deterministic security rules.
    
    Decisions are independent of LLM reasoning or prompt claims.
    """

    def __init__(
        self,
        workspace_root: Optional[Path | str] = None,
        protected_files: Optional[Set[str]] = None,
    ) -> None:
        self.workspace_root = Path(workspace_root).resolve() if workspace_root else get_config().workspace_root
        self.protected_files = {f.lower() for f in (protected_files or PROTECTED_FILES)}
        self.path_validator = PathValidator(self.workspace_root, self.protected_files)

    def evaluate(self, action: Action) -> PolicyResult:
        """Evaluate an action deterministically."""
        operation = action.operation.upper()
        target = (action.target or "").replace("\\", "/")

        context = {
            "action_id": action.action_id,
            "operation": operation,
            "target": target,
            "destination": action.destination,
        }

        # 1. Supported operations check
        if operation not in {op.value for op in ActionType}:
            return PolicyResult(
                decision=Decision.BLOCK,
                policy_id="WDN-001",
                reason="Unsupported operation.",
                context=context,
            )

        # 2. Check for empty or non-string target
        if not target.strip():
            return PolicyResult(
                decision=Decision.BLOCK,
                policy_id="WDN-002",
                reason="Target resource path cannot be empty.",
                context=context,
            )

        # 3. Path safety validation on target
        target_val = self.path_validator.validate_path(target)
        if not target_val.is_safe:
            return PolicyResult(
                decision=Decision.BLOCK,
                policy_id=target_val.policy_id or "WDN-002",
                reason=target_val.error_reason or "Path is outside the permitted workspace.",
                context=context,
            )

        # Extract filename for protected file checks
        target_filename = target.rsplit("/", 1)[-1].lower().strip()

        # 4. Check destination for RENAME operations
        if operation == "RENAME":
            if not action.destination or not action.destination.strip():
                return PolicyResult(
                    decision=Decision.BLOCK,
                    policy_id="WDN-001",
                    reason="Rename operation requires an explicit destination path.",
                    context=context,
                )
            dest_val = self.path_validator.validate_path(action.destination)
            if not dest_val.is_safe:
                return PolicyResult(
                    decision=Decision.BLOCK,
                    policy_id=dest_val.policy_id or "WDN-002",
                    reason=f"Rename destination error: {dest_val.error_reason}",
                    context=context,
                )
            dest_filename = action.destination.replace("\\", "/").rsplit("/", 1)[-1].lower().strip()
            if dest_filename in self.protected_files:
                return PolicyResult(
                    decision=Decision.BLOCK,
                    policy_id="WDN-003",
                    reason="Protected resource modification is prohibited.",
                    context=context,
                )

        # 5. Sensitive files cannot be modified, created, or deleted
        if target_filename in self.protected_files:
            if operation in {"CREATE", "WRITE", "DELETE", "RENAME"}:
                return PolicyResult(
                    decision=Decision.BLOCK,
                    policy_id="WDN-003",
                    reason="Protected resource modification is prohibited.",
                    context=context,
                )

        # 6. Destructive operations require explicit approval
        if operation in {"DELETE", "RENAME"}:
            return PolicyResult(
                decision=Decision.REQUIRE_APPROVAL,
                policy_id="WDN-004",
                reason="Destructive operation requires approval.",
                context=context,
            )

        # 7. Baseline allow
        return PolicyResult(
            decision=Decision.ALLOW,
            policy_id="WDN-000",
            reason="Action satisfies the current baseline policy.",
            context=context,
        )


_DEFAULT_POLICY_ENGINE: PolicyEngine | None = None


def get_policy_engine() -> PolicyEngine:
    global _DEFAULT_POLICY_ENGINE
    if _DEFAULT_POLICY_ENGINE is None:
        _DEFAULT_POLICY_ENGINE = PolicyEngine()
    return _DEFAULT_POLICY_ENGINE


def evaluate_action(action: Action) -> PolicyResult:
    """Convenience function preserving full backward compatibility."""
    return get_policy_engine().evaluate(action)
