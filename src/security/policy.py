from dataclasses import dataclass
from enum import Enum


class Decision(str, Enum):
    ALLOW = "ALLOW"
    BLOCK = "BLOCK"
    REQUIRE_APPROVAL = "REQUIRE_APPROVAL"


@dataclass(frozen=True)
class Action:
    operation: str
    target: str
    reason: str = ""


@dataclass(frozen=True)
class PolicyResult:
    decision: Decision
    policy_id: str
    reason: str


PROTECTED_FILES = {
    ".env",
    "production.env",
    "secrets.json",
    "credentials.json",
}


def evaluate_action(action: Action) -> PolicyResult:
    operation = action.operation.upper()
    target = action.target.replace("\\", "/")
    filename = target.rsplit("/", 1)[-1].lower()

    # Only explicitly supported operations are accepted.
    if operation not in {"READ", "CREATE", "WRITE", "DELETE", "RENAME"}:
        return PolicyResult(
            Decision.BLOCK,
            "WDN-001",
            "Unsupported operation."
        )

    # Reject paths that could escape the controlled workspace.
    if (
        target.startswith("/")
        or ".." in target.split("/")
        or ":" in target
    ):
        return PolicyResult(
            Decision.BLOCK,
            "WDN-002",
            "Path is outside the permitted workspace."
        )

    # Sensitive files cannot be modified or deleted.
    if filename in PROTECTED_FILES:
        if operation in {"WRITE", "DELETE", "RENAME"}:
            return PolicyResult(
                Decision.BLOCK,
                "WDN-003",
                "Protected resource modification is prohibited."
            )

    # Destructive operations need explicit approval.
    if operation in {"DELETE", "RENAME"}:
        return PolicyResult(
            Decision.REQUIRE_APPROVAL,
            "WDN-004",
            "Destructive operation requires approval."
        )

    return PolicyResult(
        Decision.ALLOW,
        "WDN-000",
        "Action satisfies the current baseline policy."
    )