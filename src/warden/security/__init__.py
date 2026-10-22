"""Security subsystem for WARDEN: policy, path validation, and authorization."""

from warden.security.path_validation import PathValidator, PathValidationResult, DEFAULT_PROTECTED_FILES
from warden.security.policy import PolicyEngine, evaluate_action, PROTECTED_FILES
from warden.security.authorization import AuthorizationManager, AuthorizationError

__all__ = [
    "PathValidator",
    "PathValidationResult",
    "DEFAULT_PROTECTED_FILES",
    "PolicyEngine",
    "evaluate_action",
    "PROTECTED_FILES",
    "AuthorizationManager",
    "AuthorizationError",
]
