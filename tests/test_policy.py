from src.security.policy import (
    Action,
    Decision,
    evaluate_action,
)


def test_safe_read_is_allowed():
    result = evaluate_action(
        Action("READ", "README.md")
    )
    assert result.decision == Decision.ALLOW


def test_protected_file_cannot_be_deleted():
    result = evaluate_action(
        Action("DELETE", "production.env")
    )
    assert result.decision == Decision.BLOCK


def test_path_traversal_is_blocked():
    result = evaluate_action(
        Action("READ", "../../outside.txt")
    )
    assert result.decision == Decision.BLOCK


def test_unknown_operation_is_blocked():
    result = evaluate_action(
        Action("EXECUTE_SHELL", "anything")
    )
    assert result.decision == Decision.BLOCK


def test_destructive_operation_requires_approval():
    result = evaluate_action(
        Action("DELETE", "temporary.log")
    )
    assert result.decision == Decision.REQUIRE_APPROVAL