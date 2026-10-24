"""Tests for warden.presentation.badges — status vocabulary."""

import pytest

from warden.models import Decision, ExecutionStatus
from warden.presentation.badges import (
    DECISION_BADGES,
    OPERATION_ICONS,
    STATUS_BADGES,
    badge,
    op_icon,
    policy_description,
    risk_from_operation,
)


class TestBadge:
    def test_all_execution_statuses_have_badges(self):
        for s in ExecutionStatus:
            b = badge(s)
            assert b, f"Missing badge for {s}"
            assert len(b) > 0

    def test_verified_badge_contains_checkmark(self):
        assert "✅" in badge(ExecutionStatus.VERIFIED)

    def test_blocked_badge_contains_no_symbol(self):
        assert "🚫" in badge(ExecutionStatus.BLOCKED)

    def test_awaiting_badge_contains_lock(self):
        assert "🔒" in badge(ExecutionStatus.AWAITING_APPROVAL)

    def test_failed_badge_contains_cross(self):
        assert "❌" in badge(ExecutionStatus.FAILED)

    def test_string_input_works(self):
        assert badge("VERIFIED") == badge(ExecutionStatus.VERIFIED)

    def test_rejected_named_state(self):
        b = badge("REJECTED")
        assert "🚫" in b or "REJECTED" in b

    def test_expired_named_state(self):
        b = badge("EXPIRED")
        assert "EXPIRED" in b

    def test_unknown_status_returns_question_mark_badge(self):
        b = badge("MADE_UP_STATUS")
        assert "❓" in b or "MADE_UP_STATUS" in b


class TestOpIcon:
    def test_all_known_operations_have_icons(self):
        for op in ["READ", "CREATE", "WRITE", "DELETE", "RENAME"]:
            assert op_icon(op) != ""

    def test_delete_has_bin_icon(self):
        assert "🗑" in op_icon("DELETE")

    def test_read_has_book_icon(self):
        assert "📖" in op_icon("READ")

    def test_unknown_operation_has_fallback(self):
        icon = op_icon("COMPRESS")
        assert icon  # non-empty


class TestPolicyDescription:
    def test_known_policies_have_descriptions(self):
        for pid in ["WDN-001", "WDN-002", "WDN-003", "WDN-004"]:
            desc = policy_description(pid)
            assert desc and pid not in desc or len(desc) > len(pid)

    def test_none_returns_fallback(self):
        assert "No policy" in policy_description(None)

    def test_unknown_policy_returns_id(self):
        assert policy_description("WDN-999") == "WDN-999"


class TestRiskFromOperation:
    def test_delete_is_high(self):
        assert "High" in risk_from_operation("DELETE")

    def test_read_is_none_risk(self):
        assert "None" in risk_from_operation("READ")

    def test_write_is_medium(self):
        assert "Medium" in risk_from_operation("WRITE")

    def test_unknown_returns_unknown(self):
        assert "Unknown" in risk_from_operation("COMPRESS")
