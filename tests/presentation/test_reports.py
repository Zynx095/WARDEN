"""Tests for warden.presentation.reports — text report formatters."""

import pytest
from pathlib import Path

from warden.models import ExecutionStatus
from warden.presentation.reports import (
    format_approval_executed,
    format_awaiting_approval,
    format_blocked,
    format_failed,
    format_no_action,
    format_pipeline_report,
    format_unverified,
    format_verified,
)


WS = Path("D:/secret/workspace")


def _result(**kw):
    base = {
        "action_id": "abcdef12-1234-1234-1234-abcdef123456",
        "operation": "DELETE",
        "target": str(WS / "cache.tmp"),
    }
    base.update(kw)
    return base


# ── format_verified ────────────────────────────────────────────────────────

class TestFormatVerified:
    def test_contains_verified_badge(self):
        r = _result(status=ExecutionStatus.VERIFIED, verification_details="File confirmed deleted.")
        text = format_verified(r, 1, WS)
        assert "VERIFIED" in text

    def test_scrubs_path(self):
        r = _result(status=ExecutionStatus.VERIFIED, verification_details=f"Deleted {WS}/cache.tmp")
        text = format_verified(r, 1, WS)
        assert str(WS) not in text

    def test_output_included_when_present(self):
        r = _result(status=ExecutionStatus.VERIFIED, output="line1\nline2")
        text = format_verified(r, 1, WS)
        assert "line1" in text

    def test_no_output_field_when_absent(self):
        r = _result(status=ExecutionStatus.VERIFIED)
        text = format_verified(r, 1, WS)
        assert "Output" not in text or "line" not in text


# ── format_blocked ─────────────────────────────────────────────────────────

class TestFormatBlocked:
    def test_contains_blocked_badge(self):
        r = _result(status=ExecutionStatus.BLOCKED, policy_id="WDN-003", reason="Protected resource.")
        text = format_blocked(r, 1, WS)
        assert "BLOCKED" in text

    def test_shows_policy_id(self):
        r = _result(status=ExecutionStatus.BLOCKED, policy_id="WDN-003", reason="Protected.")
        text = format_blocked(r, 1, WS)
        assert "WDN-003" in text

    def test_no_filesystem_change_stated(self):
        r = _result(status=ExecutionStatus.BLOCKED, policy_id="WDN-003", reason="Protected.")
        text = format_blocked(r, 1, WS)
        assert "no filesystem" in text.lower() or "blocked before" in text.lower()

    def test_path_scrubbed(self):
        r = _result(status=ExecutionStatus.BLOCKED, reason=f"Path {WS} is protected.")
        text = format_blocked(r, 1, WS)
        assert str(WS) not in text


# ── format_awaiting_approval ───────────────────────────────────────────────

class TestFormatAwaitingApproval:
    def _pending(self, **kw):
        base = {
            "action_id":    "abcdef12-1234-1234-1234-abcdef123456",
            "pending_id":   "abcdef12-1234-1234-1234-abcdef123456",
            "operation":    "DELETE",
            "target":       "cache.tmp",
            "policy_id":    "WDN-004",
            "reason":       "Destructive action.",
            "action_digest": "a" * 64,
            "expires_at":   "2026-10-24T13:00:00",
        }
        base.update(kw)
        return base

    def test_contains_approval_badge(self):
        text = format_awaiting_approval(self._pending(), 1, WS)
        assert "AWAITING" in text

    def test_contains_approve_command(self):
        text = format_awaiting_approval(self._pending(), 1, WS)
        assert "APPROVE" in text

    def test_digest_shown_abbreviated(self):
        text = format_awaiting_approval(self._pending(), 1, WS)
        # Full 64-char digest appears in the APPROVE command (required for safety)
        # but the *display* section shows the abbreviated form
        full = "a" * 64
        # The APPROVE command line contains the full digest
        assert full in text
        # The abbreviated digest (first 16 chars) also appears in the display section
        assert "a" * 16 in text

    def test_risk_level_shown(self):
        text = format_awaiting_approval(self._pending(), 1, WS)
        assert "High" in text  # DELETE is high risk

    def test_expiry_shown(self):
        text = format_awaiting_approval(self._pending(), 1, WS)
        assert "2026-10-24" in text

    def test_destination_shown_when_present(self):
        text = format_awaiting_approval(self._pending(destination="new_cache.tmp"), 1, WS)
        assert "Destination" in text

    def test_no_fabricated_fields_when_absent(self):
        p = self._pending()
        p.pop("expires_at")
        text = format_awaiting_approval(p, 1, WS)
        assert "Expires" not in text


# ── format_failed ──────────────────────────────────────────────────────────

class TestFormatFailed:
    def test_contains_failed_badge(self):
        r = _result(status=ExecutionStatus.FAILED, error="Permission denied.")
        text = format_failed(r, 1, WS)
        assert "FAILED" in text or "❌" in text

    def test_error_shown(self):
        r = _result(status=ExecutionStatus.FAILED, error="Disk full.")
        text = format_failed(r, 1, WS)
        assert "Disk full" in text


# ── format_no_action ──────────────────────────────────────────────────────

class TestFormatNoAction:
    def test_contains_sentinel_branding(self):
        text = format_no_action("list files")
        assert "WARDEN" in text

    def test_mentions_supported_operations(self):
        text = format_no_action("some request")
        assert "READ" in text

    def test_input_echoed_safely(self):
        text = format_no_action("delete <script>alert(1)</script>")
        # HTML-like tags must be stripped from the echoed user input
        assert "<script>" not in text

    def test_long_input_truncated(self):
        text = format_no_action("x" * 500)
        assert len(text) < 1000


# ── format_pipeline_report ────────────────────────────────────────────────

class TestFormatPipelineReport:
    def test_contains_sentinel_header(self):
        results = [_result(status=ExecutionStatus.VERIFIED, verification_details="OK")]
        text = format_pipeline_report("Delete cache.tmp", results, WS)
        assert "WARDEN Sentinel" in text

    def test_all_statuses_rendered_without_crash(self):
        statuses = [
            ExecutionStatus.VERIFIED,
            ExecutionStatus.UNVERIFIED,
            ExecutionStatus.BLOCKED,
            ExecutionStatus.AWAITING_APPROVAL,
            ExecutionStatus.FAILED,
        ]
        for s in statuses:
            r = _result(
                status=s,
                policy_id="WDN-004",
                reason="test",
                action_digest="a" * 64,
                pending_id="abcdef12-1234-1234-1234-abcdef123456",
            )
            text = format_pipeline_report("test", [r], WS)
            assert len(text) > 0, f"Empty report for status {s}"

    def test_path_never_leaks(self):
        results = [_result(status=ExecutionStatus.VERIFIED, verification_details=f"Deleted {WS}/cache.tmp")]
        text = format_pipeline_report("Delete cache.tmp", results, WS)
        assert str(WS) not in text

    def test_long_report_truncated(self):
        # Many results → long output
        results = [_result(
            status=ExecutionStatus.VERIFIED,
            verification_details="x" * 200,
        ) for _ in range(30)]
        text = format_pipeline_report("bulk delete", results, WS)
        assert len(text) < 5000


# ── format_approval_executed ──────────────────────────────────────────────

class TestFormatApprovalExecuted:
    def test_verified_contains_auditor_evidence(self):
        res = _result(status=ExecutionStatus.VERIFIED, verification_details="File gone.")
        text = format_approval_executed("abcdef12-1234-1234-1234-abcdef123456", res, WS)
        assert "VERIFIED" in text or "Auditor" in text

    def test_failed_contains_error(self):
        res = _result(status=ExecutionStatus.FAILED, error="Target missing.")
        text = format_approval_executed("abcdef12-1234-1234-1234-abcdef123456", res, WS)
        assert "Target missing" in text or "FAILED" in text or "Error" in text

    def test_path_scrubbed(self):
        res = _result(status=ExecutionStatus.VERIFIED, verification_details=f"Deleted {WS}/cache.tmp")
        text = format_approval_executed("abcdef12-1234-1234-1234-abcdef123456", res, WS)
        assert str(WS) not in text
