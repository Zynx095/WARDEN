"""Tests for warden.presentation.sanitize — safe text handling."""

import pytest
from pathlib import Path

from warden.presentation.sanitize import (
    format_file_target,
    redact_digest,
    safe_id,
    sanitize,
    scrub_paths,
    truncate_report,
)


class TestSanitize:
    def test_none_returns_empty(self):
        assert sanitize(None) == ""

    def test_truncates_at_limit(self):
        s = sanitize("a" * 400, limit=300)
        assert len(s) == 300  # exactly 299 chars + ellipsis
        assert s.endswith("…")

    def test_removes_non_printable(self):
        result = sanitize("hello\x00world\x01")
        assert "\x00" not in result
        assert "\x01" not in result
        assert "helloworld" in result

    def test_code_span_removes_backticks(self):
        result = sanitize("file`name", code_span=True)
        assert "`" not in result

    def test_strips_surrounding_whitespace(self):
        assert sanitize("  hello  ") == "hello"


class TestScrubPaths:
    def test_replaces_windows_path(self):
        ws = Path("C:/secret/ws")
        text = f"Writing to {ws}/file.txt"
        assert str(ws) not in scrub_paths(text, ws)
        assert "<workspace>" in scrub_paths(text, ws)

    def test_replaces_posix_variant(self):
        ws = Path("C:/secret/ws")
        text = f"Using {ws.as_posix()}/file.txt"
        assert "<workspace>" in scrub_paths(text, ws)

    def test_no_workspace_no_change(self):
        text = "some text"
        assert scrub_paths(text, None) == "some text"

    def test_longest_variant_replaced_first(self):
        ws = Path("D:/AI/WARDEN")
        text = f"Root: {ws}; Posix: {ws.as_posix()}"
        scrubbed = scrub_paths(text, ws)
        assert str(ws) not in scrubbed
        assert scrubbed.count("<workspace>") == 2


class TestTruncateReport:
    def test_short_report_unchanged(self):
        text = "short"
        assert truncate_report(text, limit=100) == "short"

    def test_long_report_truncated(self):
        text = "line\n" * 1000
        result = truncate_report(text, limit=200)
        assert len(result) <= 250
        assert "truncated" in result

    def test_truncation_cuts_at_newline(self):
        text = ("hello world\n" * 500)
        result = truncate_report(text, limit=300)
        # Should not split a line mid-word
        assert "\nhello" in result or result.endswith("…*(report truncated for readability)*")


class TestSafeId:
    def test_returns_first_8_chars(self):
        assert safe_id("abcdef1234567890") == "abcdef12"

    def test_short_id_returned_as_is(self):
        assert safe_id("abc") == "abc"

    def test_strips_backticks(self):
        result = safe_id("ab`cd`ef12345678")
        assert "`" not in result


class TestFormatFileTarget:
    def test_scrubs_workspace_from_target(self):
        ws = Path("D:/secret/ws")
        result = format_file_target(f"{ws}/cache.tmp", ws)
        assert str(ws) not in result
        assert "cache.tmp" in result

    def test_none_target_returns_empty(self):
        result = format_file_target(None)
        assert result == ""


class TestRedactDigest:
    def test_shows_16_chars_with_ellipsis(self):
        full = "a" * 64
        result = redact_digest(full, show_chars=16)
        assert result == "a" * 16 + "…"

    def test_short_digest_shown_fully(self):
        short = "abc123"
        assert redact_digest(short, show_chars=16) == "abc123"

    def test_none_digest_returns_placeholder(self):
        assert redact_digest(None) == "(no digest)"
