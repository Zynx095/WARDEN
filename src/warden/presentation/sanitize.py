"""Safe text sanitisation utilities for WARDEN's presentation layer.

All untrusted values — filenames, user input, error messages — pass through
these helpers before being embedded in chat replies or card payloads.

Rules:
- Printable, non-backtick characters only in code spans.
- Hard character limits to prevent flooding.
- Ellipsis appended on truncation so the reader knows content was cut.
- Path leakage removed before sending across the network.
- No injection into markdown control sequences.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Optional

# Maximum characters for a single display value in a card row
_CARD_VALUE_LIMIT = 300

# Maximum characters for a full-text report body
_REPORT_BODY_LIMIT = 3_500

# Characters that are stripped from values shown in inline code spans
_CODE_SPAN_STRIP = set("`\x00\x01\x02\x03\x04\x05\x06\x07\x08\x0b\x0c\x0e\x0f")


def sanitize(value: Any, limit: int = _CARD_VALUE_LIMIT, *, code_span: bool = False) -> str:
    """Return a safely displayable string from any value.

    Parameters
    ----------
    value:
        Any Python object; converted to str first.
    limit:
        Hard character ceiling; the value is truncated and an ellipsis appended.
    code_span:
        When True, strip backticks and control characters so the result is safe
        inside a Markdown inline code span (`…`).
    """
    if value is None:
        return ""
    text = str(value)
    # Remove non-printable characters
    text = "".join(ch for ch in text if ch.isprintable())
    if code_span:
        text = "".join(ch for ch in text if ch not in _CODE_SPAN_STRIP)
    if len(text) > limit:
        text = text[: limit - 1] + "…"
    return text.strip()


def sanitize_block(value: Any, limit: int = 1500) -> str:
    """Multi-line text (e.g. read output) safe inside a fenced code block: printable characters,
    newlines and tabs only, no backtick fences, bounded length."""
    if value is None:
        return ""
    text = "".join(ch for ch in str(value) if ch.isprintable() or ch in "\n\t")
    text = text.replace("`", "'")
    if len(text) > limit:
        text = text[: limit - 1] + "…"
    return text.rstrip()


def scrub_paths(text: Any, workspace_root: Optional[Path | str] = None) -> str:
    """Remove local filesystem path variants from text to prevent path leakage.

    Replaces the workspace root path (all slash variants) with ``<workspace>``.
    """
    out = str(text)
    if workspace_root:
        root = Path(workspace_root)
        variants = sorted(
            {str(root), root.as_posix(), str(root).replace("\\", "\\\\")},
            key=len,
            reverse=True,  # replace longest variant first
        )
        for v in variants:
            out = out.replace(v, "<workspace>")
    return out


def truncate_report(text: str, limit: int = _REPORT_BODY_LIMIT) -> str:
    """Truncate a report body that would exceed the chat-message limit."""
    if len(text) <= limit:
        return text
    cut = text[: limit - 40]
    # Try to cut at a newline boundary
    nl = cut.rfind("\n")
    if nl > limit // 2:
        cut = cut[:nl]
    return cut + "\n\n…*(report truncated for readability)*"


def safe_id(value: Any, chars: int = 8) -> str:
    """Return the first ``chars`` characters of an ID after sanitisation."""
    raw = sanitize(value, limit=chars + 4, code_span=True)
    return raw[:chars] if len(raw) >= chars else raw


def format_file_target(target: Any, workspace_root: Optional[Path | str] = None) -> str:
    """Display a file target safely — scrub absolute path then shorten if needed."""
    scrubbed = scrub_paths(sanitize(target, limit=400), workspace_root)
    return sanitize(scrubbed, limit=200, code_span=True)


def redact_digest(digest: Optional[str], show_chars: int = 16) -> str:
    """Show only the leading portion of an action digest for readability.

    The full digest is shown in the approval command; this is a display hint.
    """
    if not digest:
        return "(no digest)"
    d = sanitize(digest, limit=64, code_span=True)
    if len(d) <= show_chars:
        return d
    return d[:show_chars] + "…"
