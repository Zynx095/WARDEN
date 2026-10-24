"""Audit event logging and retrieval for WARDEN.

The persistent JSONL log is hash-chained: every line carries ``chain.prev`` (the previous
line's hash) and ``chain.hash`` = SHA-256 of ``prev`` plus the canonical JSON of the event.
``verify_audit_chain`` detects an edited, inserted, reordered or deleted line. It does not
stop someone with write access from rewriting the whole file consistently; for that, ship
the log (or its latest hash) to storage the WARDEN host cannot rewrite.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import List, Optional, Tuple
from warden.models import AuditEvent, ExecutionStatus

GENESIS = "0" * 64


def _link(prev: str, payload: dict) -> str:
    blob = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256((prev + blob).encode("utf-8")).hexdigest()


def _last_hash(log_file: Path) -> str:
    """Hash of the last chained line, so a restarted process continues the same chain."""
    try:
        with open(log_file, "rb") as f:
            f.seek(0, 2)
            size = f.tell()
            f.seek(max(0, size - 65536))
            tail = f.read().decode("utf-8", errors="replace").strip().splitlines()
    except FileNotFoundError:
        return GENESIS
    for line in reversed(tail):
        try:
            return json.loads(line)["chain"]["hash"]
        except (ValueError, KeyError, TypeError):
            continue
    return GENESIS


def verify_audit_chain(log_file: Path) -> Tuple[bool, int, str]:
    """(intact, chained lines checked, reason). Fails on the first line that breaks the chain.

    Lines written before chaining existed may precede the chain; they are counted and named in
    the reason (they are not covered), but once chained lines start, every line must chain.
    """
    prev = GENESIS
    count = 0
    legacy = 0
    with open(log_file, encoding="utf-8") as f:
        for number, line in enumerate(f, 1):
            if not line.strip():
                continue
            try:
                record = json.loads(line)
            except ValueError:
                return False, count, f"line {number} is not valid JSON"
            if not isinstance(record, dict):
                return False, count, f"line {number} is not an audit record"
            if "chain" not in record and count == 0:
                legacy += 1
                continue
            chain = record.pop("chain", None)
            if not isinstance(chain, dict):
                return False, count, f"line {number} is not a chained audit record"
            if chain.get("prev") != prev:
                return False, count, f"line {number} does not follow the previous record"
            if chain.get("hash") != _link(prev, record):
                return False, count, f"line {number} was modified"
            prev = chain["hash"]
            count += 1
    if legacy:
        return True, count, f"audit chain intact; {legacy} earlier unchained record(s) are not covered"
    return True, count, "audit chain intact"


class AuditLogger:
    """Records structured audit events in memory and optionally on disk (hash-chained)."""

    def __init__(self, log_file: Optional[Path] = None) -> None:
        self.log_file = log_file
        self._events: List[AuditEvent] = []
        self._last = _last_hash(log_file) if log_file else GENESIS

    def record(self, event: AuditEvent) -> None:
        """Record an audit event."""
        self._events.append(event)
        if self.log_file:
            payload = json.loads(event.model_dump_json())
            digest = _link(self._last, payload)
            line = json.dumps({**payload, "chain": {"prev": self._last, "hash": digest}}, separators=(",", ":"))
            self.log_file.parent.mkdir(parents=True, exist_ok=True)
            with open(self.log_file, "a", encoding="utf-8") as f:
                f.write(line + "\n")
            self._last = digest

    def get_events(
        self,
        correlation_id: Optional[str] = None,
        status: Optional[ExecutionStatus] = None,
    ) -> List[AuditEvent]:
        """Query recorded audit events."""
        results = self._events
        if correlation_id:
            results = [e for e in results if e.correlation_id == correlation_id]
        if status:
            results = [e for e in results if e.execution_status == status]
        return list(results)

    def clear(self) -> None:
        """Clear the in-memory audit log."""
        self._events.clear()
