"""Audit event logging and retrieval for WARDEN."""

from __future__ import annotations

import json
from pathlib import Path
from typing import List, Optional
from warden.models import AuditEvent, ExecutionStatus


class AuditLogger:
    """Records structured audit events in memory and optionally on disk."""

    def __init__(self, log_file: Optional[Path] = None) -> None:
        self.log_file = log_file
        self._events: List[AuditEvent] = []

    def record(self, event: AuditEvent) -> None:
        """Record an audit event."""
        self._events.append(event)
        if self.log_file:
            self.log_file.parent.mkdir(parents=True, exist_ok=True)
            with open(self.log_file, "a", encoding="utf-8") as f:
                f.write(event.model_dump_json() + "\n")

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
