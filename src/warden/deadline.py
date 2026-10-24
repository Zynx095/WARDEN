"""Run a blocking call to another agent with a hard deadline."""

from __future__ import annotations

import logging
import queue
import threading
from typing import Any, Callable, Optional, Tuple

logger = logging.getLogger(__name__)


def call_with_deadline(fn: Callable[[], Any], timeout: float, name: str) -> Tuple[Any, Optional[str]]:
    """Return ``(value, None)``, or ``(None, reason)`` on timeout, exception or a None result.

    The call runs on a daemon thread (so it may use its own event loop even when the caller is
    inside one); the caller never waits longer than ``timeout``. Only exception types are logged.
    """
    box: "queue.Queue[tuple[str, Any]]" = queue.Queue(maxsize=1)

    def run() -> None:
        try:
            box.put(("ok", fn()))
        except Exception as exc:
            box.put(("error", type(exc).__name__))

    threading.Thread(target=run, name=f"warden-{name}", daemon=True).start()
    try:
        kind, value = box.get(timeout=timeout)
    except queue.Empty:
        logger.error("%s did not answer within %.1fs", name, timeout)
        return None, "timeout"
    if kind == "error":
        logger.error("%s transport failed: %s", name, value)
        return None, "transport error"
    if value is None:
        return None, "no response"
    return value, None
