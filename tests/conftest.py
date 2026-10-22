"""Shared test configuration: keep the suite hermetic regardless of the developer's environment."""

import pytest


@pytest.fixture(autouse=True)
def _hermetic_environment(monkeypatch: pytest.MonkeyPatch):
    """Never let a developer's real API keys or identity leak into tests or trigger network calls."""
    for name in ("ASI_ONE_API_KEY", "OPENAI_API_KEY", "AGENT_SEED", "AGENTVERSE_MAILBOX_KEY",
                 "WARDEN_USE_MAILBOX", "WARDEN_APPROVER_ADDRESSES"):
        monkeypatch.delenv(name, raising=False)
