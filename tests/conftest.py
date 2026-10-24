"""Shared test configuration: keep the suite hermetic regardless of the developer's environment."""

import pytest


@pytest.fixture(autouse=True)
def _hermetic_environment(monkeypatch: pytest.MonkeyPatch):
    """Never let a developer's real API keys or identity leak into tests or trigger network calls."""
    for name in ("ASI_ONE_API_KEY", "OPENAI_API_KEY", "AGENT_SEED", "AGENTVERSE_MAILBOX_KEY",
                 "WARDEN_USE_MAILBOX", "WARDEN_APPROVER_ADDRESSES",
                 # settings that change security behaviour: tests must start from the defaults
                 "WARDEN_REMOTE_AUDITOR", "WARDEN_AUDITOR_ADDRESS", "WARDEN_AUDITOR_TIMEOUT_SECONDS",
                 "WARDEN_AUDITOR_SEED", "WARDEN_AUDITOR_ALLOWED_REQUESTER", "WARDEN_AUDITOR_PORT",
                 "WARDEN_AUDITOR_WORKSPACE_ROOT", "WARDEN_APPROVAL_TTL_SECONDS",
                 "WARDEN_MAX_PENDING_APPROVALS", "WARDEN_SECRET_KEY",
                 # hosted mode
                 "WARDEN_PUBLIC_ENDPOINT", "PORT", "WARDEN_HOSTED_ALLOW_INSECURE_ENDPOINT",
                 "AGENTVERSE_API_KEY", "WARDEN_INTERACTIVE_CARDS"):
        monkeypatch.delenv(name, raising=False)
