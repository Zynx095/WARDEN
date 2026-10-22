"""Autonomous agent orchestration for WARDEN."""

from warden.agents.warden_agent import WardenAgent
from warden.agents.intent_engine import IntentEngine
from warden.identity import AgentIdentityError, derive_agent_address

__all__ = [
    "WardenAgent",
    "IntentEngine",
    "build_warden_agent",
    "derive_agent_address",
    "AgentIdentityError",
]


def __getattr__(name: str):
    # Imported lazily so that `python -m warden.agents.run_agent` does not find the module
    # already loaded by its own package (which triggers a runpy RuntimeWarning).
    if name == "build_warden_agent":
        from warden.agents.run_agent import build_warden_agent
        return build_warden_agent
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
