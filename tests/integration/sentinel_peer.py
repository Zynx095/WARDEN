"""Runs one peer agent (Risk Analyst or Auditor) in its own process for the live Sentinel test.

Peers must be separate processes: uAgents delivers a reply to an agent in the same process
locally instead of answering the synchronous request, so co-locating them would not exercise
the real exchange. Like the in-process tests, this disables every startup call that would
publish the throwaway identity and refuses any non-loopback HTTP request.

Usage: python sentinel_peer.py risk|auditor   (configuration comes from the environment)
"""

import sys
from urllib.parse import urlparse

import aiohttp
import requests
from uagents import Agent

LOOPBACK = {"127.0.0.1", "localhost"}


def _offline() -> None:
    original_aiohttp = aiohttp.ClientSession._request
    original_requests = requests.Session.request

    async def guarded_aiohttp(self, method, url, *a, **kw):
        if urlparse(str(url)).hostname not in LOOPBACK:
            raise aiohttp.ClientConnectionError("network disabled in tests")
        return await original_aiohttp(self, method, url, *a, **kw)

    def guarded_requests(self, method, url, *a, **kw):
        if urlparse(str(url)).hostname not in LOOPBACK:
            raise requests.ConnectionError("network disabled in tests")
        return original_requests(self, method, url, *a, **kw)

    async def nothing(self, *a, **kw):
        return None

    aiohttp.ClientSession._request = guarded_aiohttp
    requests.Session.request = guarded_requests
    Agent._update_agent_status = nothing
    Agent.publish_manifest = nothing
    Agent.start_registration_loop = lambda self: None


def main(kind: str) -> int:
    _offline()
    from warden.agents.run_agent import restrict_bind_host
    restrict_bind_host()
    if kind == "risk":
        from warden.risk_analyst.agent import build_risk_analyst_agent
        agent, _ = build_risk_analyst_agent()
    else:
        from warden.auditor.agent import build_auditor_agent
        agent, _ = build_auditor_agent()
    agent.run()
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1]))
