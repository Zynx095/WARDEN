"""Entry point: ``python -m warden.risk_analyst`` runs the Risk Analyst agent (needs WARDEN_RISK_ANALYST_SEED)."""

from __future__ import annotations

import sys

from warden.agents.run_agent import restrict_bind_host
from warden.config import ConfigError, load_environment
from warden.risk_analyst.agent import build_risk_analyst_agent
from warden.risk_analyst.config import RiskAnalystConfig


def main() -> int:
    load_environment()
    try:
        cfg = RiskAnalystConfig()
        # No endpoint is registered anywhere: replies travel back on WARDEN's synchronous request.
        endpoint = f"http://127.0.0.1:{cfg.port}/submit"
        agent, service = build_risk_analyst_agent(cfg)
    except (ConfigError, ValueError) as exc:
        print(f"Risk Analyst not started: {exc}", file=sys.stderr)
        return 2
    if not restrict_bind_host():
        print("Risk Analyst not started: could not restrict the server to loopback.", file=sys.stderr)
        return 2
    print(f"Risk Analyst address: {service.address} (listening on loopback only, {endpoint})")
    print("Point WARDEN at it with WARDEN_RISK_ANALYST=remote, WARDEN_RISK_ANALYST_ADDRESS and "
          "WARDEN_RISK_ANALYST_ENDPOINT.")
    agent.run()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
