"""Entry point: ``python -m warden.auditor`` runs the Auditor agent (needs its own WARDEN_AUDITOR_SEED)."""

from __future__ import annotations

import sys

from warden.agents.run_agent import restrict_bind_host
from warden.auditor.agent import build_auditor_agent
from warden.config import ConfigError, load_environment


def main() -> int:
    load_environment()
    try:
        agent, service = build_auditor_agent()
    except (ConfigError, ValueError) as exc:
        print(f"Auditor not started: {exc}", file=sys.stderr)
        return 2
    if not restrict_bind_host():
        print("Auditor not started: could not restrict the server to loopback.", file=sys.stderr)
        return 2
    print(f"Auditor address: {service.address} (listening on loopback only)")
    print(f"Workspace (read-only inspection): {service.view.root_path}")
    agent.run()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
