"""Register the hosted WARDEN agent with Agentverse so ASI:One can discover and reach it.

``python -m warden.hosting.register --dry-run`` validates everything and shows what would be
published, without credentials or network calls. Publishing requires ``--confirm`` plus
``AGENTVERSE_API_KEY`` and the agent's existing ``AGENT_SEED``; this creates no identity.
Secrets are read from the environment only and are never printed.
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path
from typing import List, Optional

from warden.config import REPO_ROOT, ConfigError, load_environment
from warden.hosting.config import HostedConfig
from warden.identity import AgentIdentityError, derive_agent_address, validate_seed

DEFAULT_README = REPO_ROOT / "docs" / "AGENTVERSE_README.md"
STARTER_PROMPTS: List[str] = [
    "List the files in the WARDEN workspace",
    "Delete cache.tmp",
    "Clean up temporary files",
    "Delete production.env",
]


def build_registration(cfg: HostedConfig, readme_path: Optional[Path] = None) -> dict:
    """The public profile that will be sent. Contains no secret."""
    readme_file = Path(readme_path or cfg.readme_path or DEFAULT_README)
    if not readme_file.is_file():
        raise ConfigError(f"Agentverse README not found: {readme_file.name}")
    return {
        "name": cfg.agent_name,
        "endpoint": cfg.public_endpoint,
        "description": cfg.description,
        "readme": readme_file.read_text(encoding="utf-8"),
        "starter_prompts": STARTER_PROMPTS,
        "metadata": {"categories": ["security", "developer-tools"], "is_public": "True"},
    }


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Register the hosted WARDEN agent on Agentverse")
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--dry-run", action="store_true", help="Validate and print the profile; send nothing")
    mode.add_argument("--confirm", action="store_true", help="Actually publish the registration to Agentverse")
    parser.add_argument("--mailbox", action="store_true", help="Register as an Agentverse Mailbox (Mailman) agent")
    parser.add_argument("--readme", type=Path, default=None, help="README to publish (default docs/AGENTVERSE_README.md)")
    args = parser.parse_args(argv)

    load_environment()
    try:
        cfg = HostedConfig(use_mailbox=True) if args.mailbox else HostedConfig()
        if cfg.public_endpoint.startswith("http://"):
            raise ConfigError("Refusing to register a plain-http endpoint; Agentverse needs a public https URL.")
        seed = validate_seed(os.getenv("AGENT_SEED"))
        registration = build_registration(cfg, args.readme)
    except (AgentIdentityError, ConfigError, ValueError) as exc:
        print(f"[CONFIGURATION ERROR] {exc}", file=sys.stderr)
        return 1

    print(f"Agent address: {derive_agent_address(seed)}")
    print(f"Name:          {registration['name']}")
    print(f"Endpoint:      {registration['endpoint']}")
    print(f"README:        {len(registration['readme'])} characters")
    print(f"Prompts:       {len(registration['starter_prompts'])}")
    if args.dry_run:
        print("Dry run: nothing was sent.")
        return 0

    api_key = (os.getenv("AGENTVERSE_API_KEY") or "").strip()
    if not api_key:
        print("[CONFIGURATION ERROR] AGENTVERSE_API_KEY is required to publish.", file=sys.stderr)
        return 1

    from uagents_core.utils.registration import (
        AgentverseRequestError,
        RegistrationRequestCredentials,
        register_chat_agent,
    )

    try:
        register_chat_agent(
            name=registration["name"],
            endpoint=registration["endpoint"],
            active=True,
            credentials=RegistrationRequestCredentials(agentverse_api_key=api_key, agent_seed_phrase=seed),
            description=registration["description"],
            readme=registration["readme"],
            starter_prompts=registration["starter_prompts"],
            metadata=registration["metadata"],
        )
    except AgentverseRequestError as exc:
        print(f"[REGISTRATION FAILED] {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1
    if cfg.use_mailbox:
        print("Provisioning Agentverse mailbox access challenge...")
        import asyncio
        from uagents import Agent
        from warden.hosting.server import ensure_agentverse_mailbox
        temp_agent = Agent(name=registration["name"], seed=seed, mailbox=True)
        try:
            ok = asyncio.run(ensure_agentverse_mailbox(temp_agent, api_key))
            if ok:
                print("Mailbox access challenge proved and verified on Agentverse.")
            else:
                print("[NOTE] Mailbox registration requested; agent will connect to mailbox on start.")
        except Exception as exc:
            print(f"[NOTE] Mailbox provisioning will complete on agent startup: {exc}")

    print("Registered on Agentverse. Verify the profile and test it from ASI:One before announcing it.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
