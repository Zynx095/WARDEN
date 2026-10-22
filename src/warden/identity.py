"""Agent identity management: seed validation, address derivation and safe initialization.

The agent address is derived exactly as the installed uAgents SDK does it
(``Identity.from_seed(seed, 0)``), so the address shown by diagnostics is the address
the running agent will have. Seeds are never printed, logged or returned in errors.
"""

from __future__ import annotations

import argparse
import os
import re
import secrets
import sys
import tempfile
from pathlib import Path
from typing import Callable, Optional

from uagents.crypto import Identity

from warden.config import DEFAULT_ENV_FILE, is_placeholder, load_environment

MIN_SEED_LENGTH = 16
SEED_VARIABLE = "AGENT_SEED"
_SEED_LINE = re.compile(r"^\s*AGENT_SEED\s*=(.*)$")


class AgentIdentityError(ValueError):
    """Raised when agent identity configuration is missing or insecure."""


def validate_seed(seed: Optional[str]) -> str:
    """Return the stripped seed, or raise :class:`AgentIdentityError` without echoing it."""
    clean = (seed or "").strip()
    if not clean:
        raise AgentIdentityError(
            "Agent seed is not configured. Provide an explicit seed argument or set AGENT_SEED "
            "in your environment. Fallback to predictable hardcoded seeds is prohibited."
        )
    if is_placeholder(clean):
        raise AgentIdentityError(
            "AGENT_SEED still contains a template placeholder. Run "
            "scripts/setup.ps1 (or 'python -m warden.identity init') to generate a real identity."
        )
    if len(clean) < MIN_SEED_LENGTH:
        raise AgentIdentityError(
            f"AGENT_SEED is too short (minimum {MIN_SEED_LENGTH} characters). "
            "Generate one with 'python -m warden.identity init'."
        )
    return clean


def derive_agent_address(seed: str) -> str:
    """Derive the public agent address from a seed without exposing the seed."""
    return Identity.from_seed(validate_seed(seed), 0).address


def generate_seed() -> str:
    """Generate a fresh 256-bit random seed (64 hex characters)."""
    return secrets.token_hex(32)


def read_seed_from_env_file(env_file: Path) -> Optional[str]:
    """Return the raw value of an uncommented AGENT_SEED line, or None."""
    if not env_file.is_file():
        return None
    for line in env_file.read_text(encoding="utf-8").splitlines():
        m = _SEED_LINE.match(line)
        if m:
            return m.group(1).strip().strip("'\"")
    return None


def initialize_identity(
    env_file: Path | str = DEFAULT_ENV_FILE,
    generator: Callable[[], str] = generate_seed,
) -> str:
    """Create a persistent identity in ``env_file`` and return the public address.

    Refuses to replace an existing real seed. A missing, empty or placeholder
    ``AGENT_SEED`` is filled in; every other line of the file is preserved.
    """
    env_path = Path(env_file)
    if not env_path.is_file():
        raise AgentIdentityError(
            f"{env_path.name} does not exist. Copy .env.example to .env first "
            "(scripts/setup.ps1 does this safely)."
        )

    existing = read_seed_from_env_file(env_path)
    if existing and not is_placeholder(existing):
        raise AgentIdentityError(
            "AGENT_SEED is already configured. Refusing to replace an existing identity."
        )

    seed = validate_seed(generator())
    address = derive_agent_address(seed)

    lines = env_path.read_text(encoding="utf-8").splitlines()
    replaced = False
    for i, line in enumerate(lines):
        if _SEED_LINE.match(line):
            lines[i] = f"{SEED_VARIABLE}={seed}"
            replaced = True
            break
    if not replaced:
        lines.append(f"{SEED_VARIABLE}={seed}")

    fd, tmp_name = tempfile.mkstemp(dir=env_path.parent, prefix=".env.", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
            handle.write("\n".join(lines) + "\n")
        os.replace(tmp_name, env_path)
    except Exception:
        try:
            os.unlink(tmp_name)
        except OSError:
            pass
        raise
    return address


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m warden.identity", description="Manage the WARDEN agent identity.")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("init", help="Generate AGENT_SEED in .env if none is configured (never replaces one).")
    sub.add_parser("address", help="Print the public agent address derived from AGENT_SEED.")
    args = parser.parse_args(argv)

    env_path = load_environment()
    try:
        if args.command == "init":
            target = env_path or DEFAULT_ENV_FILE
            address = initialize_identity(target)
            print("Persistent WARDEN identity initialized. The seed was saved to .env and was not printed.")
            print(f"Agent address: {address}")
        else:
            print(f"Agent address: {derive_agent_address(os.getenv(SEED_VARIABLE, ''))}")
    except AgentIdentityError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
