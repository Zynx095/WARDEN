"""Local diagnostics for WARDEN: ``python -m warden.doctor``.

Every check reports PASS, WARN or FAIL. Only FAIL makes the exit code non-zero; WARN marks
optional or not-yet-configured integrations. Secret values are never printed: seeds, keys
and tokens are reported only as "set"/"not set"/"valid", and the identity only by its
public address.
"""

from __future__ import annotations

import argparse
import importlib
import os
import socket
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path
from typing import Callable, List, Optional

from warden.config import (
    DEFAULT_ENV_FILE,
    REPO_ROOT,
    ConfigError,
    WardenConfig,
    env_bool,
    is_placeholder,
    load_environment,
)
from warden.execution.workspace import _unsafe_to_wipe_reason
from warden.identity import AgentIdentityError, derive_agent_address, validate_seed

PASS, WARN, FAIL = "PASS", "WARN", "FAIL"
MIN_PYTHON = (3, 10)
REQUIRED_PACKAGES = ["uagents", "uagents-core", "pydantic", "python-dotenv"]
OPTIONAL_PACKAGES = ["openai", "pytest"]


@dataclass
class Check:
    status: str
    name: str
    detail: str = ""
    fix: str = ""


def _git(*args: str) -> Optional[subprocess.CompletedProcess]:
    try:
        return subprocess.run(["git", *args], cwd=REPO_ROOT, capture_output=True, text=True, timeout=20)
    except (OSError, subprocess.SubprocessError):
        return None


def check_python() -> List[Check]:
    checks = []
    v = sys.version_info
    ok = (v.major, v.minor) >= MIN_PYTHON
    checks.append(Check(PASS if ok else FAIL, "Python version", f"{v.major}.{v.minor}.{v.micro}",
                        "" if ok else f"Install Python {MIN_PYTHON[0]}.{MIN_PYTHON[1]}+ and rerun scripts/setup.ps1"))
    venv = REPO_ROOT / ".venv"
    inside = Path(sys.prefix).resolve() == venv.resolve()
    checks.append(Check(PASS if inside else WARN, "Interpreter is the project .venv",
                        sys.executable if inside else f"using {sys.executable}",
                        "" if inside else "Run through scripts/run.ps1 (or .venv\\Scripts\\python.exe) to avoid the global Python"))
    return checks


def check_dependencies() -> List[Check]:
    checks = []
    for pkg in REQUIRED_PACKAGES:
        try:
            checks.append(Check(PASS, f"Package {pkg}", version(pkg)))
        except PackageNotFoundError:
            checks.append(Check(FAIL, f"Package {pkg}", "not installed", "Run scripts/setup.ps1"))
    for pkg in OPTIONAL_PACKAGES:
        try:
            checks.append(Check(PASS, f"Package {pkg} (optional)", version(pkg)))
        except PackageNotFoundError:
            checks.append(Check(WARN, f"Package {pkg} (optional)", "not installed"))
    for mod in ("uagents", "uagents_core.contrib.protocols.chat", "warden.agents.run_agent"):
        try:
            importlib.import_module(mod)
            checks.append(Check(PASS, f"Import {mod}"))
        except Exception as exc:  # report type only; import errors can embed paths, not secrets
            checks.append(Check(FAIL, f"Import {mod}", type(exc).__name__, "Run scripts/setup.ps1"))
    return checks


def check_configuration(env_file: Optional[Path] = None) -> List[Check]:
    checks: List[Check] = []
    loaded = load_environment(env_file)
    if loaded is None:
        checks.append(Check(FAIL, "Configuration file", f"{Path(env_file or DEFAULT_ENV_FILE).name} not found",
                            "Run scripts/setup.ps1 (copies .env.example)"))
    else:
        checks.append(Check(PASS, "Configuration file", str(loaded)))

    try:
        cfg = WardenConfig()
        checks.append(Check(PASS, "Settings parse", f"log level {cfg.log_level}; containment and approval enforced"))
    except ConfigError as exc:
        checks.append(Check(FAIL, "Settings parse", str(exc), "Fix the named variable in .env"))

    seed = os.getenv("AGENT_SEED")
    try:
        address = derive_agent_address(validate_seed(seed))
        checks.append(Check(PASS, "Agent identity (AGENT_SEED)", f"valid; address {address}"))
    except AgentIdentityError as exc:
        checks.append(Check(FAIL, "Agent identity (AGENT_SEED)", str(exc), "python -m warden.identity init"))

    key = os.getenv("WARDEN_SECRET_KEY", "")
    if not key.strip():
        checks.append(Check(PASS, "WARDEN_SECRET_KEY", "not set: random per-process key (no persistence needed)"))
    elif is_placeholder(key) or len(key.strip()) < 32:
        checks.append(Check(FAIL, "WARDEN_SECRET_KEY", "set but weak or placeholder", "Use 32+ random characters or unset it"))
    else:
        checks.append(Check(PASS, "WARDEN_SECRET_KEY", "set (value hidden)"))
    return checks


def check_git_hygiene() -> List[Check]:
    checks: List[Check] = []
    if _git("rev-parse", "--is-inside-work-tree") is None:
        return [Check(WARN, "Git hygiene", "git not available; could not verify secrets are excluded")]
    ignored = _git("check-ignore", "-q", ".env")
    checks.append(Check(PASS if ignored and ignored.returncode == 0 else FAIL, ".env ignored by Git",
                        "", "Add '.env' to .gitignore"))
    tracked = _git("ls-files", "--error-unmatch", ".env")
    checks.append(Check(PASS if tracked and tracked.returncode != 0 else FAIL, ".env not tracked by Git",
                        "", "git rm --cached .env (then rotate AGENT_SEED)"))
    listed = _git("ls-files")
    leaked = [f for f in (listed.stdout.splitlines() if listed else [])
              if Path(f).name in {"private_keys.json", "secrets.json", "credentials.json"} or f.endswith(".pem")]
    checks.append(Check(PASS if not leaked else FAIL, "No key/credential files tracked", ", ".join(leaked)))
    example = _git("ls-files", "--error-unmatch", ".env.example")
    checks.append(Check(PASS if example and example.returncode == 0 else FAIL, ".env.example present and tracked"))
    return checks


def check_filesystem() -> List[Check]:
    checks: List[Check] = []
    try:
        cfg = WardenConfig()
    except ConfigError:
        return [Check(WARN, "Workspace checks skipped", "settings invalid")]
    root = cfg.workspace_root
    reason = _unsafe_to_wipe_reason(root)
    checks.append(Check(FAIL if reason else PASS, "Workspace is disposable", str(root) if not reason else reason,
                        "Set WARDEN_WORKSPACE_ROOT to a dedicated empty directory" if reason else ""))
    try:
        root.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile(dir=root, prefix=".doctor_", delete=True):
            pass
        checks.append(Check(PASS, "Workspace writable", str(root)))
    except OSError as exc:
        checks.append(Check(FAIL, "Workspace writable", type(exc).__name__, "Check folder permissions"))
    if cfg.audit_log is None:
        checks.append(Check(WARN, "Audit log", "persistence disabled (WARDEN_AUDIT_LOG empty)"))
    else:
        try:
            cfg.audit_log.parent.mkdir(parents=True, exist_ok=True)
            with tempfile.NamedTemporaryFile(dir=cfg.audit_log.parent, prefix=".doctor_", delete=True):
                pass
            checks.append(Check(PASS, "Audit log directory writable", str(cfg.audit_log)))
        except OSError as exc:
            checks.append(Check(FAIL, "Audit log directory writable", type(exc).__name__))
    return checks


def check_port() -> List[Check]:
    try:
        port = int(os.getenv("WARDEN_AGENT_PORT") or 8000)
    except ValueError:
        return [Check(FAIL, "Agent port", "WARDEN_AGENT_PORT is not an integer")]
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            s.bind(("127.0.0.1", port))
        except OSError:
            return [Check(WARN, f"Port {port} available", "in use (another agent running?)", "Stop it or set WARDEN_AGENT_PORT")]
    return [Check(PASS, f"Port {port} available", "127.0.0.1")]


def check_integration_readiness() -> List[Check]:
    """State configuration only. None of this proves connectivity or registration."""
    checks = [Check(PASS, "Mode", "local-only is fully usable with no external credentials")]
    try:
        mailbox = env_bool("WARDEN_USE_MAILBOX", False) or bool(os.getenv("AGENTVERSE_MAILBOX_KEY", "").strip())
    except ConfigError as exc:
        return checks + [Check(FAIL, "WARDEN_USE_MAILBOX", str(exc))]
    checks.append(Check(WARN if not mailbox else PASS, "Agentverse mailbox",
                        "configured (provisioning NOT verified by this tool)" if mailbox else "not enabled (optional)"))
    if mailbox:
        approvers = (os.getenv("WARDEN_APPROVER_ADDRESSES") or "").strip()
        if not approvers:
            checks.append(Check(WARN, "Public approvers (WARDEN_APPROVER_ADDRESSES)",
                                "not set: requesters will be able to approve own proposals in chat",
                                "Set trusted agent addresses before exposing to public users"))
        else:
            count = len([a for a in approvers.split(",") if a.strip()])
            checks.append(Check(PASS, "Public approvers (WARDEN_APPROVER_ADDRESSES)",
                                f"configured with {count} authorized address(es)"))

    try:
        pub_manifest = env_bool("AGENTVERSE_PUBLISH_MANIFEST", False)
        checks.append(Check(PASS if pub_manifest else WARN, "Protocol manifest publication",
                            "enabled (publishes ACP manifest to Almanac on startup)" if pub_manifest
                            else "disabled (local-only default; enable when ready for discovery)"))
    except ConfigError as exc:
        checks.append(Check(FAIL, "AGENTVERSE_PUBLISH_MANIFEST", str(exc)))

    key = os.getenv("ASI_ONE_API_KEY", "").strip()
    checks.append(Check(PASS if key and not is_placeholder(key) else WARN, "ASI:One API key (optional)",
                        "set (value hidden; not validated against the service)" if key and not is_placeholder(key)
                        else "not set: deterministic rule-based intent parser is used"))
    return checks


def run_tests() -> List[Check]:
    proc = subprocess.run([sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider"],
                          cwd=REPO_ROOT, capture_output=True, text=True)
    tail = (proc.stdout.strip().splitlines() or ["(no output)"])[-1]
    return [Check(PASS if proc.returncode == 0 else FAIL, "Test suite", tail, "" if proc.returncode == 0 else "python -m pytest -x")]


SECTIONS: List[tuple] = [
    ("Python environment", check_python),
    ("Dependencies", check_dependencies),
    ("Configuration and identity", check_configuration),
    ("Git hygiene (secrets)", check_git_hygiene),
    ("Filesystem and workspace", check_filesystem),
    ("Local runtime", check_port),
    ("Integration readiness", check_integration_readiness),
]


def run_doctor(with_tests: bool = False, out: Callable[[str], None] = print) -> int:
    sections = list(SECTIONS) + ([("Tests", run_tests)] if with_tests else [])
    counts = {PASS: 0, WARN: 0, FAIL: 0}
    for title, fn in sections:
        out(f"\n== {title} ==")
        for c in fn():
            counts[c.status] += 1
            line = f"[{c.status}] {c.name}" + (f": {c.detail}" if c.detail else "")
            out(line)
            if c.status != PASS and c.fix:
                out(f"       fix: {c.fix}")
    out(f"\nSummary: {counts[PASS]} passed, {counts[WARN]} warnings, {counts[FAIL]} failed.")
    return 1 if counts[FAIL] else 0


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m warden.doctor", description="Diagnose the local WARDEN setup.")
    parser.add_argument("--tests", action="store_true", help="also run the pytest suite")
    args = parser.parse_args(argv)
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    return run_doctor(with_tests=args.tests)


if __name__ == "__main__":
    raise SystemExit(main())
