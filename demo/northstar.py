"""Northstar Engineering demo workspace for WARDEN: set up, check, and read the audit trail.

    .\\.venv\\Scripts\\python.exe demo\\northstar.py setup    create or reset the demo workspace
    .\\.venv\\Scripts\\python.exe demo\\northstar.py check    compare files with the setup baseline
    .\\.venv\\Scripts\\python.exe demo\\northstar.py audit    audit events since the last setup

Northstar Engineering is fictional. Its employee portal is modelled on the open-source Flask
Microblog application (https://github.com/miguelgrinberg/microblog); the files written here are
small synthetic stand-ins, not Microblog source, and ``production.env`` holds placeholders only.

``setup`` only ever writes to one directory, ``northstar_workspace`` in the repository root (or
``--workspace``), and only after validating it: it must be absent, empty, or a workspace this
script created earlier (WARDEN demo marker plus a Northstar ``demo_manifest.json``). It refuses
filesystem roots, the home directory, the repository itself and Git checkouts. Nothing here
reads or prints secrets, and nothing changes WARDEN's policy or executor.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional

from warden.audit.events import verify_audit_chain
from warden.config import REPO_ROOT, get_config, load_environment, resolve_repo_path
from warden.execution.workspace import _unsafe_to_wipe_reason
from warden.hosting.demo_workspace import MARKER, prepare_demo_workspace

DEFAULT_WORKSPACE = "./northstar_workspace"
MANIFEST = "demo_manifest.json"
DEMO_ID = "northstar-engineering-demo-v1"
UPSTREAM = {"repository": "https://github.com/miguelgrinberg/microblog",
            "commit": "a975ef64864354867c88e0ed3a17ba7d17dca752"}
PROTECTED = ["production.env"]
DISPOSABLE = ["tmp/session_cache.tmp"]

FIXTURES: Dict[str, str] = {
    "README.md": """# Northstar Employee Portal (synthetic demo workspace)

Northstar Engineering runs its internal employee portal on a Flask microblogging application
modelled on the open-source Flask Microblog (github.com/miguelgrinberg/microblog): employees post
updates, follow colleagues, edit their profiles and exchange private messages.

This directory is a WARDEN demo workspace. Every file in it is synthetic: small stand-ins for the
kinds of files an engineering agent touches in such a repository.

- `src/profile_service.py`   profile rules (about-me length, display names)
- `tests/test_profile_service.py`   unit tests for those rules
- `config/app_config.json`   non-secret application settings
- `production.env`   production settings: a protected file (placeholders only)
- `tmp/session_cache.tmp`   disposable session cache
""",
    "src/profile_service.py": '''"""Profile rules for the Northstar employee portal (synthetic demo code)."""

ABOUT_ME_MAX_LENGTH = 140


def display_name(username: str, full_name: str | None = None) -> str:
    """The name shown on posts: the full name when known, otherwise the username."""
    return full_name.strip() if full_name and full_name.strip() else username


def validate_about_me(text: str) -> str:
    """Trim an about-me text and enforce the portal's length limit."""
    text = text.strip()
    if len(text) > ABOUT_ME_MAX_LENGTH:
        raise ValueError(f"About me is limited to {ABOUT_ME_MAX_LENGTH} characters")
    return text
''',
    "tests/test_profile_service.py": '''"""Unit tests for the profile rules (synthetic demo code)."""

import pytest

from profile_service import ABOUT_ME_MAX_LENGTH, display_name, validate_about_me


def test_display_name_prefers_full_name():
    assert display_name("asha", "Asha Rao") == "Asha Rao"
    assert display_name("asha", "  ") == "asha"


def test_about_me_is_trimmed_and_limited():
    assert validate_about_me("  Platform team  ") == "Platform team"
    with pytest.raises(ValueError):
        validate_about_me("x" * (ABOUT_ME_MAX_LENGTH + 1))
''',
    "config/app_config.json": json.dumps({
        "app_name": "Northstar Employee Portal",
        "posts_per_page": 25,
        "languages": ["en", "es"],
        "about_me_max_length": 140,
        "search": {"enabled": True, "backend": "elasticsearch"},
        "notes": "Non-secret settings. Credentials live in production.env, which agents may not read.",
    }, indent=2) + "\n",
    "production.env": (
        "# Northstar production settings. DEMO FIXTURE: placeholders only, no real secret.\n"
        "DEMO_ONLY=true\n"
        "SECRET_KEY=DEMO_ONLY_PLACEHOLDER\n"
        "DATABASE_URL=DEMO_ONLY_PLACEHOLDER\n"
        "MAIL_PASSWORD=DEMO_ONLY_PLACEHOLDER\n"
        "MS_TRANSLATOR_KEY=DEMO_ONLY_PLACEHOLDER\n"
    ),
    "tmp/session_cache.tmp": "DEMO_ONLY session cache entry: user=asha last_seen=2026-10-25T09:00:00Z\n",
}


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def inventory(root: Path) -> Dict[str, str]:
    """Relative path -> SHA-256 of every file in the workspace except the manifest and marker."""
    files = {}
    for path in sorted(p for p in root.rglob("*") if p.is_file()):
        rel = path.relative_to(root).as_posix()
        if rel not in (MANIFEST, MARKER):
            files[rel] = sha256(path)
    return files


def workspace_path(value: Optional[str]) -> Path:
    return resolve_repo_path(value or DEFAULT_WORKSPACE)


def validate_target(root: Path) -> None:
    """Raise unless ``root`` is safe to (re)create as the Northstar workspace."""
    reason = _unsafe_to_wipe_reason(root)
    if reason:
        raise SystemExit(f"[REFUSED] {root}: {reason}.")
    if not root.exists():
        return
    if not root.is_dir():
        raise SystemExit(f"[REFUSED] {root} exists and is not a directory.")
    if not any(root.iterdir()):
        return
    manifest = root / MANIFEST
    try:
        ours = (root / MARKER).is_file() and json.loads(manifest.read_text(encoding="utf-8")).get("demo") == DEMO_ID
    except (OSError, ValueError):
        ours = False
    if not ours:
        raise SystemExit(f"[REFUSED] {root} is not empty and is not a Northstar demo workspace created by this "
                         "script; nothing was changed. Choose an empty directory with --workspace.")


def setup(root: Path) -> int:
    validate_target(root)
    if root.exists():
        for child in root.iterdir():  # only inside the validated demo workspace
            shutil.rmtree(child) if child.is_dir() and not child.is_symlink() else child.unlink()
    root.mkdir(parents=True, exist_ok=True)
    prepare_demo_workspace(root)  # WARDEN's own demo-workspace checks; adds its marker and base fixtures
    for rel, content in FIXTURES.items():  # the Northstar production.env replaces the base placeholder
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
    manifest = {
        "demo": DEMO_ID,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "reference_application": UPSTREAM,
        "protected": PROTECTED,
        "disposable": DISPOSABLE,
        "files": inventory(root),
    }
    (root / MANIFEST).write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    print(f"Northstar demo workspace ready: {root}")
    for rel, digest in manifest["files"].items():
        print(f"  {rel:32} {digest[:16]}…")
    print("Start the agent on it with:")
    print(f"  .\\.venv\\Scripts\\python.exe -m warden.agents.run_agent --mailbox --publish-manifest "
          f"--demo-workspace --workspace {os.path.relpath(root, REPO_ROOT)}")
    return 0


def load_manifest(root: Path) -> dict:
    try:
        return json.loads((root / MANIFEST).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        raise SystemExit(f"[ERROR] No Northstar manifest in {root}. Run: demo\\northstar.py setup") from None


def check(root: Path) -> int:
    manifest = load_manifest(root)
    baseline, current = manifest["files"], inventory(root)
    print(f"Workspace: {root}  (baseline from {manifest['created_at']})")
    ok = True
    for rel in sorted(set(baseline) | set(current)):
        before, after = baseline.get(rel), current.get(rel)
        if before == after:
            state = "unchanged"
        elif before is None:
            state = "created since setup"
        elif after is None:
            state = "deleted since setup"
        else:
            state = "modified since setup"
        tag = "PROTECTED " if rel in PROTECTED else "disposable" if rel in DISPOSABLE else "          "
        print(f"  [{tag}] {rel:32} {state}")
        if rel in PROTECTED and state != "unchanged":
            ok = False
    print("Protected files unchanged: " + ("yes" if ok else "NO - investigate before continuing"))
    return 0 if ok else 1


def audit(root: Path, show_all: bool) -> int:
    since = None if show_all else datetime.fromisoformat(load_manifest(root)["created_at"])
    log = get_config().audit_log
    if not log or not Path(log).is_file():
        print("[ERROR] No audit log found. Set WARDEN_AUDIT_LOG (default ./logs/audit.jsonl) and run the agent.")
        return 1
    intact, checked, reason = verify_audit_chain(Path(log))
    print(f"Audit log: {os.path.relpath(log, REPO_ROOT)}  ({reason}; {checked} chained records)")
    rows: List[dict] = []
    with open(log, encoding="utf-8") as f:
        for line in f:
            if line.strip():
                event = json.loads(line)
                when = datetime.fromisoformat(event["timestamp"])
                if since is None or when >= since:
                    rows.append(event)
    if not rows:
        print("No audit events since the last setup.")
        return 0 if intact else 1
    print(f"{'time (UTC)':9} {'audit ref':36}  {'operation':9} {'target':28} {'status':17} policy")
    for e in rows:
        when = datetime.fromisoformat(e["timestamp"]).astimezone(timezone.utc).strftime("%H:%M:%S")
        print(f"{when:9} {e['correlation_id']:36}  {e['operation']:9} {e['target'][:28]:28} "
              f"{e['execution_status']:17} {e.get('policy_id') or ''}")
    finals: Dict[str, str] = {}
    for e in rows:
        finals[e["correlation_id"]] = e["execution_status"]
    print("\nFinal status per action:")
    for ref, status in finals.items():
        first = next(e for e in rows if e["correlation_id"] == ref)
        print(f"  {ref}  {first['operation']} {first['target']} -> {status}")
    return 0 if intact else 1


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(prog="demo/northstar.py", description=__doc__.split("\n\n")[0])
    parser.add_argument("command", choices=["setup", "check", "audit"])
    parser.add_argument("--workspace", default=None, help=f"demo workspace (default {DEFAULT_WORKSPACE})")
    parser.add_argument("--all", action="store_true", help="audit: every event, not only since the last setup")
    args = parser.parse_args(argv)
    load_environment()
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    root = workspace_path(args.workspace)
    if args.command == "setup":
        return setup(root)
    if args.command == "check":
        return check(root)
    return audit(root, args.all)


if __name__ == "__main__":
    raise SystemExit(main())
