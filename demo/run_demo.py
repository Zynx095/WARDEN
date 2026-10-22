"""Run the deterministic WARDEN demonstration: ``python demo/run_demo.py``."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

from warden.demo import DemoFailure, run_demo  # noqa: E402


def main() -> int:
    try:
        run_demo()
    except DemoFailure as exc:
        print(f"\nDEMO FAILED: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
