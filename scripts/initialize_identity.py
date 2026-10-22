"""Initialize the persistent WARDEN agent identity in .env (never replaces an existing one).

Thin wrapper kept for backward compatibility; the implementation lives in
``warden.identity`` and is also available as ``python -m warden.identity init``.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from warden.identity import main  # noqa: E402

if __name__ == "__main__":
    raise SystemExit(main(["init"]))
