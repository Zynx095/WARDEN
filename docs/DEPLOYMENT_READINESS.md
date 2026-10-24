# Deployment readiness (2026-10-24)

Branch `integration/sentinel-final` (worktree `D:\AI\WARDEN_final`), built on
`feature/sentinel-network` → `feature/asi-hosting` → `master` (`0afa11c`). Not merged into
`master`, not pushed, not deployed.

## Verified locally (Windows 11, Python 3.12, uAgents 0.26.1)

| Check | Command | Result |
|---|---|---|
| Compile | `python -m compileall -q src tests demo scripts` | ok |
| Full suite | `python -m pytest` | 650 passed (run repeatedly) |
| Presentation | `python -m pytest tests/presentation` | 66 passed |
| Interactive Cards | `python -m pytest tests/unit/test_cards.py tests/integration/test_interactive_cards.py` | 71 passed |
| Acceptance | `python -m pytest tests/acceptance` | 28 passed |
| Risk Analyst | `python -m pytest tests/risk` | 51 passed |
| Security | `python -m pytest tests/security` | 41 passed |
| Live loopback (real uAgents envelopes; Risk Analyst and Auditor as separate processes) | `python -m pytest tests/integration/test_sentinel_network_live.py tests/hosting/test_hosted_live.py tests/integration/test_remote_auditor_live.py` | 5 passed |
| Security demo | `python demo/run_demo.py` | DEMO PASSED, 12 checks |
| Doctor | `python -m warden.doctor` | runs; in a checkout without `.env` it reports the missing `.env` and `AGENT_SEED` (expected) |
| Clean checkout | fresh `git clone`, new venv, `pip install -e ".[dev]"`, `pytest`, demo | passed, no private files needed |
| Hosted startup validation | `python -m warden.hosting.server` with a missing approval mode, `independent` without approvers, no state DB, a corrupt state DB, an `http://` endpoint | each refused with a specific error, exit 1 |
| Registration | `python -m warden.hosting.register --dry-run` (throwaway seed) | profile printed, nothing sent |

One full-suite run on the earlier hosting branch failed once in `tests/hosting/test_hosted_live.py`
and could not be reproduced afterwards; the likely cause (a connection reset when an oversized
body is refused) is handled, but it was not confirmed. No linter or type checker is configured.

## Not verified

- **Container build**: Docker is not installed and WSL2 cannot start (virtualization disabled).
- **Linux**: the suite has only run on Windows; the image is Linux.
- **Any deployment, Agentverse registration, real ASI:One conversation**, card rendering and
  buttons in ASI:One, and the sender address ASI:One uses.

## Residual risks

1. Approver identity rests on the sender address ASI:One provides (unverified). Use
   `WARDEN_APPROVAL_MODE=independent` and confirm in a real conversation that addresses are
   per user before relying on it.
2. No OS-level isolation: all stages run in one process as one OS user. The local auditor and
   the optional peers are separate checks, not sandboxes.
3. The audit chain detects edits, not a consistent rewrite; ship it off-host for stronger
   guarantees.
4. Collateral detection covers only the touched directories.
5. Case-folded digests: keep the remote Auditor off on the (case-sensitive) Linux container.
6. A remote Risk Analyst or Auditor blocks the event loop for up to its timeout per action.
7. Slow-client protection and rate limiting are left to the hosting proxy.

## What you need to provide

- A container host with public HTTPS, a persistent volume for `/app/state`, and permission to
  deploy there.
- `AGENT_SEED` (existing WARDEN identity, or a new one you create), `WARDEN_PUBLIC_ENDPOINT`,
  `WARDEN_APPROVAL_MODE` (+ `WARDEN_APPROVER_ADDRESSES`), in the host's secret store.
- `AGENTVERSE_API_KEY` for `register --confirm`, and permission to publish.
- Only if you want separate peer agents: two new identities (`WARDEN_RISK_ANALYST_SEED`,
  `WARDEN_AUDITOR_SEED`) and a supervisor or extra containers to run them.

Steps: [HOSTING.md](HOSTING.md) "Build and local container check" and "Deployment steps".
