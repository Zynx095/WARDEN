# WARDEN hosted agent: externally hosted uAgent with a public endpoint, registered on Agentverse.
# Status: written against the tested Python entry point; this image has NOT been built or run
# in this repository's verification (no container runtime was available). Build and test it
# before relying on it.
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

RUN useradd --create-home --uid 10001 warden

WORKDIR /app
COPY pyproject.toml README.md ./
COPY src ./src
COPY docs/AGENTVERSE_README.md ./docs/AGENTVERSE_README.md
# Editable install keeps the package rooted at /app, so repository-relative defaults resolve here.
RUN pip install -e . \
 && mkdir -p /app/logs /app/hosted_workspace /app/run /app/state \
 && chown -R warden:warden /app/logs /app/hosted_workspace /app/run /app/state

USER warden
# uAgents writes its own state file in the working directory.
WORKDIR /app/run

# No secrets here. AGENT_SEED, WARDEN_PUBLIC_ENDPOINT and WARDEN_APPROVAL_MODE (plus
# WARDEN_APPROVER_ADDRESSES for independent approval) are injected by the host at runtime.
ENV WARDEN_WORKSPACE_ROOT=/app/hosted_workspace \
    WARDEN_AUDIT_LOG=/app/state/audit.jsonl \
    WARDEN_STATE_DB=/app/state/warden.db \
    PORT=8000
# Approval state and the hash-chained audit log must survive restarts: mount a persistent volume here.
VOLUME ["/app/state"]

EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
  CMD python -c "import os,urllib.request; urllib.request.urlopen('http://127.0.0.1:%s/health' % os.environ.get('PORT','8000'), timeout=4)"

CMD ["python", "-m", "warden.hosting.server"]
