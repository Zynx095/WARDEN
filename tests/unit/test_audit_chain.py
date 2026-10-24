"""Hash-chained persistent audit log: continuation across restarts and tamper detection."""

import json

from warden.audit.events import AuditLogger, verify_audit_chain
from warden.models import AuditEvent, ExecutionStatus


def event(i):
    return AuditEvent(operation="DELETE", target=f"f{i}.tmp", execution_status=ExecutionStatus.PROPOSED)


def write(path, n, start=0):
    log = AuditLogger(path)
    for i in range(start, start + n):
        log.record(event(i))


def test_chain_is_intact_and_continues_after_a_restart(tmp_path):
    path = tmp_path / "audit.jsonl"
    write(path, 3)
    write(path, 2, start=3)  # a new logger (restart) continues the same chain
    assert verify_audit_chain(path) == (True, 5, "audit chain intact")


def test_modified_inserted_or_deleted_lines_are_detected(tmp_path):
    path = tmp_path / "audit.jsonl"
    write(path, 4)
    lines = path.read_text(encoding="utf-8").splitlines()

    edited = json.loads(lines[1])
    edited["target"] = "production.env"
    path.write_text("\n".join([lines[0], json.dumps(edited), *lines[2:]]) + "\n", encoding="utf-8")
    assert verify_audit_chain(path)[0] is False

    path.write_text("\n".join([lines[0], *lines[2:]]) + "\n", encoding="utf-8")
    ok, _, reason = verify_audit_chain(path)
    assert not ok and "does not follow" in reason

    path.write_text("\n".join([lines[0], '{"target": "forged"}', *lines[1:]]) + "\n", encoding="utf-8")
    assert verify_audit_chain(path)[0] is False
