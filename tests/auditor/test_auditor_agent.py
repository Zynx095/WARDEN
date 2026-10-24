"""Auditor process: distinct identity, mandatory allow-list, read-only by construction."""

import re
from pathlib import Path

import pytest

from warden.audit.wire import AuditRequestWire
from warden.auditor import service as service_module
from warden.auditor import workspace_view as view_module
from warden.auditor.agent import AUDITOR_PROTOCOL_NAME, build_auditor_agent, create_auditor_protocol
from warden.auditor.config import AuditorConfig
from warden.config import ConfigError
from warden.identity import AgentIdentityError, derive_agent_address

AUDITOR_SEED = "auditor-test-seed-not-a-real-identity-1"
WARDEN_SEED = "warden-test-seed-not-a-real-identity-001"
WARDEN_ADDRESS = derive_agent_address(WARDEN_SEED)


def cfg(tmp_path, **kw):
    base = dict(seed=AUDITOR_SEED, port=8190, workspace_root=tmp_path, allowed_requesters=[WARDEN_ADDRESS])
    base.update(kw)
    return AuditorConfig(**base)


def test_auditor_requires_its_own_seed(tmp_path):
    with pytest.raises(ConfigError):
        cfg(tmp_path, seed=None).validated_seed(WARDEN_SEED)


def test_auditor_rejects_wardens_seed(tmp_path):
    with pytest.raises(ConfigError):
        cfg(tmp_path, seed=WARDEN_SEED).validated_seed(WARDEN_SEED)


def test_auditor_rejects_weak_seed(tmp_path):
    with pytest.raises(AgentIdentityError):
        cfg(tmp_path, seed="short").validated_seed(WARDEN_SEED)


def test_auditor_requires_an_allowed_requester(tmp_path):
    with pytest.raises(ConfigError):
        cfg(tmp_path, allowed_requesters=[]).validated_requesters()


def test_built_agent_has_a_distinct_identity_and_audit_protocol(tmp_path):
    agent, service = build_auditor_agent(cfg(tmp_path), warden_seed=WARDEN_SEED)
    assert agent.address == derive_agent_address(AUDITOR_SEED) == service.address
    assert agent.address != WARDEN_ADDRESS
    proto = create_auditor_protocol(service)
    assert proto.name == AUDITOR_PROTOCOL_NAME
    assert AuditRequestWire in proto.models.values()


def test_build_refuses_to_start_with_wardens_seed(tmp_path):
    with pytest.raises(ConfigError):
        build_auditor_agent(cfg(tmp_path, seed=WARDEN_SEED), warden_seed=WARDEN_SEED)


def test_auditor_code_contains_no_mutating_filesystem_calls():
    forbidden = re.compile(
        r"\.(unlink|rmdir|rename|mkdir|write_text|write_bytes|touch|chmod|symlink_to)\(|"
        r"shutil\.|os\.(remove|rename|rmdir|mkdir|makedirs|unlink|chmod)\(|open\([^)]*['\"][wax+]"
    )
    for module in (service_module, view_module):
        text = Path(module.__file__).read_text(encoding="utf-8")
        assert not forbidden.search(text), module.__name__


def test_auditor_does_not_import_authority_modules():
    for module in (service_module, view_module):
        text = Path(module.__file__).read_text(encoding="utf-8")
        for banned in ("warden.security.policy", "warden.security.authorization", "warden.execution", "warden.agents"):
            assert banned not in text, (module.__name__, banned)
