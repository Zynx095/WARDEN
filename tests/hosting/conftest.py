"""Hosted mode requires an explicit approval mode and durable state; give hosting tests both."""

import pytest


@pytest.fixture(autouse=True)
def _hosted_required_settings(monkeypatch, tmp_path):
    monkeypatch.setenv("WARDEN_APPROVAL_MODE", "self")
    monkeypatch.setenv("WARDEN_STATE_DB", str(tmp_path / "hosted-state" / "warden.db"))
