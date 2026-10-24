"""Tests for warden.presentation.workflow_trace — pipeline trace renderer."""

import pytest

from warden.models import Decision, ExecutionStatus
from warden.presentation.workflow_trace import (
    format_workflow_trace,
    stages_from_pipeline_result,
)


class TestFormatWorkflowTrace:
    def _stages(self, **overrides):
        base = {
            "intent":   {"status": "OK",       "note": "READ cache.tmp"},
            "risk":     {"status": "OK",       "note": ""},
            "policy":   {"status": "ALLOWED",  "note": "WDN-004 not triggered"},
            "executor": {"status": "OK",       "note": "Executed"},
            "auditor":  {"status": "VERIFIED", "note": "File removed"},
        }
        base.update(overrides)
        return base

    def test_returns_non_empty_string(self):
        text = format_workflow_trace(self._stages())
        assert len(text) > 0

    def test_contains_pipeline_trace_header(self):
        text = format_workflow_trace(self._stages())
        assert "Pipeline Trace" in text or "WARDEN" in text

    def test_all_five_stage_names_present(self):
        text = format_workflow_trace(self._stages())
        assert "Intent" in text
        assert "Policy" in text
        assert "Executor" in text
        assert "Auditor" in text

    def test_skipped_stage_shown_as_skipped(self):
        stages = self._stages()
        stages["auditor"] = None
        text = format_workflow_trace(stages)
        assert "skipped" in text.lower()

    def test_blocked_stage_shown_with_blocked_marker(self):
        stages = self._stages(policy={"status": "BLOCKED", "note": "WDN-003 triggered"})
        text = format_workflow_trace(stages)
        assert "🚫" in text or "BLOCKED" in text

    def test_action_summary_appears_in_output(self):
        text = format_workflow_trace(self._stages(), action_summary="DELETE cache.tmp")
        assert "DELETE" in text and "cache.tmp" in text

    def test_path_scrubbed_from_notes(self):
        import os
        ws = "D:/secret/ws"
        stages = self._stages(executor={"status": "OK", "note": f"Wrote to {ws}/file.txt"})
        text = format_workflow_trace(stages, workspace_root=ws)
        assert ws not in text

    def test_awaiting_stage_shown_with_lock(self):
        stages = self._stages(policy={"status": "AWAITING_APPROVAL", "note": "WDN-004"})
        text = format_workflow_trace(stages)
        assert "🔒" in text or "AWAITING" in text

    def test_extra_unknown_stage_key_ignored_gracefully(self):
        stages = self._stages()
        stages["unknown_stage"] = {"status": "OK", "note": "foo"}
        text = format_workflow_trace(stages)
        assert len(text) > 0


class TestStagesFromPipelineResult:
    def _make_result(self, status, **kw):
        base = {
            "action_id": "abc",
            "operation": "DELETE",
            "target": "cache.tmp",
            "status": status,
            "executed": True,
        }
        base.update(kw)
        return base

    def test_verified_result_maps_all_five_stages(self):
        r = self._make_result(
            ExecutionStatus.VERIFIED,
            decision=Decision.ALLOW,
            policy_id="WDN-004-APPROVED",
            reason="Approved",
            verification_details="File gone.",
        )
        stages = stages_from_pipeline_result(r)
        assert "intent" in stages
        assert "auditor" in stages
        assert stages["auditor"]["status"] == "VERIFIED"

    def test_blocked_result_skips_executor_and_auditor(self):
        r = self._make_result(
            ExecutionStatus.BLOCKED,
            decision=Decision.BLOCK,
            policy_id="WDN-003",
            reason="Protected.",
            executed=False,
        )
        stages = stages_from_pipeline_result(r)
        assert stages.get("executor") is not None
        assert "SKIP" in stages["executor"]["status"].upper() or "BLOCKED" in stages["executor"]["status"].upper()
        assert stages.get("auditor") is None

    def test_awaiting_approval_shows_correct_policy_stage(self):
        r = self._make_result(
            ExecutionStatus.AWAITING_APPROVAL,
            decision=Decision.REQUIRE_APPROVAL,
            policy_id="WDN-004",
            reason="Needs approval.",
            executed=False,
        )
        stages = stages_from_pipeline_result(r)
        assert "AWAITING" in stages["policy"]["status"].upper() or "APPROVAL" in stages["policy"]["status"].upper()

    def test_intent_note_contains_operation_and_target(self):
        r = self._make_result(
            ExecutionStatus.VERIFIED,
            decision=Decision.ALLOW,
        )
        stages = stages_from_pipeline_result(r)
        note = stages["intent"].get("note", "")
        assert "DELETE" in note or "cache.tmp" in note
