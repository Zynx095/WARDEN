"""Intent Agent: versioned, validated proposals; parser output is untrusted."""

from warden.agents.intent_agent import MAX_PROPOSALS_PER_REQUEST, PROPOSAL_SCHEMA, IntentAgent
from warden.agents.intent_engine import IntentEngine
from warden.models import Action


class FakeLLMEngine:
    """Stands in for a model that returns whatever it likes."""
    def __init__(self, actions):
        self.actions, self.last_source = actions, "llm"

    def parse_intent(self, text, context=None):
        return self.actions


def test_deterministic_proposals_are_versioned_and_name_their_target():
    batch = IntentAgent(IntentEngine(api_key=None)).propose("delete cache.tmp")
    (p,) = batch.proposals
    assert p.schema_version == PROPOSAL_SCHEMA and p.source == "deterministic"
    assert p.operation == "DELETE" and p.target == "cache.tmp" and p.target_named_by_user and not p.assumptions
    assert p.proposal_id == batch.actions[0].action_id and p.request_id == batch.request_id


def test_inferred_targets_are_recorded_as_assumptions():
    batch = IntentAgent(IntentEngine(api_key=None)).propose(
        "clean up temporary files", context={"available_files": ["cache.tmp", "README.txt"]})
    (p,) = batch.proposals
    assert not p.target_named_by_user and "inferred" in p.assumptions[0]


def test_malformed_model_output_is_dropped_with_reasons():
    bad = [Action(operation="EXECUTE", target="rm -rf /"), Action(operation="RENAME", target="a.txt"),
           Action(operation="DELETE", target="evil\x07.txt"), Action(operation="WRITE", target="x.txt", content="y" * 100001),
           Action(operation="read", target="README.txt")]
    batch = IntentAgent(FakeLLMEngine(bad)).propose("read README.txt")
    assert [p.operation for p in batch.proposals] == ["READ"] and batch.proposals[0].source == "llm"
    assert len(batch.rejected) == 4


def test_a_single_request_cannot_fan_out_without_limit():
    many = [Action(operation="DELETE", target=f"f{i}.tmp") for i in range(MAX_PROPOSALS_PER_REQUEST + 5)]
    batch = IntentAgent(FakeLLMEngine(many)).propose("delete everything")
    assert len(batch.actions) == MAX_PROPOSALS_PER_REQUEST and "dropped" in batch.rejected[0]


def test_proposals_carry_a_content_hash_not_the_content():
    batch = IntentAgent(FakeLLMEngine([Action(operation="CREATE", target="n.txt", content="secret")])).propose("x")
    assert "secret" not in batch.proposals[0].model_dump_json() and batch.proposals[0].content_length == 6


def test_a_request_for_a_path_outside_the_workspace_is_flagged_when_the_parser_narrows_it():
    batch = IntentAgent(IntentEngine(api_key=None)).propose(r"write ..\escape.txt with content 'x'")
    assert any("outside the workspace" in a for p in batch.proposals for a in p.assumptions)
