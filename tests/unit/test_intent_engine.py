"""Unit tests for IntentEngine supporting ASI:One model integration and fallback."""

import json
from unittest.mock import MagicMock
import pytest
from warden.agents.intent_engine import IntentEngine
from warden.models import Action


def test_empty_query_returns_empty_actions():
    engine = IntentEngine()
    actions = engine.parse_intent("")
    assert actions == []


def test_deterministic_fallback_cleanup_with_context():
    engine = IntentEngine(api_key=None)
    context = {"available_files": ["cache.tmp", "temp.log", "production.env", "data.json"]}
    actions = engine.parse_intent("Clean up temporary files in project", context=context)

    assert len(actions) == 2
    targets = {a.target for a in actions}
    assert targets == {"cache.tmp", "temp.log"}
    for a in actions:
        assert a.operation == "DELETE"


def test_deterministic_fallback_create():
    engine = IntentEngine(api_key=None)
    actions = engine.parse_intent("Create report.txt with content 'Audit complete'")
    assert len(actions) == 1
    assert actions[0].operation == "CREATE"
    assert actions[0].target == "report.txt"
    assert actions[0].content == "Audit complete"


def test_deterministic_fallback_read():
    engine = IntentEngine(api_key=None)
    actions = engine.parse_intent("Read notes.txt")
    assert len(actions) == 1
    assert actions[0].operation == "READ"
    assert actions[0].target == "notes.txt"


def test_mocked_asi_one_llm_response():
    mock_client = MagicMock()
    mock_response = MagicMock()
    mock_response.choices = [
        MagicMock(
            message=MagicMock(
                content=json.dumps([
                    {
                        "operation": "DELETE",
                        "target": "obsolete.tmp",
                        "reason": "Purging temporary file",
                    },
                    {
                        "operation": "CREATE",
                        "target": "summary.txt",
                        "content": "Cleaned 1 file.",
                        "reason": "Log summary",
                    },
                ])
            )
        )
    ]
    mock_client.chat.completions.create.return_value = mock_response

    engine = IntentEngine(api_key="mock-key", client=mock_client)
    actions = engine.parse_intent("Please purge obsolete.tmp and make summary.txt")

    assert len(actions) == 2
    assert actions[0].operation == "DELETE"
    assert actions[0].target == "obsolete.tmp"
    assert actions[1].operation == "CREATE"
    assert actions[1].target == "summary.txt"
    assert actions[1].content == "Cleaned 1 file."


def test_mocked_asi_one_llm_markdown_fences():
    mock_client = MagicMock()
    mock_response = MagicMock()
    json_text = json.dumps([{"operation": "READ", "target": "README.md", "reason": "Check docs"}])
    mock_response.choices = [
        MagicMock(message=MagicMock(content=f"```json\n{json_text}\n```"))
    ]
    mock_client.chat.completions.create.return_value = mock_response

    engine = IntentEngine(api_key="mock-key", client=mock_client)
    actions = engine.parse_intent("Read README.md")

    assert len(actions) == 1
    assert actions[0].operation == "READ"
    assert actions[0].target == "README.md"


def test_mocked_asi_one_llm_error_falls_back():
    mock_client = MagicMock()
    mock_client.chat.completions.create.side_effect = RuntimeError("API rate limit / timeout")

    engine = IntentEngine(api_key="mock-key", client=mock_client)
    actions = engine.parse_intent("Clean up temporary cache.tmp")

    # Gracefully falls back to deterministic rule parser
    assert len(actions) >= 1
    assert actions[0].operation == "DELETE"
    assert actions[0].target == "cache.tmp"


def test_unrelated_openai_key_is_never_sent_to_asi_one(monkeypatch):
    """An OPENAI_API_KEY in the environment must not be picked up and forwarded to the ASI:One endpoint."""
    monkeypatch.setenv("OPENAI_API_KEY", "sk-unrelated-openai-key")
    engine = IntentEngine()
    assert engine.api_key is None and engine.client is None


def test_offline_engine_ignores_configured_key(monkeypatch):
    monkeypatch.setenv("ASI_ONE_API_KEY", "asi-test-key")
    engine = IntentEngine(offline=True)
    assert engine.api_key is None and engine.client is None


def test_deterministic_fallback_list_filenames_in_permitted_workspace():
    engine = IntentEngine(api_key=None)
    actions = engine.parse_intent("List the filenames in your permitted workspace")
    assert len(actions) == 1
    assert actions[0].operation == "READ"
    assert actions[0].target == "."
    assert "directory listing" in actions[0].reason.lower()


def test_deterministic_fallback_list_files_variations():
    engine = IntentEngine(api_key=None)
    for phrase in [
        "List files in workspace",
        "Show filenames",
        "Directory listing of permitted workspace",
        "What files are in the workspace?",
    ]:
        actions = engine.parse_intent(phrase)
        assert len(actions) == 1
        assert actions[0].operation == "READ"
        assert actions[0].target == "."

def test_intent_with_agent_mention_and_negative_constraints():
    engine = IntentEngine(api_key=None)
    prompt = (
        "@agent1q0kewgd2uyceeqrfn9jdln75nhwvfk7pmycaacqvcqm8qtxptsea6szeql7 "
        "List the filenames in your permitted workspace. Do not create, modify, rename, or delete anything."
    )
    actions = engine.parse_intent(prompt)
    assert len(actions) == 1
    assert actions[0].operation == "READ"
    assert actions[0].target == "."


def test_pure_negative_constraint_proposes_no_action():
    engine = IntentEngine(api_key=None)
    actions = engine.parse_intent("Do not create, modify, rename, or delete anything.")
    assert actions == []
