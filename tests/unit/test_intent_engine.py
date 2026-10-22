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
