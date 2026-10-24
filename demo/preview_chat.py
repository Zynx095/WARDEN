"""Print WARDEN's chat replies for every outcome, offline, on a throwaway synthetic workspace.

    .\\.venv\\Scripts\\python.exe demo\\preview_chat.py           text-only replies (cards off)
    .\\.venv\\Scripts\\python.exe demo\\preview_chat.py --cards   text plus the card payloads

Uses the real chat handler and pipeline; nothing outside a temporary directory is touched and
no network call is made. It shows what ASI:One receives, not how ASI:One renders it.
"""

from __future__ import annotations

import json
import re
import sys
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

from uagents_core.contrib.protocols.chat import ChatMessage, MetadataContent, TextContent

from warden.agents.intent_engine import IntentEngine
from warden.agents.warden_agent import WardenAgent
from warden.execution.workspace import Workspace
from warden.hosting.demo_workspace import prepare_demo_workspace
from warden.integrations.acp_adapter import WardenACPHandler

USER, OTHER = "agent1qpreviewuser", "agent1qpreviewother"


def main(argv: list[str]) -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    with_cards = "--cards" in argv
    with tempfile.TemporaryDirectory() as tmp:
        warden = WardenAgent(workspace=Workspace(prepare_demo_workspace(Path(tmp) / "ws")))
        handler = WardenACPHandler(warden=warden, intent_engine=IntentEngine(offline=True), approvers=[],
                                   interactive_cards=with_cards)

        def say(text: str, sender: str = USER) -> ChatMessage:
            return handler.process_chat_message(ChatMessage(content=[TextContent(type="text", text=text)]),
                                                sender=sender)[1]

        def show(label: str, reply: ChatMessage) -> ChatMessage:
            print("=" * 78, f"\n>> {label}\n")
            print(reply.content[0].text)
            for card in (c for c in reply.content if isinstance(c, MetadataContent)):
                kind = card.metadata["card_kind"] + (" (terminal)" if card.metadata.get("is_terminal") else "")
                print(f"\n[card: {kind}]\n" + json.dumps(json.loads(card.metadata["card_payload"]), indent=2,
                                                         ensure_ascii=False))
            return reply

        def decision(reply: ChatMessage, verb: str = "APPROVE") -> str:
            action_id, digest = re.search(r"APPROVE ([a-f0-9\-]{36}) ([a-f0-9]{64})", reply.content[0].text).groups()
            return f"{verb} {action_id} {digest}"

        show("create report.txt (allowed, verified)", say('create report.txt with content "Build complete"'))
        show("read production.env (blocked)", say("read production.env"))
        pending = show("delete cache.tmp (approval required)", say("delete cache.tmp"))
        show("approval by another sender (refused)", say(decision(pending), sender=OTHER))
        show("approval with the exact digest (verified)", say(decision(pending)))
        show("delete debug.log, then reject it", say(decision(say("delete debug.log"), "REJECT")))
        expiring = say("write README.txt with content \"replaced\"")
        action_id = decision(expiring).split()[1]
        warden.auth_manager.get_pending_approval(action_id).expires_at = datetime.now(timezone.utc) - timedelta(1)
        show("approval after the window closed (expired)", say(decision(expiring)))
        show("unsupported request (help)", say("what's the weather like today?"))
        show("several actions at once", say("delete report.txt and README.txt"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
