"""Native Fetch.ai Agent Chat Protocol (ACP) adapter for WARDEN.

Implements the official AgentChatProtocol (v0.3.0) using uagents_core.
Translates incoming conversational messages into WARDEN action requests,
enforces deterministic security policies, and returns verified responses.
"""

from __future__ import annotations

import json
import logging
import re
from typing import Any, Dict, List, Optional, Tuple
from uagents import Context, Protocol
from uagents_core.contrib.protocols.chat import (
    ChatAcknowledgement,
    ChatMessage,
    TextContent,
    chat_protocol_spec,
)
from warden.agents.intent_engine import IntentEngine
from warden.agents.warden_agent import WardenAgent
from warden.models import Action, Decision, ExecutionStatus

logger = logging.getLogger(__name__)


class WardenACPHandler:
    """Processes incoming Agent Chat Protocol messages through WARDEN's verification core."""

    def __init__(
        self,
        warden: WardenAgent,
        intent_engine: Optional[IntentEngine] = None,
    ) -> None:
        self.warden = warden
        self.intent_engine = intent_engine or IntentEngine()

    def process_chat_message(
        self,
        msg: ChatMessage,
        sender: str = "asi1_user",
    ) -> Tuple[ChatAcknowledgement, ChatMessage]:
        """Synchronously process an incoming ACP ChatMessage and generate response messages."""
        # 1. Immediately formulate ChatAcknowledgement
        ack = ChatAcknowledgement(
            timestamp=msg.timestamp,
            acknowledged_msg_id=msg.msg_id,
        )

        # 2. Extract textual content
        user_text = ""
        for item in msg.content:
            if isinstance(item, TextContent):
                user_text += item.text + " "
            elif isinstance(item, dict) and item.get("type") == "text":
                user_text += item.get("text", "") + " "
        user_text = user_text.strip()

        if not user_text:
            reply_text = (
                "WARDEN: Received empty message. Please provide an instruction "
                "(e.g., 'Clean up temporary files in workspace' or 'Read README.md')."
            )
            return ack, ChatMessage(content=[TextContent(type="text", text=reply_text)])

        # 3. Check for human approval command in conversation: "APPROVE <action_id>"
        approval_match = re.search(r"^\s*APPROVE\s+([a-f0-9\-]+)", user_text, re.IGNORECASE)
        if approval_match:
            action_id = approval_match.group(1).strip()
            approval_result = self.warden.approve_and_execute(action_id=action_id, approver_id=sender)
            reply_text = self._format_approval_response(action_id, approval_result)
            return ack, ChatMessage(content=[TextContent(type="text", text=reply_text)])

        # 4. Interpret intent into candidate Action proposals
        # Gather context of files in current workspace sandbox
        available_files: List[str] = []
        if self.warden.workspace.root_path.exists():
            try:
                available_files = [
                    f.name for f in self.warden.workspace.root_path.iterdir()
                    if not f.name.startswith(".git")
                ]
            except OSError:
                pass

        context = {"available_files": available_files, "sender": sender}
        proposed_actions = self.intent_engine.parse_intent(user_text, context=context)

        if not proposed_actions:
            reply_text = (
                "WARDEN Active Defense Agent:\n"
                f"Understood request: '{user_text}'\n"
                "No filesystem mutations or tool operations were proposed for this input.\n"
                "Available operations: READ, CREATE, WRITE, DELETE, RENAME."
            )
            return ack, ChatMessage(content=[TextContent(type="text", text=reply_text)])

        # 5. Evaluate and execute proposed actions through WARDEN's pipeline
        results: List[Dict[str, Any]] = []
        for action in proposed_actions:
            res = self.warden.handle_action_request(action)
            results.append(res)

        # 6. Format structured conversational response
        reply_text = self._format_pipeline_response(user_text, results)
        return ack, ChatMessage(content=[TextContent(type="text", text=reply_text)])

    def _format_approval_response(self, action_id: str, res: Dict[str, Any]) -> str:
        """Format the response after a human approval decision."""
        if res.get("status") == ExecutionStatus.VERIFIED:
            return (
                f"[WARDEN] Action Approval Execution Verified\n"
                f"- Action ID: `{action_id}`\n"
                f"- Status: `VERIFIED`\n"
                f"- Execution: Successfully executed.\n"
                f"- Physical Verification: {res.get('verification_details')}\n"
            )
        else:
            return (
                f"[WARDEN] Action Approval Execution Failed\n"
                f"- Action ID: `{action_id}`\n"
                f"- Status: `{res.get('status')}`\n"
                f"- Error: {res.get('error')}\n"
            )

    def _format_pipeline_response(self, prompt: str, results: List[Dict[str, Any]]) -> str:
        """Format structured verification details for ASI:One chat."""
        lines = [
            f"[WARDEN] Action Verification Report",
            f"Query: \"{prompt}\"",
            f"Evaluated {len(results)} proposed operation(s):\n",
        ]

        for idx, r in enumerate(results, 1):
            status = r.get("status")
            action_id = r.get("action_id", "unknown")

            if status == ExecutionStatus.VERIFIED:
                lines.append(
                    f"**{idx}. [VERIFIED]** Action `{action_id[:8]}`\n"
                    f"   - **Result:** Successfully executed and ground-truth verified.\n"
                    f"   - **Details:** {r.get('verification_details')}"
                )
            elif status == ExecutionStatus.BLOCKED:
                lines.append(
                    f"**{idx}. [BLOCKED]** Action `{action_id[:8]}`\n"
                    f"   - **Policy:** `{r.get('policy_id')}`\n"
                    f"   - **Reason:** {r.get('reason')}\n"
                    f"   - **Security Guarantee:** Prohibited operation was blocked before execution."
                )
            elif status == ExecutionStatus.AWAITING_APPROVAL:
                pending_id = r.get("pending_id", action_id)
                lines.append(
                    f"**{idx}. [AWAITING APPROVAL]** Action `{action_id[:8]}`\n"
                    f"   - **Policy:** `{r.get('policy_id')}` (Destructive Action)\n"
                    f"   - **Reason:** {r.get('reason')}\n"
                    f"   - **Action Required:** Operation paused. Reply with:\n"
                    f"     `APPROVE {pending_id}` to authorize execution."
                )
            else:
                lines.append(
                    f"**{idx}. [FAILED]** Action `{action_id[:8]}`\n"
                    f"   - **Error:** {r.get('error', 'Execution or verification failed.')}"
                )

        return "\n".join(lines)


def create_acp_protocol(
    warden: WardenAgent,
    intent_engine: Optional[IntentEngine] = None,
) -> Protocol:
    """Create a uAgents Protocol implementing the official Agent Chat Protocol."""
    proto = Protocol(spec=chat_protocol_spec)
    handler = WardenACPHandler(warden=warden, intent_engine=intent_engine)

    @proto.on_message(model=ChatMessage)
    async def handle_message(ctx: Context, sender: str, msg: ChatMessage):
        ctx.logger.info(f"Received ACP ChatMessage from {sender}")
        ack, reply = handler.process_chat_message(msg, sender=sender)
        await ctx.send(sender, ack)
        await ctx.send(sender, reply)
        ctx.logger.info(f"Sent ACP response to {sender}")

    @proto.on_message(model=ChatAcknowledgement)
    async def handle_acknowledgement(ctx: Context, sender: str, ack: ChatAcknowledgement):
        ctx.logger.info(f"Received ACP ChatAcknowledgement from {sender} for msg {ack.acknowledged_msg_id}")

    return proto
