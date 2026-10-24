"""Native Fetch.ai Agent Chat Protocol (ACP) adapter for WARDEN.

Implements the official AgentChatProtocol (v0.3.0) using uagents_core.
Translates incoming conversational messages into WARDEN action requests,
enforces deterministic security policies, and returns verified responses.
"""

from __future__ import annotations

import json
import logging
import os
import re
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple
from uagents import Context, Protocol
from uagents_core.contrib.protocols.chat import (
    ChatAcknowledgement,
    ChatMessage,
    MetadataContent,
    TextContent,
    chat_protocol_spec,
)
from warden.agents.intent_agent import IntentAgent
from warden.agents.intent_engine import IntentEngine
from warden.agents.warden_agent import WardenAgent
from warden.config import ConfigError, env_bool, get_config
from warden.integrations.cards import (
    CardResponseError,
    CardValidationError,
    build_result_card,
    cards_for_results,
    parse_card_decision,
    risk_text,
    validate_card_metadata,
)
from warden.models import Action, Decision, ExecutionStatus
from warden.presentation.reports import format_decision_report, format_no_action, format_pipeline_report

logger = logging.getLogger(__name__)

MAX_MESSAGE_CHARS = 4000
DUPLICATE_AFTER_RESTART = (
    "[WARDEN] This message was already processed. Nothing was run again. "
    "Send a new message to make a new request."
)

# "APPROVE|REJECT <action_id> <action digest>": the operator echoes the digest shown in the prompt.
DECISION_PATTERN = re.compile(
    r"^\s*(APPROVE|REJECT)\s+([a-f0-9\-]+)(?:\s+([a-f0-9]{16,64}))?", re.IGNORECASE
)


def _display(value: Any, limit: int = 200) -> str:
    """Render untrusted text safely inside a single-line markdown code span."""
    text = "".join(ch for ch in str(value) if ch.isprintable() and ch != "`")
    return text[:limit]


def _status_label(status: Any) -> str:
    return status.value if isinstance(status, ExecutionStatus) else str(status)


class WardenACPHandler:
    """Processes incoming Agent Chat Protocol messages through WARDEN's verification core."""

    def __init__(
        self,
        warden: WardenAgent,
        intent_engine: Optional[IntentEngine] = None,
        approvers: Optional[Iterable[str]] = None,
        interactive_cards: Optional[bool] = None,
        approval_mode: Optional[str] = None,
    ) -> None:
        self.warden = warden
        self.intent_engine = intent_engine or IntentEngine()
        self.intent_agent = IntentAgent(self.intent_engine)
        # ASI:One Interactive Cards (presentation only). Off unless enabled; the hosted entry point enables it.
        self.interactive_cards = (
            interactive_cards if interactive_cards is not None else env_bool("WARDEN_INTERACTIVE_CARDS", False)
        )
        # Senders allowed to approve actions requested by others (WARDEN_APPROVER_ADDRESSES).
        # By default only the sender that requested an action may approve it.
        if approvers is None:
            approvers = [a for a in os.getenv("WARDEN_APPROVER_ADDRESSES", "").split(",")]
        self.approvers: Set[str] = {a.strip() for a in approvers if a and a.strip()}
        # "self": requester or a configured approver decides. "independent": only a configured
        # approver other than the requester may approve (the requester may still reject).
        self.approval_mode = (approval_mode or get_config().approval_mode).strip().lower()
        if self.approval_mode not in ("self", "independent"):
            raise ConfigError("approval_mode must be 'self' or 'independent'.")
        # action_id -> sender that caused the approval request; only that sender may approve it.
        self._approval_owners: Dict[str, str] = {}
        # Bounded message deduplication cache: (sender, msg_id) -> (ack, reply).
        # Scoped per sender so one peer can neither read another peer's cached reply nor
        # suppress its messages by reusing a message id.
        self._processed_messages: Dict[Tuple[str, str], Tuple[ChatAcknowledgement, ChatMessage]] = {}

    def _scrub(self, text: Any) -> str:
        """Remove local filesystem locations from text sent back to a remote chat peer."""
        out = str(text)
        root = self.warden.workspace.root_path
        for variant in {str(root), root.as_posix(), str(root).replace("\\", "\\\\")}:
            out = out.replace(variant, "<workspace>")
        return out

    def _message(self, text: str, cards: Iterable[Optional[MetadataContent]] = ()) -> ChatMessage:
        """Reply with the text report first (always readable) and, if enabled, protocol-valid cards."""
        content: List[Any] = [TextContent(type="text", text=text)]
        if self.interactive_cards:
            for card in cards:
                if card is None:
                    continue
                metadata = {k: self._scrub(v) for k, v in card.metadata.items()}
                try:
                    validate_card_metadata(metadata)
                except CardValidationError as exc:  # never send a card that breaks the protocol
                    logger.error("Dropping invalid card: %s", exc)
                    continue
                content.append(MetadataContent(metadata=metadata))
        return ChatMessage(content=content)

    def process_chat_message(
        self,
        msg: ChatMessage,
        sender: str = "asi1_user",
    ) -> Tuple[ChatAcknowledgement, ChatMessage]:
        """Process an incoming ACP ChatMessage; never raises, always returns an acknowledgement and reply.

        Guarantees idempotent delivery: duplicate messages with identical msg_id return the
        cached response without re-executing any action or creating duplicate approval proposals.
        """
        msg_id_key = (str(sender), str(msg.msg_id)) if getattr(msg, "msg_id", None) else None
        if msg_id_key and msg_id_key in self._processed_messages:
            logger.info("Duplicate ACP message %s received from %s; returning cached response", msg_id_key[1], sender)
            return self._processed_messages[msg_id_key]
        store = getattr(self.warden, "state_store", None)
        if msg_id_key and store is not None and store.get_reply(*msg_id_key) is not None:
            # Processed before a restart. The original reply is not kept on disk (it may hold read
            # output), so the sender gets a notice and nothing runs again.
            logger.info("Duplicate ACP message %s from %s was processed before a restart", msg_id_key[1], sender)
            ack = ChatAcknowledgement(timestamp=msg.timestamp, acknowledged_msg_id=msg.msg_id)
            return ack, ChatMessage(content=[TextContent(type="text", text=store.get_reply(*msg_id_key))])

        try:
            ack, reply = self._process_chat_message(msg, sender)
        except Exception as exc:  # fail closed: report a generic error, log only the type
            logger.error("ACP message handling failed: %s", type(exc).__name__)
            ack = ChatAcknowledgement(timestamp=msg.timestamp, acknowledged_msg_id=msg.msg_id)
            reply = ChatMessage(content=[TextContent(
                type="text",
                text="[WARDEN] The request could not be processed safely. No action was taken.",
            )])

        if msg_id_key:
            if len(self._processed_messages) >= 1000:
                self._processed_messages.pop(next(iter(self._processed_messages)))
            self._processed_messages[msg_id_key] = (ack, reply)
            if store is not None:
                store.put_reply(*msg_id_key, DUPLICATE_AFTER_RESTART)

        return ack, reply

    def _process_chat_message(
        self,
        msg: ChatMessage,
        sender: str,
    ) -> Tuple[ChatAcknowledgement, ChatMessage]:
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

        if len(user_text) > MAX_MESSAGE_CHARS:
            reply_text = (
                f"[WARDEN] Message rejected: {len(user_text)} characters exceeds the "
                f"{MAX_MESSAGE_CHARS} character limit. No action was taken."
            )
            return ack, ChatMessage(content=[TextContent(type="text", text=reply_text)])

        # 3. Human decision typed in the conversation: "APPROVE|REJECT <action_id> <digest>"
        clean_user_text = re.sub(r"^\s*@\S+\s*", "", user_text)
        decision_match = DECISION_PATTERN.search(clean_user_text)
        if decision_match:
            decision = decision_match.group(1).upper()
            action_id = decision_match.group(2).strip()
            return ack, self._decision_reply(decision, action_id, decision_match.group(3), sender)

        # 3b. Interactive-card button press: same authority as the typed command, same decision path.
        if self.interactive_cards:
            try:
                card_decision = parse_card_decision(clean_user_text)
            except CardResponseError as exc:
                logger.warning("Refused a card response from %s: %s", sender[:16], exc)
                return ack, self._message(f"[WARDEN] {exc}")
            if card_decision is not None:
                return ack, self._decision_reply(
                    card_decision.decision, card_decision.action_id, card_decision.digest, sender
                )

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
        batch = self.intent_agent.propose(user_text, context=context)
        proposed_actions = batch.actions
        if batch.rejected:
            logger.warning("Dropped %d invalid proposal(s) for a request from %s", len(batch.rejected), sender[:16])

        if not proposed_actions:
            # The user's text is echoed sanitized and bounded, never raw.
            return ack, ChatMessage(content=[TextContent(type="text", text=self._scrub(format_no_action(user_text)))])

        # 5. Evaluate and execute proposed actions through WARDEN's pipeline
        results: List[Dict[str, Any]] = []
        self._prune_approval_owners()
        independent = self.approval_mode == "independent"
        for action, proposal in zip(proposed_actions, batch.proposals):
            # Bind who may decide into the pending record itself, so every decision channel is held to it.
            res = self.warden.handle_action_request(
                action,
                authorized_approvers=set(self.approvers) if independent else {sender} | self.approvers,
                request_text=user_text, batch_size=len(proposed_actions),
                requester=sender, independent_approval=independent,
                proposal=proposal.audit_metadata(),
            )
            if res.get("status") == ExecutionStatus.AWAITING_APPROVAL:
                self._approval_owners[res.get("pending_id", action.action_id)] = sender
            results.append(res)

        # 6. Format structured conversational response
        reply_text = self._scrub(self._format_pipeline_response(user_text, results))
        return ack, self._message(reply_text, cards_for_results(results) if self.interactive_cards else ())

    def _prune_approval_owners(self) -> None:
        """Forget owners of approvals that are no longer pending (expired, used or invalidated)."""
        for aid in [a for a in self._approval_owners if self.warden.auth_manager.get_pending_approval(a) is None]:
            del self._approval_owners[aid]

    def decide(self, decision: str, action_id: str, supplied_digest: Optional[str], sender: str) -> Dict[str, Any]:
        """Apply one human decision through the core pipeline and return its structured result.

        This is the only decision path: typed commands and interactive-card selections both use it.
        It never executes anything itself; approval goes through ``WardenAgent.approve_and_execute``.
        """
        owner = self._approval_owners.get(action_id)
        if owner is not None and owner != sender and sender not in self.approvers:
            logger.warning("Decision attempt by a sender that did not request action %s", action_id[:8])
            return {"action_id": action_id, "status": ExecutionStatus.FAILED, "executed": False, "verified": False,
                    "refused": True,
                    "error": "only the requester or a configured approver may approve it. No action was taken."}
        if supplied_digest is None and self.warden.auth_manager.get_pending_approval(action_id) is not None:
            return {"action_id": action_id, "status": ExecutionStatus.FAILED, "executed": False, "verified": False,
                    "refused": True,
                    "error": "the action digest is required so that you approve exactly what was shown. Reply "
                             f"`{decision} <action_id> <digest>` using the full command from the approval request. "
                             "No action was taken."}
        if decision == "REJECT":
            return self.warden.reject_pending(action_id=action_id, approver_id=sender, expected_digest=supplied_digest)
        return self.warden.approve_and_execute(action_id=action_id, approver_id=sender, expected_digest=supplied_digest)

    def _decision_reply(self, decision: str, action_id: str, supplied_digest: Optional[str], sender: str) -> ChatMessage:
        result = self.decide(decision, action_id, supplied_digest, sender)
        text = self._scrub(self._format_approval_response(action_id, result))
        return self._message(text, [build_result_card(result)] if self.interactive_cards else ())

    def _format_approval_response(self, action_id: str, res: Dict[str, Any]) -> str:
        """Text for an approve/reject decision (presentation only; see warden.presentation.reports)."""
        return format_decision_report(action_id, res)

    def _format_pipeline_response(self, prompt: str, results: List[Dict[str, Any]]) -> str:
        """Text for a new request: one block per proposed action, with its trace."""
        return format_pipeline_report(prompt, results)



def create_acp_protocol(
    warden: WardenAgent,
    intent_engine: Optional[IntentEngine] = None,
    interactive_cards: Optional[bool] = None,
    approval_mode: Optional[str] = None,
) -> Protocol:
    """Create a uAgents Protocol implementing the official Agent Chat Protocol."""
    proto = Protocol(spec=chat_protocol_spec)
    handler = WardenACPHandler(warden=warden, intent_engine=intent_engine, interactive_cards=interactive_cards,
                               approval_mode=approval_mode)

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
