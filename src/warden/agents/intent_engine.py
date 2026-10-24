"""Intent interpretation engine translating natural language instructions into structured Action proposals."""

from __future__ import annotations

import json
import logging
import os
import re
from typing import Any, Dict, List, Optional
from warden.models import Action, ActionType

logger = logging.getLogger(__name__)

FILE_PATTERN = re.compile(r"(?:(?:\.\./|\./)+[\w\.-]+(?:/[\w\.-]+)*|[\w\.-]+(?:/[\w\.-]+)*\.[a-zA-Z0-9_-]+|\.[\w-]+)")

INTENT_SYSTEM_PROMPT = """You are WARDEN's Intent Interpreter.
Your job is to analyze the user's intent and translate it into a JSON array of discrete filesystem actions.

Supported operations:
- READ: inspect file contents or list directory contents (use target "." for workspace root)
- CREATE: create a new file
- WRITE: write content to a file
- DELETE: delete a file
- RENAME: rename a file (requires destination)

Rules:
1. Output MUST be a valid JSON array of objects, with NO surrounding markdown backticks.
2. Each object must have:
   - "operation": one of READ, CREATE, WRITE, DELETE, RENAME
   - "target": relative path
   - "destination": relative path (only for RENAME, otherwise null)
   - "content": string content (for CREATE or WRITE, otherwise null)
   - "reason": brief explanation
3. Do NOT make authorization decisions. You are solely proposing actions.
"""


class IntentEngine:
    """Interprets user intent using ASI:One / ASI1 LLM or deterministic fallback."""

    def __init__(
        self,
        api_key: Optional[str] = None,
        base_url: Optional[str] = None,
        model: Optional[str] = None,
        client: Optional[Any] = None,
        offline: bool = False,
    ) -> None:
        # offline=True forces the deterministic parser: no API key is read and no network call is made.
        self.offline = offline
        self.api_key = None if offline else (api_key or os.getenv("ASI_ONE_API_KEY"))
        self.base_url = base_url or os.getenv("ASI_ONE_BASE_URL", "https://api.asi1.ai/v1")
        self.model = model or os.getenv("ASI_ONE_MODEL", "asi1-mini")
        self._client = client

    @property
    def client(self) -> Optional[Any]:
        if self.offline:
            return None
        if self._client is not None:
            return self._client
        if not self.api_key:
            return None
        try:
            from openai import OpenAI
            self._client = OpenAI(base_url=self.base_url, api_key=self.api_key, timeout=15.0)
            return self._client
        except Exception as e:
            logger.warning(f"Failed to initialize OpenAI client for ASI:One: {e}")
            return None

    def parse_intent(self, text: str, context: Optional[Dict[str, Any]] = None) -> List[Action]:
        """Convert natural language query into proposed Action objects."""
        if not text or not text.strip():
            return []

        clean_text = re.sub(r"^\s*@\S+\s*", "", text)
        # Which parser produced the last result: "llm" or "deterministic" (read by the Intent Agent).
        self.last_source = "deterministic"

        # Attempt ASI:One LLM parsing if configured
        if self.client:
            try:
                actions = self._call_llm(clean_text, context)
                if actions:
                    self.last_source = "llm"
                    return self._deduplicate_actions(actions)
            except Exception as e:
                logger.warning(f"ASI:One LLM call failed, falling back to deterministic parser: {e}")

        # Deterministic fallback parser
        actions = self._deterministic_fallback(clean_text, context)
        return self._deduplicate_actions(actions)

    def _deduplicate_actions(self, actions: List[Action]) -> List[Action]:
        """Ensure no duplicate proposed actions for identical operation, target, and destination."""
        deduped: List[Action] = []
        seen = set()
        for a in actions:
            key = (
                a.operation.upper(),
                a.target.strip().lower(),
                (a.destination or "").strip().lower(),
                a.content or "",
            )
            if key not in seen:
                seen.add(key)
                deduped.append(a)
        return deduped

    def _call_llm(self, text: str, context: Optional[Dict[str, Any]] = None) -> List[Action]:
        """Call ASI:One chat completions endpoint."""
        prompt = f"User request: {text}"
        if context and "available_files" in context:
            prompt += f"\nWorkspace files present: {json.dumps(context['available_files'])}"

        response = self.client.chat.completions.create(
            model=self.model,
            messages=[
                {"role": "system", "content": INTENT_SYSTEM_PROMPT},
                {"role": "user", "content": prompt},
            ],
            temperature=0.0,
        )

        raw_content = response.choices[0].message.content or "[]"
        # Clean potential markdown fences
        clean_json = raw_content.strip()
        if clean_json.startswith("```"):
            clean_json = re.sub(r"^```(?:json)?\n", "", clean_json)
            clean_json = re.sub(r"\n```$", "", clean_json)

        data = json.loads(clean_json)
        if not isinstance(data, list):
            data = [data]

        actions: List[Action] = []
        for item in data:
            if isinstance(item, dict) and "operation" in item and "target" in item:
                actions.append(
                    Action(
                        operation=str(item["operation"]).upper(),
                        target=str(item["target"]),
                        destination=item.get("destination"),
                        content=item.get("content"),
                        reason=item.get("reason", f"Proposed by ASI:One ({self.model})"),
                    )
                )
        return actions

    def _deterministic_fallback(
        self, text: str, context: Optional[Dict[str, Any]] = None
    ) -> List[Action]:
        """Rule-based parser for offline execution and automated tests."""
        clean_text = re.sub(r"^\s*@\S+\s*", "", text)
        has_negative = bool(re.search(r"\b(?:do\s+not|don[\'\u2019]t|never|without|avoid)\b", clean_text, re.IGNORECASE))
        actionable_text = re.sub(
            r"\b(?:do\s+not|don[\'\u2019]t|never|without|avoid)\b.*?(?:[;!?]|\.(?:\s|$)|$)",
            "",
            clean_text,
            flags=re.IGNORECASE,
        ).strip()
        eval_text = actionable_text if (actionable_text or not has_negative) else ""
        lower = eval_text.lower()
        actions: List[Action] = []

        # Cleanup requests
        if "clean" in lower or "remove" in lower or "delete" in lower or "purge" in lower:
            files_to_clean: List[str] = []
            # Extract any explicitly named files in user text
            explicit_files = FILE_PATTERN.findall(eval_text)
            for ef in explicit_files:
                if ef not in files_to_clean:
                    files_to_clean.append(ef)

            # Discover temporary/cache files in workspace context only when no explicit files
            # were named or the user explicitly requested a broad/general temporary cleanup
            user_requested_general_cleanup = (
                not explicit_files
                or (
                    bool(re.search(r"\b(?:all|other|remaining)\b", lower))
                    and bool(re.search(r"\b(?:temp|temporary|cache|logs?)\b", lower))
                )
            )

            if user_requested_general_cleanup:
                if context and "available_files" in context:
                    for f in context["available_files"]:
                        if f.endswith((".tmp", ".log", ".bak", ".cache")) or "temp" in f or "cache" in f:
                            if f not in files_to_clean:
                                files_to_clean.append(f)
                elif not files_to_clean:
                    files_to_clean.extend(["cache.tmp", "temp.log"])

            for f in files_to_clean:
                actions.append(
                    Action(
                        operation="DELETE",
                        target=f,
                        reason="Rule-based cleanup proposal.",
                    )
                )

        # Create/write requests
        elif "create" in lower or "make" in lower or "write" in lower:
            matches = FILE_PATTERN.findall(eval_text)
            target = matches[0] if matches else "output.txt"
            content_match = re.search(r"with (?:content|text) ['\"](.*?)['\"]", eval_text)
            content = content_match.group(1) if content_match else "Default generated content."
            op = "WRITE" if "write" in lower else "CREATE"
            actions.append(
                Action(
                    operation=op,
                    target=target,
                    content=content,
                    reason=f"Rule-based file {op.lower()} proposal.",
                )
            )

        # Read requests
        elif ("read" in lower or "view" in lower or "inspect" in lower or "show" in lower or "list" in lower or "dir" in lower or "ls" in lower or "filename" in lower or "files" in lower):
            matches = FILE_PATTERN.findall(eval_text)
            if matches:
                target = matches[0]
                reason = "Rule-based file inspection proposal."
            elif any(k in lower for k in ("list", "dir", "ls", "filename", "files", "workspace")):
                target = "."
                reason = "Rule-based directory listing proposal."
            else:
                target = "README.md"
                reason = "Rule-based file inspection proposal."
            actions.append(
                Action(
                    operation="READ",
                    target=target,
                    reason=reason,
                )
            )

        return actions
