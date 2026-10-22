"""Intent interpretation engine translating natural language instructions into structured Action proposals."""

from __future__ import annotations

import json
import logging
import os
import re
from typing import Any, Dict, List, Optional
from warden.models import Action, ActionType

logger = logging.getLogger(__name__)

INTENT_SYSTEM_PROMPT = """You are WARDEN's Intent Interpreter.
Your job is to analyze the user's intent and translate it into a JSON array of discrete filesystem actions.

Supported operations:
- READ: inspect file contents
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

        # Attempt ASI:One LLM parsing if configured
        if self.client:
            try:
                actions = self._call_llm(text, context)
                if actions:
                    return actions
            except Exception as e:
                logger.warning(f"ASI:One LLM call failed, falling back to deterministic parser: {e}")

        # Deterministic fallback parser
        return self._deterministic_fallback(text, context)

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
        lower = text.lower()
        actions: List[Action] = []

        # Cleanup requests
        if "clean" in lower or "remove" in lower or "delete" in lower or "purge" in lower:
            files_to_clean: List[str] = []
            # Extract any explicitly named files in user text
            explicit_files = re.findall(r"(?:\.[\w-]+|[\w\.-]+\.[\w-]+)", text)
            for ef in explicit_files:
                if ef not in files_to_clean:
                    files_to_clean.append(ef)

            # Also identify temporary or cache files in workspace context
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
            matches = re.findall(r"(?:\.[\w-]+|[\w\.-]+\.[\w-]+)", text)
            target = matches[0] if matches else "output.txt"
            content_match = re.search(r"with (?:content|text) ['\"](.*?)['\"]", text)
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
        elif "read" in lower or "view" in lower or "inspect" in lower or "show" in lower:
            matches = re.findall(r"(?:\.[\w-]+|[\w\.-]+\.[\w-]+)", text)
            target = matches[0] if matches else "README.md"
            actions.append(
                Action(
                    operation="READ",
                    target=target,
                    reason="Rule-based file inspection proposal.",
                )
            )

        return actions
