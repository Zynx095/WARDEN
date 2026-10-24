"""WARDEN presentation layer: badges, safe text, conversational reports and workflow traces.

Pure presentation. Nothing here makes a security decision, evaluates policy, touches the
filesystem or authorizes anything; it formats results the backend has already produced.
Interactive Card payloads are built in ``warden.integrations.cards``.

Imported from ``feature/warden-uiux`` (badges, sanitize, reports, workflow_trace) and
adapted to the canonical backend results. That branch's ``adapter`` and ``card_builders``
were not imported: they depend on the non-canonical ``warden.cards`` validator and schema.
"""
