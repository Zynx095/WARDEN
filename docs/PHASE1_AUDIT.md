# WARDEN — Phase 1 Integration Audit: Agentverse, ACP & ASI:One

**Date:** 2026-10-22  
**Auditor:** Senior Software Engineer (AI Pair Programmer)  
**Branch:** master  
**Baseline Test Status:** 65/65 tests passing

---

## 1. Inspection Findings

### 1.1 uAgents & Agent Chat Protocol (ACP)
- **Library Version:** `uagents` 0.26.1 and `uagents-core` 0.4.12 installed in `.venv`.
- **Authoritative ACP Protocol:**
  - `uagents_core.contrib.protocols.chat` provides the official `chat_protocol_spec` with `name='AgentChatProtocol', version='0.3.0'`.
  - Protocol interactions:
    - Inbound: `ChatMessage(content=[TextContent(type="text", text="...")])`
    - Outbound: `ChatAcknowledgement(timestamp=..., acknowledged_msg_id=...)` followed by response `ChatMessage`.
  - Integrating this official protocol specification ensures immediate compatibility with the on-chain Almanac registry and ASI:One discovery routing.

### 1.2 ASI:One LLM API (`asi1-mini`)
- **API Endpoint:** `https://api.asi1.ai/v1/chat/completions` (OpenAI-compatible).
- **Default Model:** `asi1-mini` (fast, efficient structured intent parsing).
- **Integration Approach:**
  - Build `IntentEngine` utilizing the `openai` Python SDK (version 3.36.1 already in `.venv`).
  - Read `ASI_ONE_API_KEY`, `ASI_ONE_BASE_URL`, and `ASI_ONE_MODEL` from environment.
  - Provide a deterministic fallback rule parser when API keys are absent, ensuring offline tests and air-gapped environments function with 100% determinism.

### 1.3 Agentverse Registration & Mailbox
- **Mechanism:** `uagents.Agent(name=..., seed=..., mailbox=...)`.
- Connecting an agent to an Agentverse mailbox enables bi-directional communication with ASI:One without exposing open inbound HTTP ports on local development machines.

### 1.4 Preserving Foundation Security Invariants
- The LLM intent engine acts purely as an **untrusted action proposer**.
- `PolicyEngine`, `PathValidator`, and `AuthorizationManager` remain the sole authoritative decision-makers.
- No shell execution or raw code evaluation will be permitted.
- The executor and auditor continue to enforce workspace isolation and disk ground truth.
