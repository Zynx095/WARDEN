# WARDEN — Agent Identity Hardening and Endpoint Connectivity Audit

**Date:** 2026-10-23  
**Auditor:** Senior Software Engineer (AI Pair Programmer)  
**SDK Inspected:** `uagents` 0.26.1 / `uagents-core` 0.4.12 / Python 3.12.0 (win32)  
**Branch:** master  

> **Corrections (local readiness phase).** Two statements below were re-checked against the installed SDK source and are superseded by `docs/INTEGRATION.md`: (1) a "mailbox key" is not consumed by uAgents 0.26.1 (the key part of `key@url` is discarded); mailbox provisioning goes through the local inspector `/connect` endpoint with an Agentverse user token; (2) the SDK's embedded server binds `0.0.0.0` unconditionally and always sends a signed "active" status to the Almanac API at startup, so "zero open ports" applies only after WARDEN's loopback restriction. Details of the polling loop in §3.1 were not re-verified.

---

## 1. Executive Summary

This audit establishes the identity architecture, cryptographic key derivation, and network endpoint mechanisms supported by the installed `uagents` framework (v0.26.1). It identifies security risks associated with default seeds and defines the precise connectivity requirements for Agentverse onboarding and ASI:One discovery without exposing public ports.

---

## 2. Agent Identity Architecture in uAgents 0.26.1

### 2.1 Cryptographic Key Derivation
- In `uagents`, an agent's identity (`uagents.crypto.Identity`) is derived from a cryptographic seed phrase:
  - Default derivation algorithm uses SHA-256 / Ed25519 key derivation (`Identity.from_seed(seed, derivation_index)`).
  - The agent's address (`agent1q...`) is a Bech32-encoded string derived directly from the public key with the prefix `agent` (mainnet) or `test-agent` (testnet).
  - An agent's address is strictly deterministic: the same seed always yields the exact same address and cryptographic signing capability.

### 2.2 Critical Vulnerability: Predictable / Hardcoded Seeds
- **Audit Finding:** In early prototypes, `src/warden/agents/run_agent.py` fell back to a default string (`"warden_fetchathon_recovery_seed_2026"`).
- **Security Impact:**
  - Anyone with knowledge of the default seed can generate the agent's private key.
  - An attacker could impersonate the WARDEN agent on the Fetch.ai network, sign malicious messages, decrypt communications, or hijack its Agentverse registration.
- **Remediation:**
  - Remove all default seed fallbacks.
  - Fail closed with a custom `AgentIdentityError` if `AGENT_SEED` is not set in the environment or passed explicitly.
  - Enforce that seeds must never appear in logs, exceptions, terminal outputs, or Git commits.

### 2.3 Secret Hygiene & Git Exclusion
- When an agent initializes, the uAgents framework creates an internal keystore (`private_keys.json`) if persistent storage is active.
- Verified that `.gitignore` strictly excludes:
  - `.env` and `*.env` (except `.env.example`)
  - `private_keys.json`
  - `secrets.json`, `credentials.json`, `production.env`
  - Virtual environments (`.venv/`) and cache directories

---

## 3. Endpoint and Connectivity Architecture

In `uagents` 0.26.1, agents can receive incoming messages via two fundamentally different architectures:

| Feature | Architecture A: Mailbox-Based Connectivity (Recommended) | Architecture B: Direct Public Endpoint |
|---|---|---|
| **Inbound Network Requirement** | **None.** Zero open ports or public IPs required. | Requires public static IP, public DNS, or active HTTPS tunnel (e.g. ngrok). |
| **Firewall / NAT Compatibility** | Works seamlessly behind enterprise NATs, home routers, and developer laptops. | Blocked by default on standard consumer/enterprise networks. |
| **Message Retrieval Mechanism** | Outbound HTTPS polling (`GET /v1/agents/{address}/mailbox`) against Agentverse. | Inbound webhook HTTP POST (`POST /submit`) to agent's local port (e.g., 8000). |
| **Authentication** | Cryptographic attestation token (`Authorization: Agent <signature>`) signed by agent identity. | TLS certificate + message signature verification in envelope. |
| **Agentverse Discovery (ASI:One)** | Agent is registered on Agentverse; ASI:One routes messages to the Agentverse mailbox. | Agent registers endpoint URL on-chain on Fetch.ai Almanac contract. |
| **Gas / Ledger Fee** | Mailbox relay handled by Agentverse infrastructure. | Requires on-chain Almanac registration transactions (paying FET gas). |

### 3.1 Verified SDK Behavior for Mailbox Connectivity
Inspection of `uagents.agent` and `uagents.mailbox` reveals:
1. `parse_endpoint_config(endpoint, agentverse, mailbox, proxy)`:
   - When `mailbox=True` is passed to `Agent`, the agent registers `AgentEndpoint(url="https://agentverse.ai/v2/agents/mailbox/submit", weight=1)`.
   - `self._use_mailbox` is set to `True`.
   - `MailboxClient` is instantiated with the agent's identity and Agentverse configuration.
2. Polling Loop (`MailboxClient._check_mailbox_loop`):
   - Periodically polls `https://agentverse.ai/v1/agents/{identity.address}/mailbox`.
   - Passes `Authorization: Agent {attestation}`, where `attestation` is cryptographically signed using the agent's private key and refreshed every interval.
   - Envelopes are received, dispatched to protocol handlers (e.g., `AgentChatProtocol`), and acknowledged/deleted from the server.

### 3.2 Verified SDK Behavior for Agent Inspector & Onboarding
- When `enable_agent_inspector=True` (default), `uagents` serves a local REST endpoint (`/connect` taking `AgentverseConnectRequest`):
  - Used to authenticate to Agentverse via user token (`Bearer <user_token>`).
  - Proves agent identity via challenge-response (`IdentityProof` signed by the agent).
  - Automatically provisions the mailbox on Agentverse for that specific agent address.

---

## 4. Phase 2B Onboarding Requirements (Pre-Deployment Checklist)

For Phase 2B external registration:
1. **Operator must generate a high-entropy seed:**
   - E.g., a 24-word BIP39 mnemonic or a 64-character random hex string.
   - Set in `.env`: `AGENT_SEED=<secure_seed_phrase>`.
2. **Deterministic Agent Address Verification:**
   - Run `.\scripts\run.ps1 -ShowAddress` (equivalently `python -m warden.agents.run_agent --show-address`) to print only the public address without starting the server. *(Corrected: an earlier revision of this document referred to a `--dry-run` flag that never existed.)*
3. **Agentverse Mailbox Provisioning:**
   - In Agentverse dashboard, add the verified `agent1q...` address to establish the mailbox route.
4. **Almanac & ASI:One Discoverability:**
   - Once the mailbox is active on Agentverse, the agent is visible in the Almanac and callable via ASI:One chat.
