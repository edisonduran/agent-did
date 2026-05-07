# Agent-DID × Google A2A Integration

> **Roadmap item:** F2-02 — Google A2A proof-of-concept

Agent-DID as the identity layer for the [Google A2A (Agent-to-Agent)](https://google.github.io/A2A/) protocol. This integration provides DID-based cryptographic identity for A2A agent discovery, request signing, and mutual authentication.

## What This Solves

The A2A protocol is **auth-agnostic** — it defines how agents communicate (JSON-RPC 2.0 over HTTPS) and discover each other (AgentCards), but deliberately leaves authentication to the implementer. This creates a gap:

| A2A Gap | What Agent-DID Provides |
|---|---|
| No native cryptographic identity | DID anchored to the agent's model, prompt, and capabilities |
| AgentCard has no verifiable identity proof | DID fields embedded directly in the AgentCard |
| Request authenticity depends on external auth | Ed25519 HTTP Message Signatures on every JSON-RPC request |
| No standard for mutual agent authentication | DID-based verification of the counterparty agent |

## Features

- **DID-Enriched AgentCards** — generate A2A-compliant AgentCards with embedded DID, controller, and `http-signature-did` authentication scheme
- **Request Signing** — sign outgoing `tasks/send`, `tasks/get` requests using Agent-DID HTTP Signatures
- **Request Verification** — verify incoming signed requests using the sender's DID
- **JSON-RPC Helpers** — Pydantic models for A2A JSON-RPC 2.0 messages
- **Observability** — structured, sanitized event emission for signing, verification, and card generation
- **Secure Defaults** — sensitive fields redacted, private network targets blocked, extra config fields rejected

## Identity Composition Contract

The canonical A2A identity invariant for this repository is documented in [RFC-001-A2A-Identity-Composition-Contract.md](../../docs/RFC-001-A2A-Identity-Composition-Contract.md), co-drafted with APS during Public Review.

The contract defines how two identity surfaces compose:

- **Identity-at-rest**: the published AgentCard and its DID-published key material.
- **Identity-in-motion**: the per-request HTTP signature and its `keyid`.

An A2A verifier must treat those surfaces as a single trust boundary: the per-request signing key must compose with the AgentCard and DID document key material, and the signing key must be authorized for the operation context described in §6.3 of the contract.

Current integration behavior publishes DID-enriched AgentCards and signs/verifies A2A requests with Agent-DID HTTP signatures. The stricter SDK-level enforcement of §6.3 verification-relationship binding is tracked in [issue #34](https://github.com/edisonduran/agent-did/issues/34); the umbrella closure work for the composition contract remains tracked in [issue #30](https://github.com/edisonduran/agent-did/issues/30).

## Installation

```bash
cd integrations/a2a
python -m pip install -e ".[dev]"
```

Requires the Python SDK installed in dev mode:

```bash
cd sdk-python
python -m pip install -e ".[dev]"
```

## Quick Start

```python
from agent_did_sdk import AgentIdentity, AgentIdentityConfig, CreateAgentParams, InMemoryAgentRegistry
from agent_did_a2a import A2ASkill, create_agent_did_a2a_integration

# Create identity
AgentIdentity.set_registry(InMemoryAgentRegistry())
identity = AgentIdentity(AgentIdentityConfig(signer_address="0x..."))
runtime = await identity.create(
    CreateAgentParams(name="MyAgent", core_model="gpt-4.1", system_prompt="...")
)

# Create A2A integration
integration = create_agent_did_a2a_integration(
    agent_identity=identity,
    runtime_identity=runtime,
)

# Generate AgentCard for /.well-known/agent.json
card = integration.agent_card_json(
    agent_url="https://my-agent.example.com",
    skills=[A2ASkill(id="task-1", name="My Skill", description="Does something useful")],
)

# Sign an outgoing A2A request
signed = await integration.send_task(
    target_url="https://remote-agent.example.com/a2a",
    request_id=1,
    task_id="task-001",
    message={"role": "user", "parts": [{"type": "text", "text": "Hello"}]},
)

# Verify an incoming request
is_valid = await integration.verify_request(
    method="POST",
    url="https://my-agent.example.com/a2a",
    headers=incoming_headers,
    body=incoming_body,
)
```

## Examples

| Example | Description |
|---|---|
| [a2a_agent_did_discovery.py](examples/a2a_agent_did_discovery.py) | Agent publishes a DID-enriched AgentCard |
| [a2a_mutual_auth_demo.py](examples/a2a_mutual_auth_demo.py) | Two agents authenticate each other via DID HTTP Signatures |

## Running Tests

```bash
cd integrations/a2a
python -m pytest tests/ -q
```

Full quality gates:

```bash
python -m ruff check src/ tests/ examples/
python -m mypy src/
python -m pytest tests/ -q
```

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│  Agent A (Client)                                        │
│  ┌─────────────────────────────────────────────────┐    │
│  │ AgentDidA2AIntegration                           │    │
│  │  → build_agent_card() → /.well-known/agent.json │    │
│  │  → sign_request() → Signature + Signature-Input │    │
│  │  → send_task() → signed JSON-RPC POST           │    │
│  └─────────────────────┬───────────────────────────┘    │
├─────────────────────────┼───────────────────────────────┤
│         HTTPS + Ed25519 HTTP Message Signatures          │
├─────────────────────────┼───────────────────────────────┤
│  Agent B (Server)       ▼                                │
│  ┌─────────────────────────────────────────────────┐    │
│  │ AgentDidA2AIntegration                           │    │
│  │  → verify_request() → validate Signature header │    │
│  │  → resolve DID → fetch sender's public key      │    │
│  │  → ✓ authenticated → process A2A task           │    │
│  └─────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────┘
```

## How It Fits With A2A

This integration uses A2A's **authentication extension point**. The A2A spec expects an `authentication` field in the AgentCard with one or more schemes. Agent-DID adds `http-signature-did` as a scheme, meaning:

1. The AgentCard declares the agent's DID and authentication key
2. Outgoing requests include `Signature` and `Signature-Input` headers per IETF HTTP Message Signatures
3. The receiving agent resolves the sender's DID to obtain the public key
4. Signature verification proves request authenticity and integrity

This approach is **complementary** to OAuth 2.0, mTLS, or any other A2A auth scheme — agents can support multiple schemes simultaneously.

## License

[Apache-2.0](../../LICENSE)
