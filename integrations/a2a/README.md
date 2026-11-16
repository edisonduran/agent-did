# Agent-DID × Google A2A Integration

> **Roadmap item:** F2-02 — Google A2A proof-of-concept

Agent-DID as the identity layer for the [A2A (Agent2Agent)](https://a2a-protocol.org/) protocol, version 1.0 (specification v1.0.1). This integration provides DID-based cryptographic identity for A2A agent discovery, request signing, and mutual authentication.

## What This Solves

The A2A protocol is **auth-agnostic** — it defines how agents communicate (JSON-RPC 2.0 over HTTPS) and discover each other (Agent Cards), and declares authentication through standard schemes (OAuth 2.0, OpenID Connect, API keys, mTLS) without a per-agent cryptographic identity. This creates a gap:

| A2A Gap | What Agent-DID Provides |
|---|---|
| No native cryptographic identity | DID anchored to the agent's model, prompt, and capabilities |
| Agent Card has no identity bound to a DID | Agent-DID extension in `capabilities.extensions` and an A2A §8.4 card signature by a DID key |
| Request authenticity depends on external auth | Ed25519 HTTP Message Signatures on every JSON-RPC request |
| No standard for mutual agent authentication | DID-based verification of the counterparty agent |

## Features

- **A2A 1.0 Agent Cards** — `supportedInterfaces` (JSON-RPC, protocol version `1.0`), skills, capabilities, `securitySchemes`; the agent's identity goes in the Agent-DID extension (`https://agent-did.org/a2a/identity/v1`, `params.did` and `params.keyIds`), marked `required` when `require_signed_requests=True`
- **OAuth client credentials scheme** — optional `oauth2SecurityScheme` (`clientCredentials`) for authorization servers that accept DID client assertions (`AgentDidA2AOAuthClientCredentials`)
- **Request Signing** — sign outgoing `SendMessage` / `GetTask` requests using Agent-DID HTTP Signatures, with `A2A-Version: 1.0` and `A2A-Extensions` naming the Agent-DID extension
- **Request Verification** — verify incoming signed requests using the sender's DID
- **Signed AgentCards** — sign the card for the identity composition contract (A2A 1.0 §8.4 JWS) and check incoming requests against the sender's signed card
- **JSON-RPC Helpers** — Pydantic models for JSON-RPC 2.0 and the A2A 1.0 `Message`, `Part` and `Task` objects (`text_message`, `parse_send_message_result`)
- **Observability** — structured, sanitized event emission for signing, verification, and card generation
- **Secure Defaults** — sensitive fields redacted, private network targets blocked, extra config fields rejected

## Identity Composition Contract

The canonical A2A identity invariant for this repository is documented in [RFC-001-A2A-Identity-Composition-Contract.md](../../docs/RFC-001-A2A-Identity-Composition-Contract.md), co-drafted with APS during Public Review.

The contract defines how two identity surfaces compose:

- **Identity-at-rest**: the published AgentCard and its DID-published key material.
- **Identity-in-motion**: the per-request HTTP signature and its `keyid`.

An A2A verifier must treat those surfaces as a single trust boundary: the per-request signing key must compose with the AgentCard and DID document key material, and the signing key must be authorized for the operation context described in §6.3 of the contract.

The integration implements the contract with the SDK:

- `signed_agent_card_json(agent_url=...)` returns the card with an Agent-DID extension in `capabilities.extensions` (the agent DID and the keys it publishes: the signing key and the other active `assertionMethod` keys) and a `signatures` entry by the signing key. The signature follows A2A 1.0 §8.4 (JWS, `EdDSA`, over the RFC 8785 form of the card without `signatures` and without default values, §8.4.1). The tests cross-check it with the official A2A Python SDK (`a2a-sdk` 1.3): `a2a-sdk` verifies the cards this integration signs, and the SDK verifies cards `a2a-sdk` signs. `a2a-sdk` 1.3 also drops empty `REQUIRED` members and empty messages before it verifies; the cards built here never contain them.
- `verify_request_against_card(..., agent_card=card)` verifies the card's signatures, the request's HTTP signature, and that the request's `keyid` is a key the card publishes. A rejection carries the contract `reason` (`rotation_window_closed`, `emergency_revoked`, `key_purpose_violation`, `tampered`, `card_keyid_mismatch`, `format_drift`, `did_document_unresolvable`, `request_rejected`) and the `stage` that failed.

The card does not change when the agent's keys do: sign and serve it again after adding, retiring or rotating a key.

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
from agent_did_sdk import AgentIdentity, AgentIdentityConfig, CreateAgentParams, InMemoryAgentRegistry, LocalKeySigner
from agent_did_a2a import A2ASkill, create_agent_did_a2a_integration, text_message

# Create identity
AgentIdentity.set_registry(InMemoryAgentRegistry())
identity = AgentIdentity(AgentIdentityConfig(controller_signer=LocalKeySigner.generate()[0]))
runtime = await identity.create(
    CreateAgentParams(name="MyAgent", core_model="gpt-4.1", system_prompt="...")
)

# Create A2A integration
integration = create_agent_did_a2a_integration(
    agent_identity=identity,
    runtime_identity=runtime,
)

# Signed A2A 1.0 Agent Card for /.well-known/agent-card.json
card = await integration.signed_agent_card_json(
    agent_url="https://my-agent.example.com/a2a",
    skills=[A2ASkill(id="task-1", name="My Skill", description="Does something useful", tags=["demo"])],
)

# Sign an outgoing SendMessage request
signed = await integration.send_message(
    target_url="https://remote-agent.example.com/a2a",
    request_id=1,
    message=text_message("Hello"),
)

# Verify an incoming request. A valid signature only proves which DID signed it:
# accept only the senders (or the controllers of senders) you trust.
is_valid = await integration.verify_request(
    method="POST",
    url="https://my-agent.example.com/a2a",
    headers=incoming_headers,
    body=incoming_body,
    allowed_controllers=["did:webvh:...:partner.example.com:organizations:partner"],
)

# Or learn who signed and decide yourself
from agent_did_a2a import verify_a2a_request_detailed

result = await verify_a2a_request_detailed(
    agent_identity=identity, method="POST", url=url, headers=incoming_headers, body=incoming_body
)
if result.ok:
    print(result.did, result.key_id, result.controllers)

# Identity composition: serve a signed card, and check requests against the sender's card
signed_card = await integration.signed_agent_card_json(agent_url="https://agents.example.com/my-agent/a2a", skills=skills)
composition = await integration.verify_request_against_card(
    method="POST", url=url, headers=incoming_headers, body=incoming_body, agent_card=sender_card
)
if not composition.ok:
    print(composition.stage, composition.reason)
```

## Examples

| Example | Description |
|---|---|
| [a2a_agent_did_discovery.py](examples/a2a_agent_did_discovery.py) | Agent publishes a signed A2A 1.0 Agent Card and a client checks it |
| [a2a_mutual_auth_demo.py](examples/a2a_mutual_auth_demo.py) | A signed `SendMessage` checked against the sender's signed card |

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

`tests/test_a2a_sdk_interop.py` needs the `a2a-sdk[signing]` dev dependency; CI sets `AGENT_DID_REQUIRE_A2A_SDK=1` so it fails instead of skipping when it is missing.

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│  Agent A (Client)                                        │
│  ┌─────────────────────────────────────────────────┐    │
│  │ AgentDidA2AIntegration                           │    │
│  │  → signed card → /.well-known/agent-card.json   │    │
│  │  → sign_request() → Signature + Signature-Input │    │
│  │  → send_message() → signed SendMessage POST     │    │
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

A2A 1.0 declares authentication through `securitySchemes`; none of its scheme types (API key, HTTP auth, OAuth 2.0, OpenID Connect, mTLS) describes HTTP Message Signatures. The integration therefore uses A2A's **extension** mechanism (§4.6):

1. The Agent Card lists the Agent-DID extension in `capabilities.extensions`, with the agent DID and the keys the card publishes, and a JWS signature by one of those keys
2. A client activates the extension with `A2A-Extensions: https://agent-did.org/a2a/identity/v1` and signs each request (`Signature`, `Signature-Input`, `Agent-DID`)
3. The receiving agent resolves the sender's DID, verifies the signature and, with the sender's card, that the signing key is one the card publishes (identity composition contract)

This is **complementary** to the card's `securitySchemes`: an agent can also require an OAuth 2.0 token (for example client credentials with a DID client assertion) or mTLS.

## License

[Apache-2.0](../../LICENSE)
