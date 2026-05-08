# RFC-001 Agent-DID — 2-Hour Practical Course

## Course Overview

| Field | Detail |
|---|---|
| Duration | 2 hours (6 modules) |
| Level | Intermediate |
| Prerequisites | Basic cryptography, W3C DID basics, Node.js/TypeScript or Python |
| Outcome | Participants can create, resolve, sign, and verify Agent-DIDs end-to-end on the canonical `did:webvh` path |

---

## Module 1 — Fundamentals (15 min)

### 1.1 What is Decentralized Identity?

- Self-sovereign identity vs. centralized identity.
- W3C DID Core 1.0 overview.
- Why AI agents need an identity layer distinct from API keys or app credentials.

### 1.2 The Agent-DID Thesis

- Agent-DID is an application pattern on top of `did:webvh`.
- Core value: agent metadata + controller composition + runtime signatures.
- Key properties: persistent identity, tamper-evident history, revocability, interoperability.

### 1.3 Exercise — Concept Map

Draw a diagram connecting: controller DID, agent DID, DID Document, verification method, DID history, resolver, and signed HTTP request.

**Expected time:** 5 min.

---

## Module 2 — Specification & Architecture (20 min)

### 2.1 RFC-001 Structure

- Canonical DID path: `did:webvh`.
- Document anatomy: `id`, `controller`, `verificationMethod`, `authentication`, `agentMetadata`, `created`, `updated`.
- Resolution model: hosted/verifiable DID history plus controller-chain verification.

### 2.2 Architecture Diagram

```
┌─────────────────┐      ┌──────────────────────────────┐
│   SDK Client    │─────▶│  DID history (`did.jsonl`)   │
│ (AgentIdentity) │      │  hosted over HTTPS / source  │
└─────────────────┘      └──────────────┬───────────────┘
        │                                │
        │                                ▼
        │                       ┌────────────────┐
        └──────────────────────▶│   Resolver     │
                                │ + cache/failover |
                                └────────┬───────┘
                                         │
                                         ▼
                               DID Document + key material
```

### 2.3 Exercise — Identify Components

Given a sample DID Document, label each field and explain its purpose.

**Expected time:** 5 min.

---

## Module 3 — SDK End-to-End (25 min)

### 3.1 Installation

```bash
npm install @agentdid/sdk ethers
```

### 3.2 Create an Agent Identity

```typescript
import { AgentIdentity, InMemoryAgentRegistry } from '@agentdid/sdk';
import { ethers } from 'ethers';

AgentIdentity.setRegistry(new InMemoryAgentRegistry());

const signer = new ethers.Wallet(process.env.CREATOR_PRIVATE_KEY!);
const identity = new AgentIdentity({ signer });

const result = await identity.create({
  name: 'CourseAgent',
  coreModel: 'gpt-4.1-mini',
  systemPrompt: 'You are a course agent.',
  capabilities: ['data-analysis', 'nlp'],
});

console.log('DID:', result.document.id);
console.log('Controller:', result.document.controller);
```

### 3.3 Sign and Verify

```typescript
const message = 'Hello from the course!';
const signature = await identity.signMessage(message, result.agentPrivateKey);
const isValid = await AgentIdentity.verifySignature(
  result.document.id,
  message,
  signature,
);
console.log('Valid:', isValid);
```

### 3.4 Key Rotation

```typescript
await AgentIdentity.rotateVerificationMethod(result.document.id);
```

### 3.5 Exercise — Full Lifecycle

1. Create an agent identity.
2. Sign a message.
3. Verify the signature.
4. Rotate the key.
5. Re-check that the active key changed.
6. Sign a new message and verify with the updated document.

**Expected time:** 10 min.

### 3.6 Framework Integration Snapshot

Review [../integrations/langchain/README.md](../integrations/langchain/README.md) to see how the same identity model is injected into an agent runtime through middleware and tools.

---

## Module 4 — Universal Resolver & HA (20 min)

### 4.1 Resolver Architecture

- `InMemoryDIDResolver` — local, for testing.
- `UniversalResolverClient` — production, with caching and multi-source fallback.
- `WebvhDIDDocumentSource` / `HttpDIDDocumentSource` / `JsonRpcDIDDocumentSource` — pluggable resolution sources.

### 4.2 Resolution Flow

1. Client calls `resolve(did)`.
2. Resolver checks cache.
3. If needed, resolver fetches DID history from candidate sources.
4. Resolver derives the latest active document state.
5. Resolver validates DID/document consistency.
6. Client uses the resolved keys to verify signatures.

### 4.3 High Availability Concepts

- Multi-source resolution.
- SLO targets: 99.9% availability, p95 <= 750 ms.
- Cache + failover + observability.

### 4.4 Exercise — Resolver Configuration

Configure a production resolver profile and verify resolution still works when one source is unavailable.

**Expected time:** 5 min.

---

## Module 5 — Publication & Optional Adapters (20 min)

### 5.1 Hosted Publication

- Publish `did.jsonl` to an HTTPS location.
- Ensure the resulting `did:webvh` resolves from its candidate URLs.
- Re-publish after updates, rotations, or revocations.

### 5.2 Operational Storage Options

- filesystem-backed history for local or controlled environments
- writable HTTP sources for hosted publication
- presigned/object-storage and S3-compatible adapters for cloud deployment

### 5.3 Optional EVM Compatibility Profile

- available if a deployment explicitly needs the deferred on-chain profile
- not required for the core `did:webvh` release path
- should be treated as compatibility/profile work, not as the default mental model

### 5.4 Exercise — Publication Drill

1. Export a DID history log.
2. Persist it to one supported source.
3. Restore the DID from that source.
4. Verify that signatures still validate after restore.

**Expected time:** 10 min.

---

## Module 6 — Validation & Conformance (15 min)

### 6.1 Conformance Suite

```bash
# TypeScript SDK
npm --prefix sdk test
npm --prefix sdk run api:check
npm --prefix sdk run api:signature:check

# Python SDK
cd sdk-python
python scripts/conformance_rfc001.py
```

### 6.2 MUST vs. SHOULD Controls

- **MUST**: 11 controls that are mandatory for compliance.
- **SHOULD**: 5 controls that are recommended but still tracked explicitly.

### 6.3 Smoke Tests

```bash
cd sdk-python
python scripts/webvh_external_smoke.py
python scripts/resolver_ha_smoke.py
```

### 6.4 Exercise — Run and Interpret

1. Run the conformance suite.
2. Identify which controls pass/fail.
3. Explain how the resolver and publication path affect the result.

**Expected time:** 5 min.

---

## Final Assessment — 10 Questions

1. What DID method is canonical for the core release path? -> `did:webvh`
2. What algorithm does Agent-DID use for signing? -> Ed25519
3. What does the controller field express? -> Who governs the agent identity
4. What artifact is typically published for hosted DID history? -> `did.jsonl`
5. What happens when a key is rotated? -> A new active verification method is appended
6. What is the purpose of `agentMetadata`? -> Agent capabilities, integrity hashes, and related metadata
7. How does the resolver obtain the DID Document? -> By resolving DID history and deriving the latest active state
8. Can a revoked DID still be trusted for new actions? -> No
9. What is the SLO target for resolver availability? -> 99.9%
10. How many MUST controls exist in the conformance checklist? -> 11

---

## Recommended Study Plan

| Day | Activity | Duration |
|---|---|---|
| 1 | Read RFC-001 Specification | 45 min |
| 2 | Complete Modules 1-3 (exercises) | 60 min |
| 3 | Complete Modules 4-6 (exercises) | 55 min |
| 4 | Run conformance + publication/resolver smokes | 30 min |
| 5 | Review assessment, revisit weak areas, inspect integration examples | 30 min |