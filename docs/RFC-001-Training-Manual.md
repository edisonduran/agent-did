# RFC-001 Agent-DID — Training Manual

## About This Manual

This manual explains the current Agent-DID model after ADR-001: Agent-DID is an application pattern on top of `did:webvh` for AI agent identity, controller composition, and runtime authentication.

It focuses on the live core release path:

- canonical `did:webvh` identifiers
- controller-chain verification
- HTTP Message Signatures + anti-replay
- SDK lifecycle in TypeScript and Python
- operational resolution/publication patterns

The deferred EVM/on-chain profile still exists as optional compatibility material, but it is not the core `1.0.0` release path.

---

## Table of Contents

1. [What is Agent-DID?](#1-what-is-agent-did)
2. [Mental Model](#2-mental-model)
3. [DID Document Anatomy](#3-did-document-anatomy)
4. [Identity Lifecycle](#4-identity-lifecycle)
5. [SDK API Reference](#5-sdk-api-reference)
6. [Cryptographic Operations](#6-cryptographic-operations)
7. [Resolver Operations](#7-resolver-operations)
8. [Optional EVM Compatibility Profile](#8-optional-evm-compatibility-profile)
9. [Key Rotation & Revocation](#9-key-rotation--revocation)
10. [Security Considerations](#10-security-considerations)
11. [Validation & Conformance](#11-validation--conformance)
12. [Use Cases](#12-use-cases)
13. [Troubleshooting & FAQ](#13-troubleshooting--faq)
14. [Glossary](#14-glossary)
15. [Study Path & Resources](#15-study-path--resources)

---

## 1. What is Agent-DID?

Agent-DID is a web-native identity pattern for AI agents. It does not introduce a new DID method. Instead, it layers agent-specific metadata, controller composition, and signed runtime behavior on top of W3C DID Core using `did:webvh` as the canonical path.

### Why Do AI Agents Need Identity?

- **Accountability**: each agent action can be bound to a verifiable DID.
- **Trust**: other agents and services can validate signatures before interacting.
- **Delegation**: a service can prove not only which agent acted, but also which controller chain governs that agent.
- **Interoperability**: the identity surface stays compatible with DID/VC tooling and HTTP signature verification.

### Core Principles

1. **Web-native by default**: the core path centers on `did:webvh` and hosted/verifiable DID history.
2. **Persistent identity, mutable state**: the DID persists while keys, prompts, or metadata can evolve.
3. **Fail-closed verification**: broken controller chains, invalid signatures, or inactive states must fail verification.
4. **Deployment-profile flexibility**: local bootstrap, hosted publication, filesystem-backed history, writable HTTP/S3-style storage, and optional compatibility adapters can coexist without redefining the core identity model.

---

## 2. Mental Model

Think of Agent-DID as a digital passport stack for AI agents:

```
controller/root DID (organization or legal entity)
        did:webvh:example.com:organizations:acme-support
                           |
                           | controls
                           v
agent DID
        did:webvh:example.com:agents:support-bot
                           |
                           | publishes
                           v
                 DID history (`did.jsonl`)
                           |
                           | resolves to
                           v
                   DID Document + metadata
                           |
                           | provides keys for
                           v
               message / HTTP signature verification
```

For local development, the SDK can bootstrap this flow with in-memory or local sources so you can prove the lifecycle before hosting the DID history externally.

---

## 3. DID Document Anatomy

A DID Document describes the agent's identity and current verification state:

```json
{
  "@context": [
    "https://www.w3.org/ns/did/v1",
    "https://agent-did.org/v1"
  ],
  "id": "did:webvh:example.com:agents:support-bot",
  "controller": "did:webvh:example.com:organizations:acme-support",
  "created": "2026-05-08T18:00:00Z",
  "updated": "2026-05-08T18:00:00Z",
  "agentMetadata": {
    "name": "SupportBot",
    "version": "1.0.0",
    "coreModelHash": "hash://sha256/abc123...",
    "systemPromptHash": "hash://sha256/def456...",
    "capabilities": ["read:kb", "write:ticket"]
  },
  "verificationMethod": [
    {
      "id": "did:webvh:example.com:agents:support-bot#key-1",
      "type": "Ed25519VerificationKey2020",
      "controller": "did:webvh:example.com:agents:support-bot",
      "publicKeyMultibase": "z6Mk..."
    }
  ],
  "authentication": [
    "did:webvh:example.com:agents:support-bot#key-1"
  ],
  "assertionMethod": [
    "did:webvh:example.com:agents:support-bot#key-1"
  ]
}
```

### Field Reference

| Field | Required | Description |
|---|---|---|
| `@context` | Yes | JSON-LD context declarations |
| `id` | Yes | Canonical DID of the agent |
| `controller` | Yes | Governing DID for the agent/controller relationship |
| `verificationMethod` | Yes | Public keys used for signature verification |
| `authentication` | Yes | Keys valid for authentication flows |
| `assertionMethod` | Recommended | Keys valid for message/assertion signing |
| `agentMetadata` | Yes | Agent-specific metadata and integrity hashes |
| `created` / `updated` | Yes | ISO-8601 timestamps |

---

## 4. Identity Lifecycle

### 4.1 Creation

1. Create an `AgentIdentity` instance with a controller signer/config.
2. Generate an Ed25519 signing key for the agent.
3. Build the DID Document and initial history state.
4. Store the history locally, in memory, or via a configured source.
5. Optionally publish the resulting `did.jsonl` for hosted `did:webvh` resolution.

### 4.2 Resolution

1. Receive a DID to resolve.
2. Resolve the DID history from the configured source(s).
3. Parse the latest active document state.
4. Validate controller-chain and security policy.
5. Return the resolved DID Document for signature verification.

### 4.3 Update

1. Modify allowed document fields (metadata, keys, capabilities).
2. Append a new state entry to the DID history.
3. Persist the updated history locally or externally.
4. Re-resolve and verify the new active state.

### 4.4 Key Rotation

1. Generate a new Ed25519 key pair.
2. Append the new key as the active verification method.
3. Keep old keys only when needed for historical verification.
4. Ensure `assertionMethod` / `authentication` reference the active key.

### 4.5 Revocation

1. Revoke the agent or a controlling DID according to policy.
2. Persist the new inactive state.
3. All subsequent canonical verification must fail closed.
4. Historical signatures may remain cryptographically valid, but current trust decisions must reject the revoked chain.

---

## 5. SDK API Reference

### Installation

```bash
npm install @agentdid/sdk ethers
```

### Core Class: `AgentIdentity`

```typescript
import { AgentIdentity, InMemoryAgentRegistry } from '@agentdid/sdk';
import { ethers } from 'ethers';

AgentIdentity.setRegistry(new InMemoryAgentRegistry());

const signer = new ethers.Wallet(process.env.CREATOR_PRIVATE_KEY!);
const identity = new AgentIdentity({ signer });
```

#### `identity.create(params)`

Creates a new runtime identity and returns the DID Document plus agent signing material for the local flow.

#### `identity.signMessage(payload, keyOrSigner)`

Signs arbitrary data with the agent's Ed25519 signing material.

#### `identity.signHttpRequest(params)`

Signs an outbound HTTP request using HTTP Message Signatures.

#### `AgentIdentity.verifySignature(did, payload, signature)`

Resolves the DID and verifies a detached signature.

#### `AgentIdentity.verifyHttpRequestSignature(params)`

Verifies a signed HTTP request, including purpose binding and anti-replay checks.

#### `AgentIdentity.rotateVerificationMethod(did)`

Appends a new active signing key.

#### `AgentIdentity.updateDidDocument(did, patch)`

Writes an updated DID Document state.

#### `AgentIdentity.revokeDid(did)`

Revokes a DID according to the configured registry/resolution policy.

---

## 6. Cryptographic Operations

### Algorithm: Ed25519

- **Key size**: 32-byte private key -> 32-byte public key.
- **Signature size**: 64 bytes.
- **Properties**: deterministic, fast, and widely audited.
- **Library**: the SDK uses audited libraries rather than home-grown cryptography.

### Signature Flow

1. **Sign**: serialize the message/request components and sign with the agent key.
2. **Resolve**: the verifier resolves the DID to get the current public key material.
3. **Verify**: validate signature bytes, key purpose, revocation state, and clock rules.

### Hash Functions

- Prompt/model/config integrity: SHA-256 expressed as `hash://sha256/...`.
- DID history/document integrity: normalized hashing over the relevant state payloads.

---

## 7. Resolver Operations

### Resolver Types

| Resolver | Use Case | Features |
|---|---|---|
| `InMemoryDIDResolver` | Testing, local dev | Simple map-based storage |
| `UniversalResolverClient` | Production | Cache, failover, document-source composition |

### Document Sources

| Source | Protocol | Description |
|---|---|---|
| `WebvhDIDDocumentSource` | HTTPS | Resolves `did:webvh` history from candidate URLs |
| `HttpDIDDocumentSource` | HTTP/HTTPS | Writable/readable document source for hosted docs and logs |
| `JsonRpcDIDDocumentSource` | JSON-RPC | Compatibility source for JSON-RPC-backed resolution |
| Filesystem / presigned / S3-compatible sources | file / HTTP | Operational publication and persistence adapters |

### Production Configuration

```typescript
import { AgentIdentity, ProductionHttpResolverProfileConfig } from '@agentdid/sdk';

AgentIdentity.useProductionResolverFromHttp(
  new ProductionHttpResolverProfileConfig({
    cacheTtlMs: 300_000,
    onResolutionEvent: (event) => console.log(event.stage),
  })
);
```

### Caching Strategy

- TTL-based cache for repeat resolutions.
- Failover across configured sources/candidate URLs.
- Resolution telemetry for observability and HA drills.

---

## 8. Optional EVM Compatibility Profile

The EVM/on-chain profile remains available as optional compatibility material, not as the core release path.

Use it only when a deployment has a concrete need for on-chain registry operations. In that case:

- the SDK exposes `EvmAgentRegistry` adapters
- contract-backed revocation and document references can be wired in
- the web-native `did:webvh` story remains the canonical model for core guidance and release criteria

---

## 9. Key Rotation & Revocation

### Key Rotation Best Practices

1. Rotate proactively on a schedule or after any compromise suspicion.
2. Preserve historical verification only where operationally necessary.
3. Re-run signature verification tests after rotation.
4. Republish updated history wherever the DID is hosted.

### Revocation Scenarios

| Scenario | Action |
|---|---|
| Key compromise | Immediate revoke or rotate + reissue |
| Agent decommissioned | Planned revocation |
| Controller compromise | Revoke or fail closed on the controller chain |
| Policy violation | Administrative revocation |

### Post-Revocation

- Canonical verification must reject the DID.
- Historical artifacts remain inspectable but no longer authoritative for current trust decisions.
- Revocation should be reflected in the active DID history.

---

## 10. Security Considerations

### Threat Model

| Threat | Mitigation |
|---|---|
| Key theft | Private keys never need to leave the local signer/KMS/HSM |
| DID spoofing | Resolver checks DID/document consistency and controller-chain state |
| Document tampering | DID history validation and cryptographic integrity checks |
| Replay attacks | HTTP signatures include time bounds; deployments should add nonce tracking |
| SSRF / unsafe fetch targets | Resolver target validation and allow/deny rules |

### Best Practices

1. Store private keys in KMS, HSM, or secure enclaves for production.
2. Use HTTPS and hardened target validation for resolver/publication flows.
3. Validate active-state and controller-chain status during verification.
4. Monitor resolution anomalies, revocations, and failover events.
5. Rotate keys or revoke immediately on compromise suspicion.

---

## 11. Validation & Conformance

Agent-DID tracks conformance in the live checklist and release criteria documents rather than in this manual.

### Primary References

- `docs/RFC-001-Compliance-Checklist.md`
- `docs/RELEASE-1.0-CRITERIA.md`
- `docs/DEPRECATION-POLICY.md`

### Running Validation

```bash
# TypeScript SDK
npm --prefix sdk test
npm --prefix sdk run api:check
npm --prefix sdk run api:signature:check

# Python SDK
cd sdk-python
python -m ruff check src/ tests/ scripts/ examples/
python -m mypy --strict src/
python -m pytest --cov=agent_did_sdk --cov-fail-under=85 -q
python scripts/conformance_rfc001.py
```

---

## 12. Use Cases

### 12.1 Multi-Agent Collaboration

Independent agents can authenticate each other before exchanging data or delegating work.

### 12.2 Audit Trail

Signed messages and DID history provide verifiable evidence of identity state over time.

### 12.3 API Gateway Authentication

An API gateway can verify the calling agent's DID and HTTP signature before granting access.

### 12.4 Hosted Agent Fleets

Organizations can operate fleets of agents under a controller/root DID while preserving per-agent keys and lifecycle.

### 12.5 Framework Integrations

LangChain, CrewAI, Semantic Kernel, Microsoft Agent Framework, and A2A integrations can expose DID context and signature flows without leaking private keys to the model.

---

## 13. Troubleshooting & FAQ

### FAQ

**Q: Do I need blockchain to use Agent-DID?**  
A: No. The canonical path is `did:webvh` with hosted/verifiable DID history. The EVM profile is optional and deferred outside the core 1.0 release.

**Q: Where should I store the DID history?**  
A: Any resolvable publication target that matches your deployment profile: hosted HTTPS, filesystem-backed publication, presigned/object-storage targets, or other supported sources.

**Q: What happens if hosted resolution fails?**  
A: Production resolver profiles support cache, failover, and observability. Local workflows can still use in-memory or local sources.

**Q: Is Agent-DID compatible with other DID methods?**  
A: Yes at the interoperability layer, but the canonical release path is `did:webvh`.

### Common Issues

| Issue | Solution |
|---|---|
| `DID resolution failed` | Check publication target, resolver config, and candidate URLs |
| `Signature verification failed` | Verify key purpose, message canonicalization, and active DID state |
| `Controller chain invalid` | Confirm the controlling DID resolves and remains active |
| `Cache stale data` | Reduce TTL, flush cache, or inspect resolver telemetry |

---

## 14. Glossary

| Term | Definition |
|---|---|
| **DID** | Decentralized Identifier |
| **did:webvh** | Web-hosted DID method with verifiable history |
| **DID Document** | JSON-LD document containing keys, relationships, and metadata |
| **Verification Method** | Public key material used to verify signatures |
| **Controller chain** | The chain of governing DIDs used for trust decisions |
| **Ed25519** | Signature algorithm used by the SDKs |
| **Agent Metadata** | Agent-specific fields such as name, capabilities, and integrity hashes |
| **Revocation** | Inactivation of a DID for current trust decisions |

---

## 15. Study Path & Resources

1. Start with `QUICKSTART.md` for the local lifecycle.
2. Read `docs/RFC-001-Agent-DID-Specification.md` for the normative model.
3. Review `docs/Anti-Replay-HTTP-Signatures.md` for verifier-side security.
4. Use the integration READMEs when embedding identity into agent frameworks.