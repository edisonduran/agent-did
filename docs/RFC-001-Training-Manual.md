# RFC-001 Agent-DID — Training Manual

## About This Manual

This manual provides a comprehensive, zero-to-hero guide for understanding and working with the Agent-DID decentralized identity standard. It covers theory, architecture, SDK usage, resolver operations, EVM governance, security considerations, and validation procedures.

---

## Table of Contents

1. [What is Agent-DID?](#1-what-is-agent-did)
2. [Mental Model](#2-mental-model)
3. [DID Document Anatomy](#3-did-document-anatomy)
4. [Identity Lifecycle](#4-identity-lifecycle)
5. [SDK API Reference](#5-sdk-api-reference)
6. [Cryptographic Operations](#6-cryptographic-operations)
7. [Resolver Operations](#7-resolver-operations)
8. [EVM Registry & Governance](#8-evm-registry--governance)
9. [Key Rotation & Revocation](#9-key-rotation--revocation)
10. [Security Considerations](#10-security-considerations)
11. [Validation & Conformance](#11-validation--conformance)
12. [Use Cases](#12-use-cases)
13. [Troubleshooting & FAQ](#13-troubleshooting--faq)
14. [Glossary](#14-glossary)
15. [Study Path & Resources](#15-study-path--resources)

---

## 1. What is Agent-DID?

Agent-DID is a decentralized identity method designed specifically for AI agents. It extends the W3C DID Core 1.0 standard to give autonomous software agents a persistent, verifiable, and self-sovereign identity.

### Why Do AI Agents Need Identity?

- **Accountability**: Every agent action can be traced to a verified identity.
- **Trust**: Other agents and services can verify an agent's identity before interacting.
- **Autonomy**: Agents control their own keys and identity lifecycle.
- **Interoperability**: A standard method allows agents from different systems to interact.

### Core Principles

1. **Decentralization**: No central authority controls agent identities.
2. **Persistence**: Identity survives key rotation and metadata updates.
3. **Tamper-evidence**: Cryptographic proofs ensure document integrity.
4. **Revocability**: Compromised identities can be permanently revoked.

---

## 2. Mental Model

Think of Agent-DID as a **digital passport for AI agents**:

```
┌─────────────────────────────────────────────────────────┐
│                    DID (Identifier)                      │
│            did:agent-did:z6Mkf5rG...                     │
│                                                          │
│  ┌─────────────────┐  ┌──────────────────────────────┐  │
│  │ Private Key      │  │ DID Document                 │  │
│  │ (Agent holds)    │  │  - Public keys               │  │
│  │                  │  │  - Capabilities               │  │
│  │ Signs messages   │  │  - Agent metadata             │  │
│  │ Proves identity  │  │  - Created/Updated timestamps │  │
│  └─────────────────┘  └──────────────────────────────┘  │
│                                                          │
│  ┌─────────────────────────────────────────────────┐    │
│  │ On-chain Anchor (EVM Registry)                   │    │
│  │  - DID registered                                │    │
│  │  - Document hash/URI                             │    │
│  │  - Revocation status                             │    │
│  └─────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────┘
```

**Key insight**: The DID itself is derived from the public key. The full document lives off-chain. Only a minimal anchor (hash + revocation flag) lives on-chain.

---

## 3. DID Document Anatomy

A DID Document is a JSON-LD structure that describes the agent's identity:

```json
{
  "@context": [
    "https://www.w3.org/ns/did/v1",
    "https://w3id.org/security/suites/ed25519-2020/v1"
  ],
  "id": "did:agent-did:z6Mkf5rGR9o8FLJhYPKrMBiZcHZJ7e...",
  "verificationMethod": [
    {
      "id": "did:agent-did:z6Mkf...#key-1",
      "type": "Ed25519VerificationKey2020",
      "controller": "did:agent-did:z6Mkf...",
      "publicKeyMultibase": "z6Mkf5rGR9o8FLJhYPKrMBiZcHZJ7e..."
    }
  ],
  "authentication": ["did:agent-did:z6Mkf...#key-1"],
  "agentMetadata": {
    "name": "MyAgent",
    "version": "1.0.0",
    "capabilities": ["data-analysis", "nlp"],
    "codeHash": "sha256:abc123...",
    "configHash": "sha256:def456..."
  },
  "created": "2025-01-15T10:30:00Z",
  "updated": "2025-01-15T10:30:00Z"
}
```

### Field Reference

| Field | Required | Description |
|---|---|---|
| `@context` | Yes | JSON-LD context declarations |
| `id` | Yes | The DID itself — immutable |
| `verificationMethod` | Yes | Array of public keys for verification |
| `authentication` | Yes | References to keys used for authentication |
| `agentMetadata` | Yes | Agent-specific metadata (name, version, capabilities, hashes) |
| `created` | Yes | ISO-8601 timestamp of creation |
| `updated` | Yes | ISO-8601 timestamp of last update |

---

## 4. Identity Lifecycle

### 4.1 Creation

1. Generate Ed25519 key pair.
2. Derive DID from public key (multibase encoding).
3. Build DID Document with metadata.
4. Register anchor on-chain (EVM registry).
5. Store full document off-chain.

### 4.2 Resolution

1. Receive DID to resolve.
2. Query on-chain registry for document reference + revocation status.
3. If revoked → fail.
4. Fetch full document from off-chain source.
5. Validate integrity (hash match).
6. Return resolved document.

### 4.3 Update

1. Modify document fields (metadata, keys).
2. Update `updated` timestamp.
3. Recompute document hash.
4. Update on-chain reference.
5. Store new document version off-chain.

### 4.4 Key Rotation

1. Generate new Ed25519 key pair.
2. Add new key to `verificationMethod`.
3. Remove or mark old key as revoked.
4. Update `authentication` to reference new key.
5. Update on-chain anchor.

### 4.5 Revocation

1. Owner calls `revokeAgent(did)` on-chain.
2. Registry marks DID as revoked.
3. All subsequent resolutions fail.
4. Revocation is **permanent** — no un-revoke.

---

## 5. SDK API Reference

### Installation

```bash
npm install @agent-did/sdk
```

### Core Class: `AgentIdentity`

```typescript
import { AgentIdentity } from '@agent-did/sdk';
```

#### `AgentIdentity.create(options)`

Creates a new agent identity with a fresh key pair.

```typescript
const agent = await AgentIdentity.create({
  name: 'MyAgent',
  version: '1.0.0',
  capabilities: ['data-analysis'],
});
```

**Returns:** `AgentIdentity` instance with `did`, `didDocument`, `sign()`, `verifySignature()`.

#### `agent.did`

The agent's DID string: `did:agent-did:z6Mkf...`

#### `agent.didDocument`

The full DID Document object.

#### `agent.sign(data)`

Signs arbitrary data with the agent's private key.

```typescript
const signature = await agent.sign('Hello, World!');
```

**Returns:** Base64-encoded signature string.

#### `agent.verifySignature(data, signature)`

Verifies a signature against the agent's public key.

```typescript
const isValid = await agent.verifySignature('Hello, World!', signature);
```

**Returns:** `boolean`

#### `agent.rotateVerificationMethod()`

Generates a new key pair and rotates the active verification method.

```typescript
await agent.rotateVerificationMethod();
```

#### `agent.updateDidDocument(patch)`

Updates the DID Document with the provided changes.

```typescript
await agent.updateDidDocument({
  agentMetadata: { version: '2.0.0' }
});
```

---

## 6. Cryptographic Operations

### Algorithm: Ed25519

- **Key size**: 256-bit private key → 256-bit public key.
- **Signature size**: 64 bytes.
- **Properties**: Deterministic, fast, secure against side-channel attacks.
- **Library**: `@noble/curves` (audited, pure JavaScript).

### Signature Flow

1. **Sign**: `Ed25519.sign(message, privateKey)` → 64-byte signature.
2. **Verify**: `Ed25519.verify(signature, message, publicKey)` → boolean.

### Key Derivation

- Private key: 32 random bytes (cryptographically secure).
- Public key: Derived from private key via Ed25519 scalar multiplication.
- DID: `did:agent-did:` + multibase(base58btc, public_key).

### Hash Functions

- Document integrity: SHA-256.
- Code/config hashes in metadata: SHA-256.

---

## 7. Resolver Operations

### Resolver Types

| Resolver | Use Case | Features |
|---|---|---|
| `InMemoryDIDResolver` | Testing, local dev | Simple map-based storage |
| `UniversalResolverClient` | Production | Caching, multi-source, failover |

### Document Sources

| Source | Protocol | Description |
|---|---|---|
| `HttpDIDDocumentSource` | HTTP/HTTPS | Fetches documents from HTTP endpoints |
| `JsonRpcDIDDocumentSource` | JSON-RPC | Fetches documents via JSON-RPC calls |

### Production Configuration

```typescript
import { UniversalResolverClient } from '@agent-did/sdk';

const resolver = new UniversalResolverClient({
  sources: [
    new HttpDIDDocumentSource('https://resolver-1.example.com'),
    new HttpDIDDocumentSource('https://resolver-2.example.com'),
  ],
  cacheTtl: 300, // seconds
});

const document = await resolver.resolve('did:agent-did:z6Mkf...');
```

### Caching Strategy

- TTL-based cache (default: 300 seconds).
- Stale-while-revalidate for high availability.
- Cache metrics: hit/miss counters.

---

## 8. EVM Registry & Governance

### Smart Contract: `AgentRegistry.sol`

Deployed on EVM-compatible chains (Ethereum, Sepolia testnet, etc.).

### Functions

| Function | Access | Description |
|---|---|---|
| `registerAgent(did, owner, documentHash)` | Public | Register a new agent DID |
| `getAgentRecord(did)` | View | Retrieve on-chain record |
| `updateDidDocument(did, newHash)` | Owner only | Update document reference |
| `revokeAgent(did)` | Owner only | Permanently revoke the DID |

### Events

| Event | Emitted When |
|---|---|
| `AgentRegistered` | New agent registered |
| `AgentUpdated` | Document reference updated |
| `AgentRevoked` | Agent revoked |

### Governance Model

- **Owner-controlled**: Only the DID owner can update or revoke.
- **Immutable registration**: DID-to-owner mapping cannot change.
- **Permanent revocation**: No mechanism to un-revoke.
- **Transparent**: All operations emit events for auditability.

---

## 9. Key Rotation & Revocation

### Key Rotation Best Practices

1. **Rotate proactively**: Schedule regular rotations (e.g., every 90 days).
2. **Grace period**: Briefly support both old and new keys during transition.
3. **Update all references**: Ensure on-chain anchor reflects new key.
4. **Verify rotation**: Test that old key no longer verifies new signatures.

### Revocation Scenarios

| Scenario | Action |
|---|---|
| Key compromise | Immediate revocation |
| Agent decommissioned | Planned revocation |
| Policy violation | Administrative revocation by owner |
| Regulatory requirement | Compliance-driven revocation |

### Post-Revocation

- All `resolve()` calls return error/null.
- Existing signatures remain cryptographically valid but should not be trusted.
- Revocation is recorded on-chain with timestamp.

---

## 10. Security Considerations

### Threat Model

| Threat | Mitigation |
|---|---|
| Key theft | Private keys never leave the agent process; no network transmission |
| DID spoofing | DID is deterministically derived from public key |
| Document tampering | On-chain hash ensures integrity |
| Replay attacks | HTTP Message Signatures include timestamp + nonce |
| Registry manipulation | EVM smart contract with owner-only access control |

### Best Practices

1. Store private keys in secure enclaves or HSMs when possible.
2. Use TLS for all resolver communication.
3. Validate document hash against on-chain anchor on every resolution.
4. Implement rate limiting on resolver endpoints.
5. Monitor for unexpected revocation events.
6. Rotate keys on any suspicion of compromise.

### HTTP Message Signatures (Bot Auth)

For agent-to-service authentication, use HTTP Message Signatures (RFC 9421):

1. Agent signs the HTTP request with its private key.
2. Service resolves the agent's DID.
3. Service verifies the signature with the agent's public key.
4. If valid, request is authenticated.

---

## 11. Validation & Conformance

### MUST Controls (11 total)

These are mandatory requirements from RFC-001. All must pass for conformance:

- DID syntax follows `did:agent-did:<multibase-pubkey>`.
- `@context` includes W3C DID v1.
- At least one `verificationMethod` of type `Ed25519VerificationKey2020`.
- `authentication` references at least one verification method.
- `agentMetadata` is present and well-formed.
- Document integrity verifiable via on-chain hash.
- Revocation is permanent and prevents resolution.
- ...and more (see Compliance Checklist).

### SHOULD Controls (5 total)

Recommended but not blocking:

- Multi-key support for key rotation.
- Cache layer in resolver.
- Automated conformance test suite.
- Temporal normalization documentation.
- HA deployment for resolver.

### Running Validation

```bash
# Unit tests
cd sdk && npm test

# Conformance suite
node scripts/conformance-rfc001.js

# End-to-end smoke
node scripts/e2e-smoke.js

# Resolver HA smoke
node scripts/resolver-ha-smoke.js

# Revocation policy smoke
node scripts/revocation-policy-smoke.js
```

---

## 12. Use Cases

### 12.1 Multi-Agent Collaboration

Multiple AI agents from different organizations authenticate each other using Agent-DIDs before sharing data or delegating tasks.

### 12.2 Audit Trail

Every agent action is signed with its DID private key, creating a tamper-evident audit trail that can be verified by third parties.

### 12.3 API Gateway Authentication

An API gateway resolves the calling agent's DID and verifies its HTTP Message Signature before granting access.

### 12.4 Supply Chain Automation

Agents representing different supply chain participants use Agent-DIDs to establish trust and sign logistics transactions.

### 12.5 Regulatory Compliance

Financial or healthcare agents demonstrate their identity and capabilities through their DID Document, enabling automated compliance checks.

### 12.6 LangChain Agent Orchestration

LangChain agents can inject Agent-DID identity into their runtime through the integration package in [../integrations/langchain/README.md](../integrations/langchain/README.md), allowing tool-enabled agents to expose their DID, sign payloads or HTTP requests, and verify signatures without leaking private keys to the model.

---

## 13. Troubleshooting & FAQ

### FAQ

**Q: Can I use a different signing algorithm?**
A: RFC-001 specifies Ed25519. Future versions may support additional algorithms.

**Q: Where should I store the DID Document?**
A: Any HTTP-accessible location. IPFS, cloud storage, or a dedicated document server all work.

**Q: What happens if the EVM network is down?**
A: New registrations and updates will fail. Existing cached resolutions continue to work (stale-while-revalidate).

**Q: Can I transfer DID ownership?**
A: No. DID ownership is tied to the original registrant address. Create a new DID if ownership changes.

**Q: Is Agent-DID compatible with other DID methods?**
A: Agent-DID follows W3C DID Core 1.0 so it interoperates at the standard level. Cross-method resolution depends on universal resolver support.

**Q: Is there a framework integration example available today?**
A: Yes. LangChain JS 1.x is already implemented in [../integrations/langchain/README.md](../integrations/langchain/README.md). CrewAI now has a functional Python integration in [../integrations/crewai/README.md](../integrations/crewai/README.md). Semantic Kernel now has a functional Python integration in [../integrations/semantic-kernel/README.md](../integrations/semantic-kernel/README.md). Microsoft Agent Framework remains a separate future integration target.

### Common Issues

| Issue | Solution |
|---|---|
| `DID resolution failed` | Check network connectivity, verify DID is registered, confirm not revoked |
| `Signature verification failed` | Ensure correct key is used, check for key rotation, verify message encoding |
| `Contract call reverted` | Verify caller is the DID owner, check DID exists, ensure not already revoked |
| `Cache stale data` | Reduce cache TTL, manually flush cache, verify source health |

---

## 14. Glossary

| Term | Definition |
|---|---|
| **DID** | Decentralized Identifier — a URI that identifies a subject in a decentralized manner |
| **DID Document** | JSON-LD document containing public keys, authentication methods, and metadata |
| **Verification Method** | A cryptographic public key used to verify signatures |
| **Multibase** | An encoding format that prefixes the encoding type (e.g., `z` = base58btc) |
| **Ed25519** | An elliptic curve signing algorithm (EdDSA over Curve25519) |
| **EVM** | Ethereum Virtual Machine — the runtime for executing smart contracts |
| **Agent Metadata** | Agent-specific fields: name, version, capabilities, integrity hashes |
| **Revocation** | Permanent deactivation of a DID |
| **Key Rotation** | Replacing an active key pair with a new one while preserving the DID |
| **Universal Resolver** | A resolution service that can resolve multiple DID methods |
| **JSON-LD** | JSON for Linking Data — a method of encoding linked data using JSON |
| **HTTP Message Signatures** | RFC 9421 standard for signing HTTP requests |

---

## 15. Study Path & Resources

### Recommended Study Path

| Phase | Activities | Duration |
|---|---|---|
| **1. Foundations** | Read this manual (Sections 1-4), review RFC-001 | 2 hours |
| **2. Hands-on** | Complete 2-Hour Course (all modules + exercises) | 2 hours |
| **3. Deep Dive** | Read SDK source code, review [../integrations/langchain/README.md](../integrations/langchain/README.md), study contract, run all tests | 3 hours |
| **4. Validation** | Run conformance suite, review Compliance Checklist | 1 hour |
| **5. Production** | Review HA Runbook, plan deployment | 2 hours |

### External Resources

- [W3C DID Core 1.0](https://www.w3.org/TR/did-core/)
- [W3C DID Resolution](https://w3c-ccg.github.io/did-resolution/)
- [Ed25519 — RFC 8032](https://tools.ietf.org/html/rfc8032)
- [HTTP Message Signatures — RFC 9421](https://www.rfc-editor.org/rfc/rfc9421)
- [Multibase Specification](https://datatracker.ietf.org/doc/html/draft-multiformats-multibase)
- [Solidity Documentation](https://docs.soliditylang.org/)
- [@noble/curves](https://github.com/paulmillr/noble-curves)
- [Agent-DID LangChain integration](../integrations/langchain/README.md)
