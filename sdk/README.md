# @agentdid/sdk

[![License: Apache-2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Node.js](https://img.shields.io/badge/node-%3E%3D18-brightgreen)](https://nodejs.org)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.4+-blue)](https://www.typescriptlang.org/)

Verifiable decentralized identity for autonomous AI agents. Create, sign, resolve, and verify Agent-DIDs based on [RFC-001](https://github.com/edisonduran/agent-did/blob/main/docs/RFC-001-Agent-DID-Specification.md).

> **SDK en TypeScript para identidad descentralizada verificable de agentes de IA autónomos.**
>
> **Public Review note:** Agent-DID is pre-1.0 and the RFC is still under community review. See [../docs/DEPRECATION-POLICY.md](../docs/DEPRECATION-POLICY.md) for compatibility and breaking-change expectations during this phase.

---

## Why Agent-DID?

AI agents operate autonomously — calling APIs, executing tools, coordinating tasks. But **how do you verify who an agent is, who controls it, and whether it's been compromised?**

Agent-DID solves this with:

- **Decentralized identity** (W3C DID-compatible) specifically designed for AI agents
- **Ed25519 cryptographic signatures** — deterministic, fast, no entropy vulnerability
- **HTTP Bot Auth** — sign and verify HTTP requests (IETF Message Signatures)
- **Privacy by design** — model and prompt hashes protect IP without exposure
- **EVM registry** — on-chain anchoring and revocation on any EVM chain
- **Universal resolver** — HTTP, JSON-RPC, and IPFS with failover and caching

## Installation

```bash
npm install @agentdid/sdk ethers
```

Requires **Node.js 18+**.

## Quick Start

```ts
import { AgentIdentity } from '@agentdid/sdk';
import { ethers } from 'ethers';

// 1. Create an agent identity
const wallet = new ethers.Wallet(process.env.CREATOR_PRIVATE_KEY!);
const identity = new AgentIdentity({ signer: wallet, network: 'polygon' });

const { document, agentPrivateKey } = await identity.create({
  name: 'SupportBot-X',
  coreModel: 'gpt-4o-mini',
  systemPrompt: 'You are a helpful assistant'
});

// 2. Sign a payload
const payload = 'approve:ticket:123';
const signature = await identity.signMessage(payload, agentPrivateKey);

// 3. Verify — anyone can do this with just the DID
const isValid = await AgentIdentity.verifySignature(document.id, payload, signature);
// true ✓

// 4. Revoke if compromised
await AgentIdentity.revokeDid(document.id);
// All subsequent verifications will fail
```

## Features

| Feature | API | Status |
|---|---|---|
| Create Agent-DID document | `identity.create(params)` | ✅ |
| Sign messages (Ed25519) | `identity.signMessage(payload, key)` | ✅ |
| Sign HTTP requests (Bot Auth) | `identity.signHttpRequest(params)` | ✅ |
| Verify message signatures | `AgentIdentity.verifySignature(did, payload, sig)` | ✅ |
| Verify HTTP signatures | `AgentIdentity.verifyHttpRequestSignature(params)` | ✅ |
| Resolve DID → document | `AgentIdentity.resolve(did)` | ✅ |
| Revoke DID | `AgentIdentity.revokeDid(did)` | ✅ |
| Update document | `AgentIdentity.updateDidDocument(did, patch)` | ✅ |
| Rotate verification keys | `AgentIdentity.rotateVerificationMethod(did)` | ✅ |
| Document history/audit | `AgentIdentity.getDocumentHistory(did)` | ✅ |
| EVM registry adapter | `EvmAgentRegistry` + `EthersAgentRegistryContractClient` | ✅ |
| Universal resolver (HTTP/RPC/IPFS) | `UniversalResolverClient` | ✅ |

## EVM Registry Integration

Connect to a real on-chain `AgentRegistry` contract:

```ts
import { EthersAgentRegistryContractClient, EvmAgentRegistry } from '@agentdid/sdk';
import { ethers } from 'ethers';

const provider = new ethers.JsonRpcProvider('http://localhost:8545');
const signer = new ethers.Wallet(PRIVATE_KEY, provider);
const contract = new ethers.Contract(REGISTRY_ADDRESS, ABI, signer);

const client = new EthersAgentRegistryContractClient(contract);
const registry = new EvmAgentRegistry(client);

AgentIdentity.setRegistry(registry);
```

See full example: [`examples/evm-registry-wiring.ts`](https://github.com/edisonduran/agent-did/blob/main/sdk/examples/evm-registry-wiring.ts)

## Production Resolver

Configure a production-grade resolver with failover and caching:

```ts
import { AgentIdentity } from '@agentdid/sdk';

// HTTP resolver with IPFS gateway failover
AgentIdentity.useProductionResolverFromHttp({
  registry: evmRegistry,
  cacheTtlMs: 60_000,
  ipfsGateways: ['https://gateway.pinata.cloud', 'https://ipfs.io'],
  onResolutionEvent: (event) => console.log('Resolution:', event)
});
```

Minimal `did:wba` example: [`examples/did-wba-resolution.js`](examples/did-wba-resolution.js)

## Production Signer (KMS/HSM)

By default `create()` generates a local Ed25519 key pair (demo mode). For production, inject an `AgentSigner` backed by your KMS/HSM/Vault:

```ts
import { AgentIdentity, AgentSigner, LocalKeySigner } from '@agentdid/sdk';

// Option A: Use LocalKeySigner (testing / demo)
const [signer, privateKeyHex] = LocalKeySigner.generate();

// Option B: Implement AgentSigner for your KMS
const kmsSigner: AgentSigner = {
  async sign(payload: Uint8Array): Promise<string> { /* call KMS */ },
  async getPublicKey(): Promise<Uint8Array> { /* return pub key */ },
};

const result = await identity.create({
  name: 'ProdBot', coreModel: 'gpt-4o', systemPrompt: '...',
  signer: kmsSigner, // private key never leaves KMS
});

// signMessage & signHttpRequest also accept the signer
const sig = await identity.signMessage('payload', kmsSigner);
```

When `signer` is provided, `result.agentPrivateKey` is empty string — the private key never leaves the signer.

## Historical Signature Verification

After key rotation, old keys are marked `deactivated` (ISO timestamp) but kept in the document. Use `verifyHistoricalSignature` to verify signatures made with rotated keys:

```ts
const valid = await AgentIdentity.verifyHistoricalSignature(
  did, payload, signatureHex, 'did:agent:polygon:0x...#key-1'
);
```

## Anti-Replay (HTTP Signatures)

HTTP signatures include `created`, `expires`, and a random `nonce`. Verifiers SHOULD:
- Reject signatures where `expires < now`
- Reject signatures where `created > now + maxSkew` (default: 30s)
- Track seen nonces to prevent replay within the expiration window

## Specification

This SDK implements [RFC-001: Agent-DID Specification](https://github.com/edisonduran/agent-did/blob/main/docs/RFC-001-Agent-DID-Specification.md) — a standard for decentralized AI agent identity extending W3C DIDs with agent-specific metadata.

**Conformance:** 11/11 MUST PASS + 5/5 SHOULD PASS

## Current Limitations

- Default resolver is in-memory (not persistent) — use production resolver for real deployments
- EVM adapter assumes contract exposes `registerAgent`, `revokeAgent`, `getAgentRecord`, `isRevoked`
- EVM timestamps consumed as Unix-string, SDK normalizes to ISO-8601

## Contributing

See [CONTRIBUTING.md](https://github.com/edisonduran/agent-did/blob/main/CONTRIBUTING.md)

## License

[Apache-2.0](../../LICENSE) — see root LICENSE.
