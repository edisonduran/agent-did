# @agentdid/sdk

[![License: Apache-2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Node.js](https://img.shields.io/badge/node-%3E%3D22.12-brightgreen)](https://nodejs.org)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.4+-blue)](https://www.typescriptlang.org/)

Verifiable decentralized identity for autonomous AI agents. Create, sign, resolve, and verify Agent-DIDs based on [RFC-001](https://github.com/edisonduran/agent-did/blob/main/docs/RFC-001-Agent-DID-Specification.md).

> **SDK en TypeScript para identidad descentralizada verificable de agentes de IA autónomos.**
>
> **Release-candidate note:** The repository is frozen for the `1.0.0-rc.5` release train and RFC-001 is now treated as Stable text. Final `v1.0.0` publication still depends on the remaining gates in [../docs/RELEASE-1.0-CRITERIA.md](../docs/RELEASE-1.0-CRITERIA.md).
>
> **Moving from `0.x`?** See [MIGRATION-0.x-to-1.0.md](MIGRATION-0.x-to-1.0.md). Coming from `1.0.0-rc.3`? The breaking changes in `1.0.0-rc.5` are listed in [MIGRATION-1.0-rc.3-to-rc.5.md](MIGRATION-1.0-rc.3-to-rc.5.md); from `1.0.0-rc.2`, see [MIGRATION-1.0-rc.2-to-rc.3.md](MIGRATION-1.0-rc.2-to-rc.3.md) first.

---

## Why Agent-DID?

AI agents operate autonomously — calling APIs, executing tools, coordinating tasks. But **how do you verify who an agent is, who controls it, and whether it's been compromised?**

Agent-DID solves this with:

- **Decentralized identity** (W3C DID-compatible) specifically designed for AI agents
- **Ed25519 cryptographic signatures** — deterministic, fast, no entropy vulnerability
- **HTTP request signatures** — sign and verify HTTP requests (RFC 9421 HTTP Message Signatures)
- **Privacy by design** — model and prompt hashes protect IP without exposure
- **Optional EVM registry adapter** — available when a deployment explicitly needs the deferred on-chain profile
- **Universal resolver** — HTTP, JSON-RPC, and IPFS with failover and caching

## Installation

```bash
npm install @agentdid/sdk@next
```

Requires **Node.js 22.12+** (22.23.4+, 24.22.1+ or 26.12.1+ recommended for the October 2026 Node.js security fixes). For browser bundles, see [Browser Usage](#browser-usage).

## Quick Start

```ts
import { AgentIdentity, LocalKeySigner } from '@agentdid/sdk';

// 1. Create an agent identity. The controller is an Ed25519 key (use a KMS/HSM-backed AgentSigner in production)
const controllerSigner = new LocalKeySigner(process.env.CREATOR_PRIVATE_KEY!);
const identity = new AgentIdentity({ controllerSigner });

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

This quickstart validates the local signing lifecycle first. By default the SDK follows the canonical `did:webvh` path and bootstraps the local controller side for you; hosted publication of `did.jsonl` is a separate deployment concern.

Since `1.0.0-rc.3`, `did:webvh` DIDs are did:webvh v1.0 DIDs: the `did.jsonl` log has a self-certifying SCID and every entry is signed by the controller key, through the DIF reference implementation `didwebvh-ts`. CI runs the pinned DIF `didwebvh-test-suite` vectors against the SDK's did:webvh layer. See [MIGRATION-1.0-rc.2-to-rc.3.md](MIGRATION-1.0-rc.2-to-rc.3.md) for the explicit profile's `controllerSigner` and for re-issuing older DIDs.

An agent's controller does not have to be an Agent-DID document: any DID Core `did:webvh` document works, for example your organization's DID created with another did:webvh tool (RFC-001 §4.2.1). Pass it as `webvh.controllerDid` with a `controllerSigner` whose key the controller lists under `capabilityInvocation`. `resolveDocument(did)` returns such a document; `resolve(did)` returns Agent-DID documents only.

## Features

| Feature | API | Status |
|---|---|---|
| Create Agent-DID document | `identity.create(params)` | ✅ |
| Sign messages (Ed25519) | `identity.signMessage(payload, key)` | ✅ |
| Sign HTTP requests (RFC 9421) | `identity.signHttpRequest(params)` | ✅ |
| Verify message signatures | `AgentIdentity.verifySignature(did, payload, sig)` | ✅ |
| Enforce key purpose binding | `assertKeyPurpose(keyId, didDoc, purpose)` | ✅ |
| Verify HTTP signatures | `AgentIdentity.verifyHttpRequestSignature(params)` | ✅ |
| Verify HTTP signatures, with the reason of a rejection | `client.verifyHttpRequestSignatureDetailed(params)` | ✅ |
| Resolve DID → document | `AgentIdentity.resolve(did)` | ✅ |
| Revoke DID | `AgentIdentity.revokeDid(did)` | ✅ |
| Update document | `AgentIdentity.updateDidDocument(did, patch)` | ✅ |
| Rotate verification keys | `AgentIdentity.rotateVerificationMethod(did)` (`{ emergency: true }` also revokes the old keys) | ✅ |
| Retire or revoke one key | `client.retireVerificationMethod(did, keyId, { emergency })` | ✅ |
| Signed A2A Agent Cards (composition contract) | `signAgentCard(card, signer, keyId)`, `client.verifyAgentCard(card)`, `client.verifyIdentityComposition({ ...request, agentCard })` | ✅ |
| Document history/audit | `AgentIdentity.getDocumentHistory(did)` + `AgentIdentity.exportDidWebvhHistory(did)` + `AgentIdentity.importDidWebvhHistory(log)` + `AgentIdentity.saveDidWebvhHistoryToFile(did, path)` + `AgentIdentity.loadDidWebvhHistoryFromFile(path)` + `AgentIdentity.persistDidWebvhHistoryToSource(did, ref, source)` + `AgentIdentity.restoreDidWebvhHistoryFromSource(ref, source)` | ✅ |
| Filesystem storage adapter | `FilesystemDIDDocumentSource` | ✅ |
| Remote HTTP storage adapter | `HttpDIDDocumentSource` (`storeByReference`, `getDidLogByReference`, `storeDidLogByReference`) | ✅ |
| Authenticated HTTP gateway adapter | `BearerTokenHttpDIDDocumentSource` | ✅ |
| Presigned/object-storage adapter | `PresignedHttpDIDDocumentSource` | ✅ |
| S3-compatible object-store adapter | `S3CompatibleDIDDocumentSource` | ✅ |
| AWS SigV4 S3 adapter | `AwsSigV4S3DIDDocumentSource` | ✅ |
| Universal resolver (HTTP/RPC/IPFS) | `UniversalResolverClient` | ✅ |
| Agent metadata credential (VC 2.0, `eddsa-jcs-2022`) | `client.issueAgentMetadataCredential(params)` / `client.verifyAgentMetadataCredential(credential)` | ✅ |
| Capabilities: delegation and HTTP invocation (RFC-001 §6.7) | `client.createCapability(params)`, `client.verifyCapabilityChain(capability, { rootControllers })`, `signHttpRequest({ ..., capability })`, `client.verifyHttpCapabilityInvocation({ ...request, rootControllers })` | ✅ |
| OAuth client assertion with the DID key (`private_key_jwt`, RFC-001 §6.8) | `createClientAssertion(params)`, `buildClientJwks(document)`, `buildClientMetadataDocument(params)`, `client.verifyClientAssertion(params)` | ✅ |

By default, `verifySignature` and HTTP signature verification require the signing key to be listed under `assertionMethod` in the DID document. Passing a key that exists only under another relationship, including `keyAgreement`, raises `IdentityCompositionError` with reason `key_purpose_violation`.

## Optional EVM Registry Integration

The core SDK has no EVM dependency. The optional adapter `@agentdid/evm` (`EvmAgentRegistry`, an `AgentRegistry` backed by the on-chain `AgentRegistry` contract) is maintained with the contract in [edisonduran/agent-did-evm](https://github.com/edisonduran/agent-did-evm); see its README for the wiring.

## Production Resolver

Configure a production-grade resolver with failover and caching:

```ts
import { AgentIdentity } from '@agentdid/sdk';

// HTTP resolver with IPFS gateway failover
AgentIdentity.useProductionResolverFromHttp({
  registry: evmRegistry, // optional when using the EVM compatibility profile
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

## Signatures at a Stated Time

After key rotation, old keys are marked `deactivated` but kept in the log. To check a signature against the key the DID had at the time the signed artifact states (RFC-001 §6.2.2), use the DID's did:webvh log. With the production resolver (`useProductionResolver`) the client fetches and verifies the log from the DID's host, so later rotations and a deactivation are seen once the resolver cache entry expires. A log imported with `importDidWebvhHistory` is a copy, not an authority: with a resolver that fetches logs the next resolution fetches the host's log at once and the longer of the two wins, and if the host cannot be reached the resolution fails closed. The imported log is used as is only when the resolver does not fetch logs (the in-memory default); then nothing tells an older copy (for example one from before a revocation) from the current log, so import logs only from a source you trust to be current:

```ts
// await client.importDidWebvhHistory(didLog); // only without a resolver that fetches logs
const result = await client.verifySignatureAtTime(did, payload, signatureHex, `${did}#key-1`, {
  statedTime: '2026-01-02T10:00:00Z',            // from the artifact; asserted by the signer
  // timestampToken: tsr, tsaTrustAnchors: [tsaRootPem], // an RFC 3161 token over the signature (see below)
  // trustedTimeNotAfter: '2026-01-02T10:00:05Z' // other evidence you trust; not together with timestampToken
});
if (result.status !== 'valid') { /* 'invalid' or 'indeterminate': reject */ }
```

The stated time is the signer's claim, so a key retired after it gives `indeterminate` unless you pass trusted time evidence earlier than the retirement. `checkDidWebvhKeyAtTime(log, { keyId, statedTime })` returns the same key check, with the public key, without verifying a signature.

**RFC 3161 timestamps** ([ADR-007](../docs/ADR-007-Witnesses-and-Timestamps.md)). A Time Stamping Authority can attest that a signature existed at a given time. Build the request with `createTimestampRequest(signatureBytes)` (the raw 64 signature bytes), send it to a TSA you trust with content type `application/timestamp-query` (the SDK does not contact TSAs), and keep the response with the artifact. A verifier passes it as `timestampToken` with the TSA trust anchors it chooses; the SDK checks the token (status, imprint, `id-kp-timeStamping`, CMS signature, path to an anchor at `genTime`) and uses `genTime + accuracy` as the evidence. A token that does not verify gives `{ status: 'invalid', reason: 'timestamp_invalid', timestampRejection }`. `verifyTimestampToken(token, signatureBytes, { trustAnchors })` is the check on its own. Revocation of TSA certificates is not checked.

`verifyHistoricalSignature` was removed in `1.0.0-rc.5`: it accepted any retired key still in the document, with no time check, so it also accepted signatures forged with a compromised key after it was retired.

## did:webvh Witnesses

Witnesses make a forked or rewritten log visible: `threshold` of the listed `did:key` DIDs must approve every log entry before it is published, and resolvers reject entries without enough approvals ([ADR-007](../docs/ADR-007-Witnesses-and-Timestamps.md), did:webvh v1.0).

```ts
const client = new AgentDidClient({
  // Ask each witness to approve the entry (over the network in production); a witness signs with createDidWebvhWitnessProof
  collectWitnessProofs: async (request) =>
    Promise.all(witnessSigners.map((signer) => createDidWebvhWitnessProof({ log: request.log, witnessFile: request.witnessFile, signer })))
});
// webvh: { ..., witness: { threshold: 2, witnesses: ['did:key:z6Mk...', 'did:key:z6Mk...'] } }
// await client.setDidWebvhWitnesses(did, { threshold: 1, witnesses: ['did:key:z6Mk...'] }); // or null to remove
const witnessFile = client.exportDidWebvhWitnessFile(did); // publish as did-witness.json, before did.jsonl
```

`UniversalResolverClient` (through `WebvhDIDDocumentSource`) fetches `did-witness.json` next to `did.jsonl` and fails closed when it is missing or the approvals do not reach a threshold. Watchers are not supported.

## Agent Metadata Credential

The controller can state an agent's metadata, or part of it, in a W3C VC 2.0 credential with an `eddsa-jcs-2022` proof (RFC-001 §4.4) and present it out of band, for example in an A2A Agent Card:

```ts
const credential = await client.issueAgentMetadataCredential({
  agentDid,
  signer: controllerSigner,                          // holds an assertionMethod key of the controller
  verificationMethodId: controllerDocument.assertionMethod![0],
  agentMetadata: { name: 'BillingBot', capabilities: ['billing:read'] }, // optional subset
  validUntil: '2027-01-01T00:00:00Z'
});

const result = await verifier.verifyAgentMetadataCredential(credential, { expectedAgentDid: agentDid });
if (!result.ok) { /* result.reason: 'expired', 'issuer_not_controller', 'signature_invalid', ... */ }
```

Verification resolves the agent and its controller and checks the binding, so the verifier needs their did:webvh logs (production resolver or imported). The metadata is the controller's assertion, not evidence of what the agent runs.

## Capabilities and OAuth

A DID with a `capabilityDelegation` key can grant another DID a scoped, expiring authority, and the grantee invokes it with a request signed by a `capabilityInvocation` key (RFC-001 §6.7). Create both agents with `additionalVerificationRelationships`.

```ts
const capability = await client.createCapability({
  invocationTarget: 'https://api.example.com/files',
  controller: workerDid,                       // the delegate
  allowedAction: ['GET'],
  expires: '2026-12-01T00:00:00Z',             // keep it short: there is no per-capability revocation
  verificationMethodId: `${ownerDid}#key-1`,   // under capabilityDelegation
  signer: ownerSigner
});

// The worker invokes it
const headers = await workerIdentity.signHttpRequest({ method: 'GET', url, agentDid: workerDid, signer, verificationMethodId, capability });

// The resource server decides who may delegate its targets
const result = await server.verifyHttpCapabilityInvocation({ method: 'GET', url, headers, rootControllers: { 'https://api.example.com/files': [ownerDid] } });
```

The same DID key can authenticate the agent to an OAuth authorization server, including one in front of an MCP server (RFC-001 §6.8): `createClientAssertion({ clientId, issuer, verificationMethodId, signer })` is the `client_assertion` of a token request, and `buildClientMetadataDocument({ clientId, clientName, didDocument })` is the Client ID Metadata Document to publish at `clientId`. The SDK runs no OAuth flow. Aligned with ZCAP v0.4, RFC 7523 and the Client ID Metadata Document draft; no conformance with them is claimed.

## Anti-Replay (HTTP Signatures)

Since `1.0.0-rc.3`, HTTP signatures are RFC 9421 HTTP Message Signatures with the Agent-DID profile: the agent DID goes in an `Agent-DID` Dictionary header keyed by signature label (`Agent-DID: sig1="did:webvh:…"`; since `1.0.0-rc.5`, before it was a bare `Signature-Agent` header), the signature covers `@method`, `@authority`, `@path`, `@query`, `Content-Digest`, `Date` and `"agent-did";key="sig1"`, and carries `created`, `expires`, `nonce`, `keyid`, `alg="ed25519"` and `tag="agent-did"`. `verifyHttpRequestSignature` checks the window and the digest, verifies the signature, and then records the nonce in a `NonceStore`: a process-wide `InMemoryNonceStore` by default, or a shared store you pass as `nonceStore`. **The default store is per process: with more than one verifier instance (replicas, serverless, Kubernetes) a replayed request is accepted by any instance that has not seen it, so pass a shared `nonceStore`.** CI checks the signature base against RFC 9421 Appendix B.2.6 and cross-verifies with the independent `http-message-signatures` package. See [Anti-Replay-HTTP-Signatures.md](../docs/Anti-Replay-HTTP-Signatures.md).

## Browser Usage

The SDK targets Node.js, but its core (creating identities, signing, verifying and in-memory resolution) runs in a browser bundle. The [Agent-DID in Action](https://edisonduran.github.io/agent-did-in-action/) demo runs on the published package this way. A few APIs import Node.js built-ins lazily, on first use, and are not available in a browser:

| Node.js built-in | Used by | In the browser |
|---|---|---|
| `node:fs/promises` | `FilesystemDIDDocumentSource`, `saveDidWebvhHistoryToFile`, `loadDidWebvhHistoryFromFile` | Not available. Keep DID logs in memory or store them through an HTTP source (`persistDidWebvhHistoryToSource`). |
| `node:dns`, `node:http`, `node:https` | The default `fetch` of the HTTP sources (`HttpDIDDocumentSource`, `WebvhDIDDocumentSource`, the S3 and bearer-token sources, `useProductionResolverFromHttp`) and the default transport of `JsonRpcDIDDocumentSource` | Pass your own `fetchFn` (or `transport` for JSON-RPC). |
| `node:path` | `FilesystemDIDDocumentSource` (imported statically, called only by that class) | Not available. |
| `Buffer` global | `verifyTimestampToken` with PEM text in `trustAnchors` | Pass DER bytes (`Uint8Array`) instead, or provide a `Buffer` global. |

Randomness and hashing come from `@noble/*` and the Web Crypto API, so they need no polyfill.

**Bundler setup.** Vite 5 with no Node.js polyfills builds the SDK as it is: it replaces the built-ins with empty modules and prints a "has been externalized for browser compatibility" warning for each. If you add `vite-plugin-node-polyfills`, its stand-in for `fs` has no `fs/promises` and the build fails, so exclude those modules from the plugin and alias them to a stub that throws a clear error:

```ts
// vite.config.ts
import { fileURLToPath } from 'node:url';
import { defineConfig } from 'vite';
import { nodePolyfills } from 'vite-plugin-node-polyfills';

export default defineConfig({
  resolve: {
    alias: [
      {
        find: /^(node:)?(fs\/promises|dns|http|https)$/,
        replacement: fileURLToPath(new URL('./src/shims/node-unavailable.ts', import.meta.url))
      }
    ]
  },
  plugins: [nodePolyfills({ exclude: ['fs', 'dns', 'http', 'https'] })]
});
```

```ts
// src/shims/node-unavailable.ts
function unavailable(): never {
  throw new Error('This Node.js API is not available in the browser');
}
export const readFile = unavailable;
export const writeFile = unavailable;
export const mkdir = unavailable;
export const rename = unavailable;
export const rm = unavailable;
export const lookup = unavailable;
export const request = unavailable;
export const promises = { lookup: unavailable };
export default { readFile, writeFile, mkdir, rename, rm, lookup, request, promises };
```

The stub also helps without the plugin: an empty module fails with an unclear `... is not a function` error, the stub names the cause.

**In-memory identities.** Give each identity a shared `AgentDidClient`, so that DIDs created in the page resolve for verification:

```ts
import { AgentDidClient, AgentIdentity, LocalKeySigner } from '@agentdid/sdk';

const client = new AgentDidClient();
const [controllerSigner] = LocalKeySigner.generate();
const identity = new AgentIdentity({ controllerSigner, client });

const { document, agentPrivateKey } = await identity.create({ name: 'BrowserBot', coreModel: 'gpt-4o-mini', systemPrompt: '...' });
const signature = await identity.signMessage('hello', agentPrivateKey);
await client.verifySignature(document.id, 'hello', signature); // true
```

**Remote resolution.** Pass the browser `fetch` as `fetchFn`:

```ts
import { HttpDIDDocumentSource, WebvhDIDDocumentSource } from '@agentdid/sdk';

const browserFetch = (url: string, init?: RequestInit) => fetch(url, { ...init, redirect: 'error' });

const webvhSource = new WebvhDIDDocumentSource({ fetchFn: browserFetch });
const httpSource = new HttpDIDDocumentSource({ fetchFn: browserFetch });
```

A custom `fetchFn` replaces the SDK's SSRF-safe default, which refuses redirects and private or reserved addresses, pins the address it checked, and limits the time and size of each response. With your own `fetchFn`, those checks are yours to make. The target server must also allow the page's origin (CORS).

The SDK's CI does not run a browser build; the demo above is what checks it, against each release it upgrades to. Checked with `1.0.0-rc.5`, Vite 5.4 and `vite-plugin-node-polyfills` 0.22 in Chromium.

## Specification

This SDK implements [RFC-001: Agent-DID Specification](https://github.com/edisonduran/agent-did/blob/main/docs/RFC-001-Agent-DID-Specification.md) — a standard for decentralized AI agent identity extending W3C DIDs with agent-specific metadata.

**Conformance:** external evidence per standard is tracked in the [External Conformance Matrix](https://github.com/edisonduran/agent-did/blob/main/docs/External-Conformance-Matrix.md). The internal RFC-001 checklist (MUST 11/11, SHOULD 5/5) measures this SDK against our own specification, not against external standards.

## Current Limitations

- Default resolver is in-memory (not persistent) — use production resolver for real deployments
- Default replay store (`InMemoryNonceStore`) is per process — use a shared `NonceStore` when more than one instance verifies HTTP signatures
- Browsers: file-backed APIs are unavailable and HTTP sources need your own `fetchFn`; no browser build runs in CI (see [Browser Usage](#browser-usage))
- did:webvh domains: every label must have at least two characters and start with a letter (`x.com` and `3m.com` are refused). The Python did:webvh library (`did-webvh`) refuses other labels, and both SDKs accept only what both libraries resolve
- Optional EVM adapter assumes contract exposes `registerAgent`, `revokeAgent`, `getAgentRecord`, `isRevoked`
- EVM timestamps consumed as Unix-string, SDK normalizes to ISO-8601

## Maintainer Release to npm

The repository includes `.github/workflows/publish-sdk.yml` for npm Trusted Publishing with provenance.

Before the first release, create the `@agentdid/sdk` package in npm and register GitHub Trusted Publishing for:

- repository: `edisonduran/agent-did`
- workflow file: `.github/workflows/publish-sdk.yml`
- workflow trigger: tag `sdk-vX.Y.Z` for npm, or `workflow_dispatch` from `main`

Release preparation:

```bash
cd sdk
npm ci
npm run api:check
npm run api:signature:check
npm test -- --coverage --runInBand
npm run build
npm pack --dry-run
```

Release flow:

- bump `version` in `package.json`
- publish to npm by pushing a tag named `sdk-vX.Y.Z`
- alternatively, run the workflow manually from `main`
- verify the published npm release shows GitHub Actions provenance for `.github/workflows/publish-sdk.yml`

## Contributing

See [CONTRIBUTING.md](https://github.com/edisonduran/agent-did/blob/main/CONTRIBUTING.md)

## License

[Apache-2.0](../../LICENSE) — see root LICENSE.
