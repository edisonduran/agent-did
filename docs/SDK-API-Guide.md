# Agent-DID Reference SDK API Guide

> **Non-normative.** This guide describes the API of the two reference SDKs, `@agentdid/sdk` (TypeScript) and `agent-did-sdk` (Python), for release `1.0.0-rc.5`. The protocol is defined only by [RFC-001](RFC-001-Agent-DID-Specification.md): if this guide and the RFC disagree, the RFC governs. An independent implementation conforms through the behavior RFC-001 §10 requires, not by reproducing these names.

The text in this guide was part of RFC-001 (§7 and parts of §4 and §6) up to `1.0-rc.5`; it moved here so that the RFC states only the protocol.

The two SDKs keep the same API with language-idiomatic names (`camelCase` in TypeScript, `snake_case` in Python). Their public API is pinned by snapshots (`npm run api:check`), and the parity rules are in [F2-01-TS-Python-Parity-Matrix.md](F2-01-TS-Python-Parity-Matrix.md).

## 1. Entry points

The SDKs expose two entry points with the same operations:

- `AgentIdentity`: a convenience facade with a process-wide resolver and registry; instance methods create and sign, class-level methods resolve and verify.
- `AgentDidClient` / `agent_did_sdk.core.client`: the same operations on an instance with its own resolver, registry and stores. Use it when one process verifies for several configurations, or in tests.

Minimum operations, present in both SDKs:

| Operation | TypeScript | Python |
| :-- | :-- | :-- |
| Create an agent identity | `create(params)` | `create(params)` |
| Sign a payload (RFC-001 §6.2.3) | `signMessage(payload, keyOrSigner)` | `sign_message(payload, key_or_signer)` |
| Sign an HTTP request (§6.5) | `signHttpRequest(params)` | `sign_http_request(params)` |
| Resolve a DID | `resolve(did)` | `resolve(did)` |
| Verify a payload signature | `verifySignature(did, payload, signature, keyId?, requiredPurpose?)` | `verify_signature(...)` |
| Verify an HTTP request | `verifyHttpRequestSignature(params)` (boolean), `AgentDidClient.verifyHttpRequestSignatureDetailed(params)` (result with reason) | `verify_http_request_signature(params)`, `verify_http_request_signature_detailed(params)` |
| Deactivate the DID (§6.4) | `revokeDid(did, options?)` | `revoke_did(did, *, controller_signer=None)` |
| Check a key's relationship (§6.2.1) | `assertKeyPurpose(keyId, didDoc, requiredPurpose)` | `assert_key_purpose(...)` |

`keyOrSigner` / `key_or_signer` is a private key or an `AgentSigner` (KMS, HSM or any other signer behind the abstraction; RFC-001 §6.6 item 2).

## 2. RFC flows and the SDK API

| RFC flow | Reference SDK API |
| :-- | :-- |
| Identity Registration (§6.1) | `AgentIdentity.create(params)` |
| Payload Signing (§6.2.3) | `signMessage(payload, keyOrSigner)` |
| HTTP Signing (§6.5) | `signHttpRequest(params)` |
| DID Resolution (§6.2) | `AgentIdentity.resolve(did)` |
| Controller Documents (§4.2.1) | `AgentDidClient.resolveDocument(did)` / `resolveControllerChain(did)` (DID Core documents, `DidDocument`); Python `resolve_document` / `resolve_controller_chain` |
| Signature Verification (§6.2) | `AgentIdentity.verifySignature(...)` and `verifyHttpRequestSignature(...)` |
| Verification Relationship Binding (§6.2.1) | `assertKeyPurpose(...)` / `assert_key_purpose(...)`, default `assertionMethod` |
| Key Validity at a Stated Time (§6.2.2) | `AgentDidClient.verifySignatureAtTime(did, payload, signature, keyId, { statedTime, timestampToken?, tsaTrustAnchors? })`, `checkDidWebvhKeyAtTime(log, ...)`, `verifyTimestampToken(token, signatureBytes, { trustAnchors })`, `createTimestampRequest(signatureBytes)`; Python adds the `timestamps` extra. `verifyHistoricalSignature` was removed in `1.0.0-rc.5`: it accepted a retired key without any time check |
| Agent Metadata Credential (§4.4) | `AgentDidClient.issueAgentMetadataCredential(params)` / `verifyAgentMetadataCredential(credential)`; Python `issue_agent_metadata_credential` / `verify_agent_metadata_credential` |
| Document Evolution (§6.3) | `updateDidDocument(did, patch)` |
| Key Rotation (§6.6 item 3) | `rotateVerificationMethod(did, { emergency })`: marks old keys as `deactivated` (and `revoked` with `emergency`) |
| Single-Key Retirement (§6.6 item 3) | `AgentDidClient.retireVerificationMethod(did, keyId, { emergency })` / Python `retire_verification_method` |
| Identity Composition (§6.2.1.1) | `signAgentCard(card, signer, keyId)`, `AgentDidClient.verifyAgentCard(card)` / `verifyIdentityComposition({ ...request, agentCard })`; Python `sign_agent_card`, `verify_agent_card`, `verify_identity_composition` |
| Revocation (§6.4) | `revokeDid(did)` |
| Capabilities (§6.7) | `AgentDidClient.createCapability(params)`, `verifyCapabilityChain(capability, { rootControllers })`, `verifyHttpCapabilityInvocation({ ...request, rootControllers })`, option `capability` of `signHttpRequest`; Python `create_capability`, `verify_capability_chain`, `verify_http_capability_invocation`, `SignHttpRequestParams.capability` |
| OAuth Client Authentication (§6.8) | `createClientAssertion(params)`, `buildClientJwks(document)`, `buildClientMetadataDocument(params)`, `AgentDidClient.verifyClientAssertion(params)`; Python `create_client_assertion`, `build_client_jwks`, `build_client_metadata_document`, `verify_client_assertion` |
| did:webvh Witnesses (§6.1) | `webvh.witness` at creation, `AgentDidClient.setDidWebvhWitnesses(did, witness \| null)`, `exportDidWebvhWitnessFile(did)`, option `collectWitnessProofs`; a witness approves with `createDidWebvhWitnessProof(...)`. Python `set_did_webvh_witnesses`, `export_did_webvh_witness_file`, `collect_witness_proofs`, `create_did_webvh_witness_proof` |
| Production Resolver (§5.3) | `useProductionResolverFromHttp(...)`, `useProductionResolverFromJsonRpc(...)` |
| Optional EVM Integration (§5.3) | `@agentdid/evm` / `agent-did-evm` (`EvmAgentRegistry`), in `edisonduran/agent-did-evm` |

## 3. SDK behavior behind RFC sections

### 3.1 Verification relationships (RFC-001 §6.2.1, §6.2.1.3)

- The table of RFC-001 §6.2.1.3 is one public constant, `REQUIRED_RELATIONSHIP_BY_ARTIFACT`, with the lookup `requiredRelationshipFor` / `required_relationship_for`. The SDKs use it wherever they choose a default relationship, and both run `fixtures/verification-relationship-vectors.json`.
- `assertKeyPurpose` / `assert_key_purpose` is a membership-only predicate over the requested relationship and does not short-circuit on `keyAgreement`. The rule that `keyAgreement` never signs lives in `assertSigningPurpose` / `assert_signing_purpose`, which the SDKs call before `assertKeyPurpose` during signature verification.
- Documents created by the SDKs list the agent key under `authentication` and `assertionMethod`. A DID that issues delegations or invokes capabilities needs its key under `capabilityDelegation` or `capabilityInvocation`; the SDKs add those relationships only on request (`additionalVerificationRelationships` / `additional_verification_relationships` at creation, accepting `capabilityDelegation` and `capabilityInvocation`). Without the option the document is the same as in earlier releases. When the agent key is rotated, the new key joins each of those relationships that listed a key the rotation deactivates.

### 3.2 Identity-composition errors (RFC-001 §6.2.1.1)

The SDKs raise `IdentityCompositionError` with the members of RFC-001 §6.2.1.1 as direct properties, in the language's naming:

| RFC member | TypeScript | Python |
| :-- | :-- | :-- |
| reason | `reason` | `reason` |
| key identifier | `keyId` | `key_id` |
| required relationship | `requiredPurpose` | `required_purpose` |
| relationships where the key was found | `foundIn` | `found_in` |
| subject DID (optional) | `did` | `did` |

An implementation MAY also mirror these values under a `context` namespace (for example `error.context.keyId`) for verifiers that expect a nested envelope, provided the direct properties stay authoritative and the mirrored values are equal to them. The reference SDKs do not add the mirror.

### 3.3 Controller documents (RFC-001 §4.2.1)

The SDKs read DID Core controller documents for `did:webvh` DIDs (`resolveDocument` / `resolve_document`). For other DID methods their document sources still return Agent-DID documents only.

### 3.4 Key validity at a stated time (RFC-001 §6.2.2)

The check is `checkDidWebvhKeyAtTime` / `check_did_webvh_key_at_time` over a verified log, and `verifySignatureAtTime` / `verify_signature_at_time` over a resolved DID (option `timestampToken` / `timestamp_token` with TSA trust anchors). The token check alone is `verifyTimestampToken` / `verify_timestamp_token`. Payload signatures are verified against the prefixed bytes of RFC-001 §6.2.3 in both functions.

### 3.5 Agent Metadata Credential (RFC-001 §4.4)

The SDKs never fetch a `LinkedVerifiablePresentation` while resolving a DID.

## 4. Minimum end-to-end flow (onboarding)

1. Create the agent identity with `create(params)`.
2. Sign a payload with `signMessage`.
3. Verify that payload with `verifySignature` using the issued DID.
4. Resolve the DID with `resolve` and check that it is active.
5. Revoke with `revokeDid` and confirm that later verification fails.

Executable examples:

- `sdk/examples/quickstart.js`
- `scripts/e2e-smoke.js` and `sdk-python/scripts/e2e_smoke.py` (`npm run smoke:e2e`)

The optional EVM profile examples are in `edisonduran/agent-did-evm`. Full validation: `npm run conformance:rfc001` (Python: `npm run python:conformance`).

## 5. Errors and results

| Situation | SDK behavior |
| :-- | :-- |
| DID not found | Resolution fails (`DID not found` or the resolver's equivalent). |
| DID deactivated | `resolve` / `verifySignature` fail or return `false`. |
| Invalid signature or tampered payload | `verifySignature` returns `false`. |
| Key not under the required relationship | Raises or reports `key_purpose_violation` with the relationships where the key was found (§3.2). |
| HTTP request that does not meet RFC-001 §6.5 | `verifyHttpRequestSignature` returns `false`; the detailed variant returns the reason. A request whose `keyid` is not an `assertionMethod` key of the agent DID is a rejection, never an exception. |
| Unresolvable DID document or history entry | The resolver tries its other sources for availability failures only; if all fail, it raises. Integrity failures never fall back (RFC-001 §6.2, §6.6 item 4). |

## 6. Tests that run the shared vectors

The vectors listed in RFC-001 §7.2 are run by, among others: `sdk/tests/InteropVectors.test.ts`, `sdk/tests/HttpVerificationVectors.test.ts`, `sdk/tests/crypto.test.ts`, `sdk-python/tests/test_interop_vectors.py` and `sdk-python/tests/test_http_verification_vectors.py`. `npm run interop:check` runs the shared fixtures in both SDKs.

---

**License:** Apache-2.0
