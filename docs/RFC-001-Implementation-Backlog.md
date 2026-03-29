# RFC-001 Implementation Backlog

## Objective

Translate the findings from `RFC-001-Compliance-Checklist` into implementable work with priority, dependencies, and verifiable acceptance criteria.

---

## Epic P1 — Robust RFC-001 Conformance

### P1-01 — DID Document Evolution (`updateDidDocument`)

**Problem:** The RFC requires persistent identity with mutable state, but the SDK did not expose document update/versioning.

**Technical Scope:**

- Add `updateDidDocument(did, patch)` API in `AgentIdentity`.
- Validate that `id` remains stable and `updated` changes.
- Allow updates to `agentMetadata` (including hashes and capabilities).

**Acceptance Criteria:**

1. Public typed method exists in the SDK.
2. Tests cover successful update and rejection for non-existent/revoked DIDs.
3. `resolve(did)` returns updated document version.

**Dependencies:** None.

**Status:** ✅ Completed.

---

### P1-02 — Multiple `verificationMethod` Support + Key Rotation

**Problem:** `verifySignature` initially used only `verificationMethod[0]`; no rotation policy existed.

**Technical Scope:**

- Extend model for multiple active keys.
- Add rotation API (`rotateVerificationMethod` or equivalent).
- Update verifier to select key by `keyid` or controlled fallback.

**Acceptance Criteria:**

1. Verification works for new active key.
2. Revoked/obsolete key fails verification.
3. Tests cover at least 2 rotation cycles.

**Dependencies:** P1-01.

**Status:** ✅ Completed.

---

### P1-03 — Document Anchoring in Registry (`documentUri`/`documentHash`)

**Problem:** The RFC requires an on-chain reference to the document; the contract needed to store it.

**Technical Scope:**

- Extend `AgentRegistry.sol` with `documentUri` or `documentHash`.
- Update ABI/adapters (`EvmAgentRegistry`, `EthersAgentRegistryContractClient`).
- Register reference from `create` and update it from `updateDidDocument`.

**Acceptance Criteria:**

1. `getAgentRecord` returns document reference.
2. Smoke test verifies create + resolve using on-chain reference.
3. ABI compatibility documented (contract versioning).

**Dependencies:** P1-01.

**Status:** ✅ Completed.

---

## Epic P2 — Production and Interoperability

### P2-01 — Production Universal Resolver (RPC + IPFS + Cache)

**Problem:** Default in-memory resolver does not meet the operational interoperability objective.

**Technical Scope:**

- Create `UniversalResolverClient` with:
  - resolution by DID to on-chain record,
  - off-chain document fetch,
  - TTL cache.
- Maintain `InMemoryDIDResolver` for tests/local.

**Acceptance Criteria:**

1. Resolution works for DIDs not created in the local process.
2. Basic cache metrics (hit/miss) available.
3. Integration tests with network mock adapter.

**Dependencies:** P1-03.

**Status:** ✅ Completed.

---

### P2-02 — Temporal Normalization (ISO vs Unix)

**Problem:** SDK uses ISO-8601 and contract uses Unix-string.

**Technical Scope:**

- Define canonical format (recommended: ISO-8601 in document, Unix in contract with explicit conversion).
- Add utility converters and format validations.

**Acceptance Criteria:**

1. Temporal rule documented in RFC + checklist.
2. No ambiguity in SDK types/serialization.
3. Serialization/deserialization tests pass.

**Dependencies:** P1-03.

**Status:** ✅ Completed.

---

### P2-03 — Automated MUST/SHOULD Conformance Suite

**Problem:** Conformance was documented but not automated in a pipeline.

**Technical Scope:**

- Create `conformance:rfc001` suite.
- Map each MUST to a traceable test case.
- Add summarized compliance output.

**Acceptance Criteria:**

1. Pipeline reports status per control (PASS/PARTIAL/FAIL).
2. Suite fails if any MUST fails.
3. Execution evidence in local CI or workflow.

**Dependencies:** P1-01, P1-02, P1-03.

**Status:** ✅ Completed.

---

### P2-04 — Cross-SDK Canonicalization and Shared Fixtures

**Problem:** TypeScript and Python reached feature parity, but document reference hashing and timestamp serialization still needed an explicit canonical contract to guarantee deterministic interoperability.

**Technical Scope:**

- Canonicalize DID-document serialization before computing `documentRef` in both SDKs.
- Normalize ISO timestamps to a shared UTC `YYYY-MM-DDTHH:mm:ss.SSSZ` format.
- Move interop vectors to shared repository fixtures consumed by both SDK test suites.
- Clarify local Python commands versus monorepo `npm` wrappers.

**Acceptance Criteria:**

1. Equivalent DID documents produce the same `documentRef` in TypeScript and Python.
2. Shared fixtures are consumed by both SDK test suites.
3. Documentation explains the canonical Python workflow and the optional root-level wrappers.

**Dependencies:** P2-01, P2-02, P2-03.

**Status:** ✅ Completed.

---

## Recommended Execution Order

1. P1-01 ✅
2. P1-02 ✅
3. P1-03 ✅
4. P2-01 ✅
5. P2-02 ✅
6. P2-03 ✅
7. P2-04 ✅
8. P3-01 ✅
9. P3-02 ✅
10. P3-03 ✅
11. P3-04 ✅
12. P3-05 ✅
13. P3-06 ✅

---

## Epic P3 — Post-Analysis Remediation

### P3-01 — W3C Multibase Conformance

**Problem:** `publicKeyMultibase` used `z` + hex instead of the standard `z` + multicodec + Base58btc encoding.

**Technical Scope:**
- Implement `encodePublicKeyMultibase` / `decodePublicKeyMultibase` using Ed25519 multicodec prefix `0xed01` + Base58btc.
- Update `create()`, `verifySignature()`, `rotateVerificationMethod()` in both TS and Python SDKs.
- Update shared interop fixtures.

**Status:** ✅ Completed.

---

### P3-02 — Atomic Registration

**Problem:** `create()` generated identity and stored in registry as two separate steps. A failure between them could leave orphaned identities.

**Technical Scope:**
- Wrap identity creation + registry storage in atomic operation.
- Rollback on registry failure.

**Status:** ✅ Completed.

---

### P3-03 — HTTP Anti-Replay Protection

**Problem:** HTTP signature verification lacked nonce and expiration validation.

**Technical Scope:**
- Add `created`, `expires`, `nonce` to HTTP signature headers.
- Validate timestamps and reject expired/future signatures.

**Status:** ✅ Completed.

---

### P3-04 — Historical Signature Verification

**Problem:** After key rotation, signatures made with old keys could not be verified.

**Technical Scope:**
- Add `deactivated` field to `VerificationMethod` (ISO-8601 timestamp).
- `rotateVerificationMethod()` marks old keys as deactivated instead of removing them.
- New `verifyHistoricalSignature(did, payload, signature, keyId)` searches all methods including deactivated.

**Status:** ✅ Completed.

---

### P3-05 — Signer Abstraction Layer

**Problem:** `create()` returned raw private key hex. Production deployments need KMS/HSM/Vault integration.

**Technical Scope:**
- `AgentSigner` interface/protocol with `sign()` and `getPublicKey()`.
- `LocalKeySigner` wrapping current behavior.
- `create()`, `signMessage()`, `signHttpRequest()` accept optional signer.
- Demo mode (no signer) works as before.

**Status:** ✅ Completed.

---

### P3-06 — SSRF Hardening

**Problem:** HTTP validation only checked protocol scheme. No protection against loopback, private networks, or cloud metadata endpoints.

**Technical Scope:**
- `validateHttpTarget()` helper blocking loopback, private, link-local, metadata, and embedded credentials.
- `allowPrivateTargets` flag for dev/testing.
- Integrated into `HttpDIDDocumentSource`, `JsonRpcDIDDocumentSource`, `signHttpRequest()`.

**Status:** ✅ Completed.

---

## Global Definition of Done

A task is considered closed when:

1. Implementation merged into main branch.
2. Associated unit/integration tests green.
3. Documentation references updated (`RFC`, `Checklist`, `README`).
4. Relevant smoke executed without regressions.
