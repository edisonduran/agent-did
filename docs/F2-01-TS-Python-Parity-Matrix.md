# F2-01 — TS ↔ Python SDK Parity Matrix

## Objective

Define the operational parity contract between the TypeScript SDK in `sdk/` and the Python SDK in `sdk-python/`.

This document is the source of truth for answering:

1. What parity means in this repository.
2. Which capabilities are already equivalent.
3. Which checks are required before calling the SDKs "at parity".
4. Which gaps remain open after functional parity is reached.

---

## Scope of Parity

Parity in this project is defined across four dimensions:

1. **API surface parity**
   The two SDKs expose equivalent capability families, even if language idioms differ (`camelCase` vs `snake_case`).

2. **Behavioral parity**
   Equivalent inputs must produce equivalent RFC-001 behavior.

3. **Interoperability parity**
   Shared fixtures, canonical timestamps, and canonical `documentRef` generation must agree across both SDKs.

4. **Quality-gate parity**
   Each SDK must be protected by stack-appropriate CI, tests, conformance, and smoke validation.

---

## Canonical Local Commands

### TypeScript SDK

```bash
cd sdk
npm test
npm run build
```

### Python SDK

```bash
cd sdk-python
python -m pip install -e ".[dev]"
python -m ruff check src/ tests/ scripts/
python -m mypy --strict src/
python -m pytest tests/ -q
python scripts/conformance_rfc001.py
```

### Monorepo Convenience Wrappers

These wrappers exist for convenience only and do **not** replace the canonical Python workflow:

```bash
npm run python:install-dev
npm run python:test
npm run python:conformance
```

---

## Shared Interoperability Artifacts

The following files define the cross-language contract:

- `fixtures/interop-vectors.json`
- `fixtures/canonical-document-reference.json`

They are consumed by:

- `sdk/tests/InteropVectors.test.ts`
- `sdk/tests/crypto.test.ts`
- `sdk-python/tests/test_interop_vectors.py`
- `sdk-python/tests/test_crypto.py`

---

## Parity Matrix

| Capability Family | TypeScript Reference | Python Reference | Status | Notes |
|---|---|---|---|---|
| Package entrypoint | `sdk/src/index.ts` | `sdk-python/src/agent_did_sdk/__init__.py` | ✅ | Public surface intentionally mirrors capability families, not language syntax. |
| Identity creation | `AgentIdentity.create` | `AgentIdentity.create` | ✅ | Same RFC-001 lifecycle role. |
| Message signing | `signMessage` | `sign_message` | ✅ | Ed25519 in both SDKs. |
| Message verification | `verifySignature` | `verify_signature` | ✅ | Revocation-aware in both SDKs. |
| HTTP signing | `signHttpRequest` | `sign_http_request` | ✅ | Shared Bot Auth model. |
| HTTP verification | `verifyHttpRequestSignature` | `verify_http_request_signature` | ✅ | Shared header semantics and interop vectors. |
| DID resolution | `resolve` | `resolve` | ✅ | Resolver abstraction aligned. |
| DID revocation | `revokeDid` | `revoke_did` | ✅ | Registry-backed and history-aware. |
| DID update | `updateDidDocument` | `update_did_document` | ✅ | Preserves DID and updates metadata. |
| Verification key rotation | `rotateVerificationMethod` | `rotate_verification_method` | ✅ | Active authentication key switches to the latest key. |
| Document history | `getDocumentHistory` | `get_document_history` | ✅ | Same lifecycle events tracked. |
| In-memory resolver | `InMemoryDIDResolver` | `InMemoryDIDResolver` | ✅ | Testing/local reference implementation. |
| Universal resolver | `UniversalResolverClient` | `UniversalResolverClient` | ✅ | Cache, registry lookup, document source, fallback. |
| HTTP DID document source | `HttpDIDDocumentSource` | `HttpDIDDocumentSource` | ✅ | SSRF-sensitive paths covered in tests. |
| JSON-RPC DID document source | `JsonRpcDIDDocumentSource` | `JsonRpcDIDDocumentSource` | ✅ | Failover and validation present in both SDKs. |
| In-memory registry | `InMemoryAgentRegistry` | `InMemoryAgentRegistry` | ✅ | Same lifecycle semantics. |
| EVM registry adapter | `EvmAgentRegistry` + ethers client | `EvmAgentRegistry` + web3 client | ✅ | Client library differs, capability family is equivalent. |
| Time normalization | `normalizeTimestampToIso` | `normalize_timestamp_to_iso` | ✅ | Canonical UTC millisecond format now aligned. |
| Canonical document hashing | `generateCanonicalDocumentHash` (internal helper path) | `generate_canonical_document_hash` (internal helper path) | ✅ | Deterministic `documentRef` agreement now enforced by shared fixtures. |
| Shared conformance suite | `scripts/conformance-rfc001.js` | `sdk-python/scripts/conformance_rfc001.py` | ✅ | Both report 11/11 MUST and 5/5 SHOULD. |
| Shared interoperability fixtures | Root `fixtures/` | Root `fixtures/` | ✅ | Single source of truth for cross-language parity. |
| CI protection | `.github/workflows/ci.yml` | `.github/workflows/ci-python.yml` | ✅ | Separate pipelines; equivalent intent. |

---

## Quality Gates Required for Parity

### TypeScript

1. `npm --prefix sdk test`
2. `npm --prefix sdk run build`
3. RFC-001 conformance through the repo root workflow

### Python

1. `python -m ruff check src/ tests/ scripts/`
2. `python -m mypy --strict src/`
3. `python -m pytest tests/ -q`
4. `python scripts/conformance_rfc001.py`
5. Python smoke suite in `.github/workflows/ci-python.yml`

### Cross-SDK

1. Shared fixture verification must pass in both SDKs.
2. Equivalent DID documents must yield the same canonical `documentRef`.
3. Timestamp normalization must converge to the same serialized UTC output.

---

## Current Status

### Achieved

1. Functional parity is implemented.
2. Canonical `documentRef` generation is aligned.
3. Timestamp normalization is aligned.
4. Shared interoperability fixtures are active.
5. TypeScript and Python both pass their relevant validation suites.
6. Python CI remains separate, but no longer weaker in intent than TypeScript CI.

### Remaining Non-Blocking Gaps

1. Public export symmetry is not fully literal.
   Some canonicalization helpers are used as internal contract helpers rather than promoted API surface in both languages.

2. Documentation parity outside the core SDK tracks is still evolving.
   Integration docs that were written when Python was still roadmap-first may still need language updates.

3. Release-process parity should be formalized further.
   The repository now has quality parity, but a single release checklist spanning npm and Python packaging would still improve consistency.

---

## Definition of Done

TS ↔ Python parity is considered maintained when all of the following remain true:

1. The parity matrix above remains accurate.
2. Shared fixtures continue to pass in both SDKs.
3. Both CI workflows remain green on relevant changes.
4. New RFC-001 capabilities are added to both SDKs or explicitly documented as exceptions.
5. Documentation does not describe the Python SDK as future work when the capability already exists.

---

## Recommended Follow-Up

1. Add this matrix to release review for SDK changes via `docs/SDK-Release-Checklist.md`.
2. Extend the same parity discipline to future Python integrations.
3. Keep the release checklist aligned with CI and packaging changes.