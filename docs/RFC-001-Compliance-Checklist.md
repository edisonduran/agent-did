# RFC-001 Compliance Checklist (Agent-DID)

## Purpose

This checklist translates RFC-001 v0.3 into verifiable controls to evaluate implementation conformance.

It reflects the current state of the repository after the pivot to Agent-DID as an application pattern on top of `did:webvh`. The canonical web-native runtime path now closes the Phase 5 default-semantics and controller-chain work across both SDKs; remaining partial controls are production-hardening SHOULD items rather than core MUST gaps.

Automated verification commands:

- `npm run conformance:rfc001`
- `python sdk-python/scripts/conformance_rfc001.py`

Scale used:

- **PASS:** Fully compliant.
- **PARTIAL:** Partially compliant / with limitations.
- **FAIL:** Not implemented or not verifiable.

---

## A. MUST Controls (Mandatory)

| ID | Control | Current Status | Evidence | Required Action |
| :-- | :-- | :-- | :-- | :-- |
| MUST-01 | Emit Agent-DID document with required fields (`id`, `controller`, `created`, `updated`, `agentMetadata.coreModelHash`, `agentMetadata.systemPromptHash`, `verificationMethod`, `assertionMethod`, `authentication`) and controller semantics compatible with RFC-001 v0.3 | PASS | `sdk/src/core/AgentIdentity.ts`, `sdk/tests/AgentIdentity.test.ts`, `sdk-python/src/agent_did_sdk/core/identity.py`, `sdk-python/tests/test_identity.py`, `sdk-python/scripts/conformance_rfc001.py` (both SDKs now emit canonical `did:webvh` identities by default, auto-bootstrap a local `did:webvh` controller root, and keep `did:agent` only as an explicit compatibility mode) | Maintain regression coverage for default and legacy compatibility paths. |
| MUST-02 | Support `create(params)` for the core agent-identity lifecycle | PASS | `sdk/src/core/AgentIdentity.ts`, `sdk/tests/AgentIdentity.test.ts`, `sdk/examples/quickstart.js`, `sdk-python/src/agent_did_sdk/core/identity.py`, `sdk-python/tests/test_identity.py`, `sdk-python/examples/did_wba_http_sign_verify.py` | Maintain the canonical default path and keep EVM/legacy examples explicitly fenced behind `did_method="agent"` or `didMethod: 'agent'`. |
| MUST-03 | Support `signMessage(payload, privateKey)` | PASS | `sdk/src/core/AgentIdentity.ts` | Add interoperable test vectors (future). |
| MUST-04 | Support `signHttpRequest(params)` with `@request-target`, `host`, `date`, `content-digest`, agent identity | PASS | `sdk/src/core/AgentIdentity.ts` (signs/verifies required components, supports multiple labels and signature dictionaries), `sdk/tests/AgentIdentity.test.ts` (positive/negative cases, tamper, unsupported algorithm, alternate labels, multiple signatures) | Maintain interoperable fixtures and continuous regression in CI. |
| MUST-05 | Support `resolve(did)` for the underlying DID method/profile used by the implementation, with `did:webvh` as the recommended/default path in RFC-001 v0.3 | PASS | `sdk/src/core/AgentIdentity.ts` (`useProductionResolver`, `useProductionResolverFromHttp`, `useProductionResolverFromJsonRpc`, `resolveControllerChain`), `sdk/src/resolver/UniversalResolverClient.ts` (cache + events + direct `did:wba` and `did:webvh` resolution), `sdk/src/resolver/WebvhDIDDocumentSource.ts`, `sdk/tests/UniversalResolverClient.test.ts`, `sdk/tests/WebvhDIDDocumentSource.test.ts`, `sdk/tests/AgentIdentity.test.ts`, `sdk/tests/InteropVectors.test.ts`, `sdk-python/src/agent_did_sdk/core/identity.py` (`use_production_resolver`, `use_production_resolver_from_http`, `use_production_resolver_from_json_rpc`, `resolve_controller_chain`), `sdk-python/src/agent_did_sdk/resolver/universal.py`, `sdk-python/src/agent_did_sdk/resolver/webvh_source.py`, `sdk-python/tests/test_universal_resolver.py`, `sdk-python/tests/test_webvh_source.py`, `sdk-python/tests/test_identity.py`, `sdk-python/scripts/conformance_rfc001.py` | Maintain direct `did.jsonl` resolution plus controller-chain regression coverage across both SDKs. |
| MUST-06 | Support `verifySignature(did, payload, signature)` with DID verification-relationship enforcement and failure on inactive/revoked state | PASS | `sdk/src/core/AgentIdentity.ts`, `sdk/src/core/identity-composition.ts`, `sdk/tests/AgentIdentity.test.ts`, `sdk-python/src/agent_did_sdk/core/identity.py`, `sdk-python/tests/test_identity.py`, `sdk-python/scripts/conformance_rfc001.py` (verification now resolves the canonical controller chain and returns `false` when the chain is inactive/unresolvable while preserving key-purpose enforcement) | Maintain policy-layer regression tests for inactive-controller and key-purpose cases. |
| MUST-07 | Support `revokeDid(did)` or DID-method-equivalent deactivation flow | PASS | `sdk/src/core/AgentIdentity.ts`, `sdk/tests/AgentIdentity.test.ts`, `sdk/src/registry/*`, `sdk-python/src/agent_did_sdk/core/identity.py`, `sdk-python/tests/test_identity.py`, `sdk-python/scripts/conformance_rfc001.py` | Maintain explicit documentation when profile-specific backends add stronger deactivation semantics. |
| MUST-08 | Evaluate active state via the underlying DID method or declared deployment profile, rather than requiring an on-chain registry for core conformance | PASS | `sdk/src/core/AgentIdentity.ts`, `sdk/src/resolver/UniversalResolverClient.ts`, `sdk/tests/AgentIdentity.test.ts`, `sdk-python/src/agent_did_sdk/core/identity.py`, `sdk-python/tests/test_identity.py`, `sdk-python/scripts/conformance_rfc001.py` (the canonical default path now evaluates active state through the resolvable `did:webvh` controller chain instead of an EVM-only assumption) | Keep the EVM registry documented as an optional overlay, not the conformance floor. |
| MUST-09 | Conformance verification: valid signature before revocation and invalid after | PASS | smoke + unit tests (`npm run smoke:e2e`) | Add external network scenario in CI. |
| MUST-10 | Support evolution cycle (`updated` + rotation or update of `verificationMethod`) | PASS | `sdk/src/core/AgentIdentity.ts`, `sdk/tests/AgentIdentity.test.ts` | Extend with historical version traceability (SHOULD). |
| MUST-11 | Support the canonical `did:webvh` default profile, or another DID method that preserves RFC-001 v0.3 semantics end-to-end | PASS | `sdk/src/core/AgentIdentity.ts`, `sdk/src/resolver/UniversalResolverClient.ts`, `sdk/src/resolver/WebvhDIDDocumentSource.ts`, `sdk/tests/AgentIdentity.test.ts`, `sdk/tests/UniversalResolverClient.test.ts`, `sdk/tests/WebvhDIDDocumentSource.test.ts`, `sdk/tests/InteropVectors.test.ts`, `sdk-python/src/agent_did_sdk/core/identity.py`, `sdk-python/src/agent_did_sdk/resolver/universal.py`, `sdk-python/src/agent_did_sdk/resolver/webvh_source.py`, `sdk-python/tests/test_identity.py`, `sdk-python/tests/test_universal_resolver.py`, `sdk-python/tests/test_webvh_source.py`, `sdk-python/tests/test_interop_vectors.py`, `sdk-python/scripts/conformance_rfc001.py` | Keep the canonical default path stable and preserve legacy/EVM behavior only as explicit compatibility profiles. |

---

## B. SHOULD Controls (Recommended)

| ID | Control | Current Status | Evidence | Recommended Action |
| :-- | :-- | :-- | :-- | :-- |
| SHOULD-01 | Universal resolver with cache and high availability across the default web-native profile | PASS | `sdk/src/resolver/UniversalResolverClient.ts` (resolution telemetry + direct `did:webvh`/`did:wba` paths), `sdk/src/resolver/HttpDIDDocumentSource.ts` (endpoint failover + IPFS gateways), `sdk/src/resolver/WebvhDIDDocumentSource.ts` (candidate URL failover for `did.jsonl`), `sdk/src/resolver/JsonRpcDIDDocumentSource.ts` (RPC endpoint failover), `sdk/src/core/AgentIdentity.ts` (`useProductionResolverFromHttp`, `useProductionResolverFromJsonRpc`), `scripts/resolver-ha-smoke.js`, `sdk-python/src/agent_did_sdk/resolver/webvh_source.py`, `sdk-python/scripts/resolver_ha_smoke.py`, `docs/RFC-001-Resolver-HA-Runbook.md`, `sdk/tests/UniversalResolverClient.test.ts`, `sdk/tests/HttpDIDDocumentSource.test.ts`, `sdk/tests/JsonRpcDIDDocumentSource.test.ts`, `sdk/tests/WebvhDIDDocumentSource.test.ts`, `sdk-python/tests/test_universal_resolver.py`, `sdk-python/tests/test_webvh_source.py` | Maintain periodic real-endpoint drills and alerting thresholds for production deployments. |
| SHOULD-02 | Homogeneous temporal normalization between SDK and contract layers | PASS | `sdk/src/core/time.ts`, `sdk/src/registry/EthersAgentRegistryContractClient.ts`, `sdk/tests/time.test.ts` | Maintain clear contracts: on-chain Unix-string, SDK exposes normalized ISO. |
| SHOULD-03 | Interoperable verification mode with external implementations and fixtures aligned to RFC-001 v0.3 | PASS | `fixtures/interop-vectors.json` (shared legacy + `did:webvh` vectors), `sdk/tests/InteropVectors.test.ts`, `sdk-python/tests/test_interop_vectors.py`, `sdk-python/scripts/conformance_rfc001.py`, `sdk/tests/AgentIdentity.test.ts`, `sdk-python/tests/test_identity.py`, `sdk/src/core/AgentIdentity.ts` (verifySignature/verifyHttpRequestSignature, `resolveControllerChain`) | Maintain shared fixtures and add third-party vectors as external implementations mature. |
| SHOULD-04 | Contract-level revocation access control policies | PASS | `contracts/src/AgentRegistry.sol` (`setRevocationDelegate`, `transferAgentOwnership`, `isRevocationDelegate`, `revokeAgent` with `owner\|delegate`), `contracts/scripts/revocation-policy-check.js`, `scripts/revocation-policy-smoke.js` | Maintain governance reviews and custodian rotation per release. |
| SHOULD-05 | Document evolution traceability by version | PASS | `sdk/src/core/AgentIdentity.ts`, `sdk/tests/AgentIdentity.test.ts` | Maintain historical persistence when migrating to external backend. |

---

## C. Executive Conformance Summary

- **MUST:** 11 PASS / 0 PARTIAL / 0 FAIL
- **SHOULD:** 5 PASS / 0 PARTIAL / 0 FAIL

Quick read:

1. The canonical `did:webvh` runtime path is now the shipped default across both SDKs, including local bootstrap controller roots and controller-chain-aware verification.
2. All RFC-001 MUST controls are now in PASS on the currently validated SDK surface.
3. The remaining work is production hardening beyond the current checklist floor: extending beyond the shipped filesystem-backed, writable HTTP, bearer/authenticated HTTP, presigned/object-storage, S3-compatible, and AWS SigV4 S3 adapters toward additional managed-provider integrations, maintaining the repo-managed public `did:webvh` smoke target set and recurring failure drills, and continuing to clarify optional EVM overlays.

---

## D. Suggested Hardening Plan (Prioritized)

Associated executable backlog:

- `docs/RFC-001-Implementation-Backlog.md`

### P2 (production)

1. Extend the current `did.jsonl` source-persistence hooks beyond the shipped filesystem-backed, writable HTTP, bearer/authenticated HTTP, presigned/object-storage, S3-compatible, and AWS SigV4 S3 adapters with additional managed-provider backends and backend recovery scenarios.
2. Maintain the shipped repo-managed public `did:webvh` smoke manifest and keep recurring failure-scenario drills beyond the current mocked HA coverage.
3. Normalize and document profile-specific active-state/revocation expectations between the web-native default and the optional EVM overlay.

---

## E. Exit Criteria ("RFC-001 conformant")

An implementation is marked as conformant when:

1. All MUST controls are in PASS.
2. At least 3 SHOULD controls are in PASS and none in FAIL for production deployment.
