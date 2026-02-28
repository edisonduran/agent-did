# RFC-001 Compliance Checklist (Agent-DID)

## Purpose

This checklist translates RFC-001 into verifiable controls to evaluate implementation conformance.

Automated verification command:

- `npm run conformance:rfc001`

Scale used:

- **PASS:** Fully compliant.
- **PARTIAL:** Partially compliant / with limitations.
- **FAIL:** Not implemented or not verifiable.

---

## A. MUST Controls (Mandatory)

| ID | Control | Current Status | Evidence | Required Action |
| :-- | :-- | :-- | :-- | :-- |
| MUST-01 | Emit Agent-DID document with required fields (`id`, `controller`, `created`, `updated`, `agentMetadata.coreModelHash`, `agentMetadata.systemPromptHash`, `verificationMethod`, `authentication`) | PASS | `sdk/src/core/types.ts`, `sdk/src/core/AgentIdentity.ts` | Maintain schema regression tests. |
| MUST-02 | Support `create(params)` | PASS | `sdk/src/core/AgentIdentity.ts` | None immediate. |
| MUST-03 | Support `signMessage(payload, privateKey)` | PASS | `sdk/src/core/AgentIdentity.ts` | Add interoperable test vectors (future). |
| MUST-04 | Support `signHttpRequest(params)` with `@request-target`, `host`, `date`, `content-digest`, agent identity | PASS | `sdk/src/core/AgentIdentity.ts` (signs/verifies required components, supports multiple labels and signature dictionaries), `sdk/tests/AgentIdentity.test.ts` (positive/negative cases, tamper, unsupported algorithm, alternate labels, multiple signatures) | Maintain interoperable fixtures and continuous regression in CI. |
| MUST-05 | Support `resolve(did)` | PASS | `sdk/src/core/AgentIdentity.ts` (`useProductionResolver`, `useProductionResolverFromHttp`, `useProductionResolverFromJsonRpc`), `sdk/src/resolver/UniversalResolverClient.ts` (cache + events), `sdk/src/resolver/HttpDIDDocumentSource.ts` (multi-endpoint failover + `ipfs://` gateways), `sdk/src/resolver/JsonRpcDIDDocumentSource.ts` (RPC failover), `sdk/tests/UniversalResolverClient.test.ts`, `sdk/tests/HttpDIDDocumentSource.test.ts`, `sdk/tests/JsonRpcDIDDocumentSource.test.ts`, `scripts/rpc-resolver-smoke.js` | Maintain operational monitoring and periodic testing against real infrastructure. |
| MUST-06 | Support `verifySignature(did, payload, signature)` and fail if revoked | PASS | `sdk/src/core/AgentIdentity.ts`, tests | Maintain tests with `keyId` and rotation. |
| MUST-07 | Support `revokeDid(did)` | PASS | `sdk/src/core/AgentIdentity.ts`, `sdk/src/registry/*` | Add explicit authorization policy in interfaces. |
| MUST-08 | Registry with minimum operations (`registerAgent`, `revokeAgent`, `getAgentRecord`, `isRevoked`) | PASS | `contracts/src/AgentRegistry.sol`, `sdk/src/registry/*` | Maintain stable and versioned ABI. |
| MUST-09 | Conformance verification: valid signature before revocation and invalid after | PASS | smoke + unit tests (`npm run smoke:e2e`) | Add external network scenario in CI. |
| MUST-10 | Support evolution cycle (`updated` + rotation or update of `verificationMethod`) | PASS | `sdk/src/core/AgentIdentity.ts`, `sdk/tests/AgentIdentity.test.ts` | Extend with historical version traceability (SHOULD). |
| MUST-11 | Minimum on-chain/off-chain separation with document reference | PASS | `contracts/src/AgentRegistry.sol`, `sdk/src/core/AgentIdentity.ts`, `sdk/src/registry/*`, `npm run smoke:e2e` | Maintain ABI compatibility and versioning. |

---

## B. SHOULD Controls (Recommended)

| ID | Control | Current Status | Evidence | Recommended Action |
| :-- | :-- | :-- | :-- | :-- |
| SHOULD-01 | Universal serverless resolver with cache and high availability | PASS | `sdk/src/resolver/UniversalResolverClient.ts` (resolution telemetry), `sdk/src/resolver/HttpDIDDocumentSource.ts` (endpoint failover + IPFS gateways), `sdk/src/resolver/JsonRpcDIDDocumentSource.ts` (RPC endpoint failover), `sdk/src/core/AgentIdentity.ts` (`useProductionResolverFromHttp`, `useProductionResolverFromJsonRpc`), `scripts/resolver-ha-smoke.js`, `docs/RFC-001-Resolver-HA-Runbook.md`, `sdk/tests/UniversalResolverClient.test.ts`, `sdk/tests/HttpDIDDocumentSource.test.ts`, `sdk/tests/JsonRpcDIDDocumentSource.test.ts` | Maintain periodic HA drill execution and SLO/alert review per release. |
| SHOULD-02 | Homogeneous temporal normalization between SDK and contract layers | PASS | `sdk/src/core/time.ts`, `sdk/src/registry/EthersAgentRegistryContractClient.ts`, `sdk/tests/time.test.ts` | Maintain clear contracts: on-chain Unix-string, SDK exposes normalized ISO. |
| SHOULD-03 | Interoperable verification mode with external implementations | PASS | `sdk/tests/fixtures/interop-vectors.json`, `sdk/tests/InteropVectors.test.ts`, `sdk/src/core/AgentIdentity.ts` (verifySignature/verifyHttpRequestSignature) | Maintain and version shared fixtures per release. |
| SHOULD-04 | Contract-level revocation access control policies | PASS | `contracts/src/AgentRegistry.sol` (`setRevocationDelegate`, `transferAgentOwnership`, `isRevocationDelegate`, `revokeAgent` with `owner\|delegate`), `contracts/scripts/revocation-policy-check.js`, `scripts/revocation-policy-smoke.js` | Maintain governance reviews and custodian rotation per release. |
| SHOULD-05 | Document evolution traceability by version | PASS | `sdk/src/core/AgentIdentity.ts`, `sdk/tests/AgentIdentity.test.ts` | Maintain historical persistence when migrating to external backend. |

---

## C. Executive Conformance Summary

- **MUST:** 11 PASS / 0 PARTIAL / 0 FAIL
- **SHOULD:** 5 PASS / 0 PARTIAL / 0 FAIL

Quick read:

1. The functional core of the standard is operational for create/sign/resolve/verify/revoke.
2. No MUST gaps: all mandatory controls are in PASS.
3. The main production gap is a real universal resolver (currently in-memory by default).

---

## D. Suggested Closure Plan (Prioritized)

Associated executable backlog:

- `docs/RFC-001-Implementation-Backlog.md`

### P1 (blocking for robust conformance)

1. ✅ Completed.

### P2 (production)

1. Implement universal resolver (RPC + IPFS + cache).
2. Normalize timestamps (ISO or Unix, single canonical format).
3. Add external network smoke test (`smoke:e2e:ci`).

---

## E. Exit Criteria ("RFC-001 conformant")

An implementation is marked as conformant when:

1. All MUST controls are in PASS.
2. At least 3 SHOULD controls are in PASS and none in FAIL for production deployment.
