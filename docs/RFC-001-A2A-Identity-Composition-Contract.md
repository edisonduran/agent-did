# A2A Identity Composition Contract

> **Status**: Landing for `main` — promoted from DRAFT after all five sections (§4.3, §4.4, §5, §6.3, §6.4) reached APS-confirmed posture. Co-drafted with `@aeoess` (APS) on `spec/a2a-composition-contract`. Final review pass requested via PR.
> **Tracking issue**: [#30](https://github.com/edisonduran/agent-did/issues/30)
> **Upstream thread**: [a2aproject/A2A#1742](https://github.com/a2aproject/A2A/issues/1742)
> **Co-drafting workflow** (now closed for substantive content; future revisions go through PR review against `main`): both sides edited / reviewed / counter-drafted on the `spec/a2a-composition-contract` branch until rotation-window edge cases and verifier-side semantics were tight enough to land in RFC-001 and propose normative text upstream in A2A.
> **Co-author push access**: `@aeoess` invited as repo collaborator (Write) 2026-04-30, scoped operationally to `spec/a2a-composition-contract` (`develop` and `main` are protected, require PR + 1 review).
> **Sync state with APS**: All five sections (§4.3, §4.4, §5, §6.3, §6.4) are **APS-confirmed**. §4.3, §4.4, §6.3, §6.4 confirmed by `@aeoess` via direct push (commits `3fc38384` and `da473ee3`, 2026-04-30 / 2026-05-01). §5 (Error shape) confirmed by `@aeoess` via [a2aproject/A2A#1742 comment 2026-05-01 23:52 UTC](https://github.com/a2aproject/A2A/issues/1742#issuecomment-4362194636) under the explicit superset-with-aliases contract documented inline; flip applied by `@edisonduran` via commit `0e6a5d4c` on aeoess's behalf with text reflecting his 2026-05-01 23:52 UTC posture verbatim. When aeoess pushes commits directly against the spec branch, those commits are authoritative over the working baseline.
>
> **APS-aligned pre-pass (2026-04-30)**: §0 (threat model), §1.1 (canonicalization split), §4.1 scenario 3e (unknown DID method), §3.1 (wire shape reference), §8 (test vectors), §9 (vocabulary) below were added unilaterally by Agent-DID after analyzing publicly inspectable APS infrastructure (`agent-passport-system`, `aps-conformance-suite`, `a2a-compliance-harness`, `agent-governance-vocabulary`). Each carries `[APS-aligned pre-pass, open to revision in counter-draft]`. Counter-draft from `@aeoess` is authoritative over this pre-pass.

## 0. Threat model `[APS-aligned pre-pass, open to revision in counter-draft]`

This composition contract addresses, at minimum, the following AIVSS (Agentic AI Vulnerability Scoring System) categories from the OWASP AIVSS framework §3.6 *Agent Authentication & Identity*:

- **AIVSS §3.6.5 Identity Impersonation** — a request signed under key material that is not legitimately associated with the claimed agent identity. The composition contract closes this by requiring the per-request `keyid` to be a member of the Agent Card published key material modulated by the rotation state machine (§2, §4).
- **AIVSS §3.6.2 Access Control Violation** — a request whose signing key is technically valid for the agent but is not authorized for the requested verification purpose. The composition contract closes this via the `assertionMethod` purpose-scoping requirement (§6.3).

Out of scope for this draft, recorded as adjacent threat surfaces:

- AIVSS §3.6.3 *Privilege Escalation* across delegation chains — covered by the broader RFC-001 delegation model, not by this composition contract.
- AIVSS §3.6.7 *Replay attacks* — covered by RFC 9421 `nonce` + `created` window at the per-request signature layer, not by this composition contract.

The threat model anchor is consistent with APS posture and with the OWASP AIVSS categorization used by [`a2a-compliance-harness`](https://github.com/aeoess/a2a-compliance-harness).

## 1. Scope

Defines the composition contract between two distinct identity surfaces in an A2A-conformant agent system:

- **Identity-at-rest** — Agent Card, signed at publish time, durable for the lifetime of a key.
- **Identity-in-motion** — per-request signature (RFC 9421 HTTP signatures profile), signed at request time over a freshly canonicalized payload, ephemeral as a single message.

The composition contract is the normative requirement that ties them together so that neither surface becomes self-attesting in isolation.

### 1.1 Canonicalization split `[APS-aligned pre-pass, open to revision in counter-draft]`

The two identity surfaces use **different canonicalization rules** by design, and both are normative:

| Surface | Canonicalization | Signature mechanism | Lifetime |
|---------|------------------|---------------------|----------|
| Agent Card body (identity-at-rest) | **RFC 8785 JCS** (JSON Canonicalization Scheme); `signature` field stripped before canonicalization (detached-signature style) | Detached Ed25519 over JCS-canonical bytes | Lifetime of the published key |
| Per-request (identity-in-motion) | **RFC 9421 §2** signature base (component canonicalization over `@signature-params` + selected headers) | RFC 9421 HTTP Message Signature, Ed25519 | Single message |

The two coexist because they answer different questions: the Card answers "which keys is this agent authorized to sign with, and is that authorization signed?", the per-request signature answers "is this exact byte sequence authentic right now?". Mixing the two canonicalizations would not improve either property and would break interop with both `aps-conformance-suite` (which assumes JCS for the Card) and the RFC 9421 ecosystem (which assumes its own component canonicalization for HTTP messages).

## 2. Normative requirement

> **MUST**: an A2A-conformant verifier MUST cross-check the per-request signature's key material against the key material published in the Agent Card associated with the signing agent's identity.
>
> Mismatch MUST cause the request to be rejected with an `IdentityCompositionError`.

Placement target in upstream A2A: **core spec normative section** (not security-considerations, not a separate identity-composition section). Rationale: the contract changes what "interop" means; alternative placements would let an implementation skip the cross-check and still claim conformance.

## 3. Resolution path (this SDK)

For `did:` based identities resolved through DID document verification material:

1. Verifier extracts `keyid` from the per-request signature (RFC 9421 `keyid` parameter).
2. Verifier resolves the signing agent's DID → DID document → verification material.
3. Verifier resolves the signing agent's Agent Card → published key material (JWKS or equivalent).
4. Verifier asserts: `keyid` ∈ DID-document-verification-material ∩ Agent-Card-published-keys (subject to rotation rules in §4 and key-purpose scoping in §6.3).

Mismatch at step 4 → `IdentityCompositionError(reason=...)`.

### 3.1 Wire shape reference `[APS-aligned pre-pass, open to revision in counter-draft]`

For cross-implementation interop with [`a2a-compliance-harness`](https://github.com/aeoess/a2a-compliance-harness), Agent Card bodies SHOULD follow the wire shape assumed by that harness:

```json
{
  "name": "...",
  "description": "...",
  "issuer": "did:webvh:example.com:organizations:acme-support",
  "capabilities": ["..."],
  "schema_version": "...",
  "signature": { "alg": "EdDSA", "kid": "did:webvh:example.com:agents:supportbot-x#key-1", "value": "<base64url>" },
  "delegation_chain": []
}
```

The `signature` field is stripped before JCS canonicalization (§1.1). The `kid` follows the DID URL fragment convention (`did:method:identifier#fragment`) and is the key whose membership the verifier checks per §2. Implementations MAY add fields beyond this shape; the listed fields MUST be present and MUST canonicalize identically across implementations for the harness to accept the Card.

### 3.2 Canonical `did:webvh` controller-to-agent composition path

Under RFC-001 v0.3, the canonical Agent-DID composition path is a `did:webvh` agent controlled by another `did:webvh` identity higher in the trust chain.

Reference pattern:

1. **Controller/root DID:** `did:webvh:example.com:organizations:acme-support`
2. **Agent DID:** `did:webvh:example.com:agents:supportbot-x`
3. **Agent DID document:** lists the controller DID above and publishes the signing key under the required DID verification relationship.
4. **Controller `/whois` evidence:** publishes KYB or equivalent organizational evidence binding the controller DID to a legal entity.
5. **Optional agent `/whois` evidence:** publishes role, lifecycle, or operational claims specific to the agent.

Verifier behavior for the canonical pattern:

- Resolve the agent DID and verify that the per-request `keyid` is authorized both by the DID document and by the Agent Card.
- If policy requires organizational or legal accountability, recurse to the controller DID and evaluate its `/whois` evidence or attached VC chain.
- Treat the controller recursion as policy-layer trust expansion on top of the composition contract, not as a replacement for the per-request key cross-check.

Scenario 3e (§4.1) remains valid as a compatibility backstop when a verifier encounters an unsupported DID method. It is not the expected mainline path for Agent-DID deployments after the `did:webvh` pivot.

## 4. Key rotation state machine

Rotation modes:

- **Planned mode** — configurable overlap window. Both prior and current keys are listed in the resolved DID document for the duration of the overlap.
- **Emergency mode** — immediate retirement of the prior key. Prior key transitions to `revoked` state in the DID document with no overlap.

### 4.1 Conformance scenarios (4 required)

| # | Scenario | Expected verifier behavior |
|---|----------|----------------------------|
| 3a | Signature under **current key** during planned overlap window | Accept. |
| 3b | Signature under **prior key** during planned overlap window, prior key still listed in resolved DID document | Accept. |
| 3c | Signature under **prior key** after planned overlap window has closed | Reject with `IdentityCompositionError(reason="rotation_window_closed" / "OverlapWindowExceeded")`. |
| 3d | Signature under **emergency-revoked prior key** at any time | Reject with `IdentityCompositionError(reason="emergency_revoked" / "EmergencyRevokedKey")`, regardless of in-flight signature timestamps or resolver cache state. |
| 3e | Signature whose `keyid` resolves through a **DID method the verifier does not support** `[APS-aligned pre-pass, open to revision in counter-draft]` | **Degrade gracefully**: do NOT fail-closed. Mark the verification result with `did_resolver_unsupported` and surface it to the calling policy layer. The composition contract is undefined for unknown DID methods; failing closed would penalize agents using methods not yet registered with the verifier and contradicts APS posture (per `a2a-compliance-harness/README.md`). In the canonical Agent-DID profile this is a compatibility fallback, not the expected `did:webvh` path. |

### 4.2 Resolver cache hazard

A `did:` resolver honoring a 24h-cached DID document during a 1-hour emergency rotation is a silent failure. Conformance MUST be tested against the verifier's externally observable behavior (the 4 scenarios above), not against the resolver's caching strategy. Implementations that defer to a cached resolver are responsible for cache-invalidation semantics that satisfy scenario 3d.

### 4.3 Default overlap window — spec vs verifier-policy knob `[APS-confirmed via aeoess push 2026-04-30]`

Working baseline carried from APS posture (`@aeoess` 2026-04-30 21:47 UTC):

- **24 hours** is the spec default for planned-mode overlap.
- A verifier **MAY** shorten the overlap below 24h via local configuration (private hardening; does not affect cross-implementation interop).
- A verifier **MUST NOT** lengthen the overlap beyond a hard ceiling of **7 days**. Indefinite overlap defeats the rotation-state-machine semantics scenarios 3a–3d depend on.

### 4.4 Maximum resolver cache TTL — `max_emergency_propagation_window` `[APS-confirmed via aeoess push 2026-04-30]`

Working baseline carried from APS posture (`@aeoess` 2026-04-30 21:47 UTC):

- Verifiers **MUST** honor the `revoked` status of a verification method present in the resolved DID document at evaluation time.
- The spec defines a constant **`max_emergency_propagation_window`** with a **proposed value of 1 hour**. Verifier resolver caches **MUST** be bounded such that the worst-case propagation delay between an emergency revocation publication and a verifier rejecting a signature under the revoked key does not exceed this window.
- This constant is the SLA that emergency rotation can promise across implementations. Anything longer would make scenario 3d untestable in practice.

## 5. Error shape — RESOLVED `[APS-confirmed via aeoess thread reply 2026-05-01]`

Three groups shown side-by-side: the canonical four-string `reason` enum APS standardizes (the cross-stack contract floor), the typed `IdentityCompositionError` subtypes proposed by APS for cross-stack debugging parity, and verifier-side / harness-side reasons that exist in the Agent-DID SDK reference verifier and `a2a-compliance-harness` for diagnostic surface area beyond the APS floor.

### 5.1 Cross-stack contract (the canonical floor)

The four reason codes APS canonicalizes are the **canonical floor**. Every conformant implementation that detects the corresponding condition **MUST** surface at least these four:

- `rotation_window_closed` (see §4.3)
- `emergency_revoked` (see §4.4)
- `key_purpose_violation` (see §6.3)
- `tampered` (signature does not verify against any published key under any rotation scenario)

These map 1:1 to the typed APS subtypes:

- `rotation_window_closed` ↔ `OverlapWindowExceeded`
- `emergency_revoked` ↔ `EmergencyRevokedKey`
- `key_purpose_violation` ↔ `KeyPurposeViolation`
- `tampered` ↔ `Tampered`

Reference implementation: `IdentityCompositionError` in agent-passport-system v2.5.1-alpha (commit `f37f1cc` on `aeoess/agent-passport-system` `main`), `src/errors/identity-composition-error.ts`. Conformance: `tests/v2/identity-composition-error.test.ts` (9 tests).

### 5.2 Verifier-side extension (optional)

Verifiers **MAY** surface additional reason codes for verifier-side failure modes that occur **before the APS-defined verification logic engages**. These are orthogonal to the canonical floor and APS implementations need not surface them. The Agent-DID SDK reference verifier currently surfaces:

- `card_keyid_mismatch` — the per-request keyId is not present in the Agent Card body. Aliased as `key_mismatch` for harness-output parity.
- `card_unresolvable` — the Agent Card cannot be fetched or parsed.
- `did_document_unresolvable` — the DID document cannot be resolved by any configured resolver.
- `format_drift` — Card body fails JCS canonicalization or violates §3.1 wire shape.
- `did_resolver_unsupported` — scenario 3e (§4.1); NOT a hard rejection, surfaced as a marker.

### 5.3 Alias mapping rule

Where a verifier-side code overlaps semantically with an APS canonical code, **the APS code is the canonical name and the verifier code is the alias**. Implementations emitting the verifier-side alias **SHOULD** also be readable as emitting the APS canonical code by consumers of the cross-stack contract.

Current overlaps:

- `card_keyid_mismatch` and `key_mismatch` are verifier-side aliases. They map to APS subtype `SignatureKeyNotInCard` (a verifier-side check, not an APS-canonical reason — verifiers MAY surface this; APS implementations need not).

### 5.4 Wire shape

```text
IdentityCompositionError {
  reason: // canonical floor (APS-confirmed)
          "rotation_window_closed"     // -> OverlapWindowExceeded
        | "emergency_revoked"          // -> EmergencyRevokedKey
        | "key_purpose_violation"      // -> KeyPurposeViolation          (see §6.3)
        | "tampered"                   // -> Tampered
          // verifier-side extension (optional, see §5.2 / §5.3)
        | "card_keyid_mismatch"        // alias: key_mismatch; APS: SignatureKeyNotInCard
        | "key_mismatch"               // alias of card_keyid_mismatch
        | "card_unresolvable"
        | "did_document_unresolvable"
        | "format_drift"
        | "did_resolver_unsupported"   // marker, not a hard rejection (§4.1 scenario 3e)
  request_keyid: string
  card_published_keyids: string[]
  did_document_verification_keyids: string[]
  found_in?: string[]                  // when reason is "key_purpose_violation"; see §6.3
}
```

Standardizing the canonical floor across SDK implementations enables cross-stack debugging when a verifier and signer disagree, and matches what APS gateways emit on the receipt-rejection path. The verifier-side extension is documented for diagnostic transparency without expanding the cross-stack contract.

## 6. Resolutions for the original open questions

The original four open questions are now resolved (working baseline) per `@aeoess`'s 2026-04-30 21:47 UTC reply on [a2aproject/A2A#1742](https://github.com/a2aproject/A2A/issues/1742). Final wording follows once aeoess pushes directly to this branch.

### 6.1 Default overlap window — RESOLVED

24h spec default, verifier MAY shorten, MUST NOT extend beyond 7d ceiling. See **§4.3**.

### 6.2 Resolver cache TTL — RESOLVED

Spec defines `max_emergency_propagation_window` (proposed 1h). Verifiers MUST honor `revoked` status at evaluation time. See **§4.4**.

### 6.3 Verification-relationship binding — RESOLVED `[APS-confirmed via aeoess push 2026-04-30]`

The per-request signing key MUST resolve to a verification method whose
verification relationship in the resolved DID document corresponds to the
operation context:

- Agent-to-agent message signing → `assertionMethod`
- Delegation issuance → `capabilityDelegation`
- Capability invocation → `capabilityInvocation`
- Authentication challenge response → `authentication`

Implementations MUST reject any signature where the keyId resolves to a
verification relationship that does not match the operation context.
On rejection, implementations SHOULD raise an `IdentityCompositionError`
with `reason: "key_purpose_violation"` (see §5).

Note: `keyAgreement` is intentionally excluded from the signing-purpose
set. Per W3C DID Core, `keyAgreement` is a verification relationship for
key-agreement primitives (X25519 ECDH for encryption / key derivation),
not for signing. Implementations MUST NOT accept a Linked Data Proof
that declares `proofPurpose: "keyAgreement"`.

#### Reference implementation

agent-passport-system v2.5.1-alpha (commit `f37f1cc` on aeoess/
agent-passport-system `main`) provides:

- `IdentityCompositionError` class (`src/errors/identity-composition-error.ts`)
  with the four-string reason enum aligned to §5:
  `rotation_window_closed`, `emergency_revoked`, `key_purpose_violation`,
  `tampered`.
- `assertKeyPurpose(keyId, didDoc, requiredPurpose)` helper that throws
  `IdentityCompositionError` with `reason: "key_purpose_violation"` when
  the keyId is not authorized for the required verification relationship.
  The error context surfaces `foundIn`, enumerating which other
  relationships the keyId WAS in (diagnostic, not authorization).
- `DIDDocument` typed with all five W3C DID Core verification
  relationships: `authentication`, `assertionMethod`,
  `capabilityDelegation`, `keyAgreement`, `capabilityInvocation`.
- Nine conformance tests at `tests/v2/identity-composition-error.test.ts`
  covering reason-enum exhaustiveness, error-class shape, all five
  positive purposes, key-not-in-purpose negative case, `foundIn`
  enumeration, unknown-key path, and minimal-doc-with-optional-fields-
  absent.

### 6.4 Cross-DID-method identity mapping — RESOLVED (out of scope) `[APS-confirmed via aeoess push 2026-04-30]`

Working baseline carried from APS posture (`@aeoess` 2026-04-30 21:47 UTC):

- The composition contract is well-defined **within a single DID method**. The canonical Agent-DID profile is `did:webvh` cross-checking `did:webvh` for the agent and its controller recursion; other supported methods cross-check within their own method.
- Cross-method bridging is **explicitly out of scope** for this draft and is recorded as **Future Work**.
- Rationale: cross-method bridging touches DID method registry semantics still in flux at the broader DIF community level. Landing it here would force premature closure on that question and tie the composition contract's lifecycle to a DID-method-registry timeline that is not under this spec's control.

## 7. Test vectors `[APS-aligned pre-pass, open to revision in counter-draft]`

This spec commits to publishing a `fixtures/composition-contract/` directory with deterministic JCS-canonicalized fixtures, mirroring the shape used by [`aps-conformance-suite`](https://github.com/aeoess/aps-conformance-suite) so that suite can ingest these fixtures as a sub-corpus.

**Minimum corpus** (8 fixtures, locked at v0.1):

| ID | Scenario | Expected verifier outcome |
|----|----------|---------------------------|
| F1 | Happy path: current key, valid Card, valid per-request signature | accept |
| F2 | Happy path during planned overlap, signed under prior key still listed in DID document | accept (scenario 3b) |
| F3 | Negative: §2 cross-check fails (`keyid` not in Card) | reject `card_keyid_mismatch` / `key_mismatch` |
| F4 | Negative: prior key after planned overlap window closed | reject `rotation_window_closed` (scenario 3c) |
| F5 | Negative: emergency-revoked key | reject `emergency_revoked` (scenario 3d) |
| F6 | Negative: signing key purpose is not `assertionMethod` (e.g. `keyAgreement`) | reject `key_purpose_violation` (§6.3) |
| F7 | Marker: unknown DID method on `keyid` resolution path | mark `did_resolver_unsupported`, surface to policy (scenario 3e) |
| F8 | Negative: Agent Card body fails JCS canonicalization or §3.1 wire shape | reject `format_drift` |

Fixture properties:

- Deterministic Ed25519 seed (publicly published in the fixture README so any implementation can regenerate).
- JCS-canonicalized Card body bytes (RFC 8785).
- RFC 9421 signature base shown alongside the signature value for verifier debugging.
- Each fixture shipped as a self-describing JSON with `expected_outcome`, `expected_reason` (if reject), `expected_marker` (if marker).

## 8. Vocabulary `[APS-aligned pre-pass, open to revision in counter-draft]`

For primitive names, this spec defers to [`agent-governance-vocabulary`](https://github.com/aeoess/agent-governance-vocabulary) as the authoritative source where overlap exists. Primitives introduced by this composition contract that are not yet canonical in vocabulary v0.1 are mapped in [`crosswalk/agent-did.yaml`](https://github.com/aeoess/agent-governance-vocabulary/pull/66) under `out_of_vocabulary_primitives`:

- `agent_card` (identity material at rest)
- `per_request_signature` (identity material in motion)
- `identity_composition_contract` (the verifier-side rule normative in §2)
- `key_rotation_state_machine` (§4)
- `identity_composition_error` (§5)

When vocabulary v0.2 lands canonical names for any of these, this spec will adopt the canonical slug and retire local naming.

## 9. References

- A2A upstream thread: https://github.com/a2aproject/A2A/issues/1742
- APS posture source comment (2026-04-30 21:47 UTC): https://github.com/a2aproject/A2A/issues/1742#issuecomment-4355813752
- APS test vectors directory: https://github.com/ScopeBlind/agent-governance-testvectors
- APS conformance suite: https://github.com/aeoess/aps-conformance-suite
- A2A compliance harness: https://github.com/aeoess/a2a-compliance-harness
- Agent governance vocabulary: https://github.com/aeoess/agent-governance-vocabulary
- Vocabulary crosswalk for Agent-DID (PR pending merge): https://github.com/aeoess/agent-governance-vocabulary/pull/66
- OWASP AIVSS §3.6 Agent Authentication & Identity: referenced in §0 threat model
- RFC 9421 HTTP Message Signatures: https://www.rfc-editor.org/rfc/rfc9421
- RFC 8785 JSON Canonicalization Scheme: https://www.rfc-editor.org/rfc/rfc8785
- Sister cross-over case (Microsoft Agent Framework / `add_verified_handoff`): https://github.com/microsoft/agent-framework/issues/4842
- Internal tracking: https://github.com/edisonduran/agent-did/issues/30
