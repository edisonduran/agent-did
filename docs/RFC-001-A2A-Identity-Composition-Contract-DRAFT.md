# DRAFT — A2A Identity Composition Contract

> **Status**: DRAFT for co-drafting with `@aeoess` (APS).
> **Tracking issue**: [#30](https://github.com/edisonduran/agent-did/issues/30)
> **Upstream thread**: [a2aproject/A2A#1742](https://github.com/a2aproject/A2A/issues/1742)
> **Workflow**: open this branch, both sides edit / review / counter-draft until the rotation-window edge cases and verifier-side semantics are tight enough to land in `RFC-001` and propose normative text upstream in A2A.
> **Co-author push access**: `@aeoess` invited as repo collaborator (Write) 2026-04-30, scoped operationally to `spec/a2a-composition-contract` (`develop` and `main` are protected, require PR + 1 review).
> **Sync state with APS**: §4.3, §4.4, §5, §6.3, §6.4 below carry **APS posture as proposed by `@aeoess` in [a2aproject/A2A#1742 comment 2026-04-30 21:47 UTC](https://github.com/a2aproject/A2A/issues/1742)** as the working baseline. All such sections are marked `[APS-proposed, awaiting aeoess push to confirm wording]`. When aeoess pushes commits directly against this branch, those commits are authoritative over the working baseline.

## 1. Scope

Defines the composition contract between two distinct identity surfaces in an A2A-conformant agent system:

- **Identity-at-rest** — Agent Card, signed at publish time, durable for the lifetime of a key.
- **Identity-in-motion** — per-request signature (RFC 9421 HTTP signatures profile), signed at request time over a freshly canonicalized payload, ephemeral as a single message.

The composition contract is the normative requirement that ties them together so that neither surface becomes self-attesting in isolation.

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

### 4.2 Resolver cache hazard

A `did:` resolver honoring a 24h-cached DID document during a 1-hour emergency rotation is a silent failure. Conformance MUST be tested against the verifier's externally observable behavior (the 4 scenarios above), not against the resolver's caching strategy. Implementations that defer to a cached resolver are responsible for cache-invalidation semantics that satisfy scenario 3d.

### 4.3 Default overlap window — spec vs verifier-policy knob `[APS-proposed, awaiting aeoess push to confirm wording]`

Working baseline carried from APS posture (`@aeoess` 2026-04-30 21:47 UTC):

- **24 hours** is the spec default for planned-mode overlap.
- A verifier **MAY** shorten the overlap below 24h via local configuration (private hardening; does not affect cross-implementation interop).
- A verifier **MUST NOT** lengthen the overlap beyond a hard ceiling of **7 days**. Indefinite overlap defeats the rotation-state-machine semantics scenarios 3a–3d depend on.

### 4.4 Maximum resolver cache TTL — `max_emergency_propagation_window` `[APS-proposed, awaiting aeoess push to confirm wording]`

Working baseline carried from APS posture (`@aeoess` 2026-04-30 21:47 UTC):

- Verifiers **MUST** honor the `revoked` status of a verification method present in the resolved DID document at evaluation time.
- The spec defines a constant **`max_emergency_propagation_window`** with a **proposed value of 1 hour**. Verifier resolver caches **MUST** be bounded such that the worst-case propagation delay between an emergency revocation publication and a verifier rejecting a signature under the revoked key does not exceed this window.
- This constant is the SLA that emergency rotation can promise across implementations. Anything longer would make scenario 3d untestable in practice.

## 5. Error shape `[partially APS-proposed]`

Two shapes shown side-by-side: the descriptive `reason` enum currently emitted by the Agent-DID SDK reference verifier, and the typed `IdentityCompositionError` subtypes proposed by APS for cross-stack debugging parity.

```text
IdentityCompositionError {
  reason: "card_keyid_mismatch"        // -> SignatureKeyNotInCard
        | "rotation_window_closed"     // -> OverlapWindowExceeded
        | "emergency_revoked"          // -> EmergencyRevokedKey
        | "key_purpose_violation"      // -> KeyPurposeViolation   (see §6.3)
        | "card_unresolvable"
        | "did_document_unresolvable"
  request_keyid: string
  card_published_keyids: string[]
  did_document_verification_keyids: string[]
}
```

Typed subtypes proposed by APS (`@aeoess` 2026-04-30 21:47 UTC), to be aligned with the enum above when the APS wording lands on this branch:

- `SignatureKeyNotInCard` — equivalent to `card_keyid_mismatch`.
- `OverlapWindowExceeded` — equivalent to `rotation_window_closed`.
- `EmergencyRevokedKey` — equivalent to `emergency_revoked`.
- `KeyPurposeViolation` — emitted when the per-request signature key resolves to a verification method whose purpose is not `assertionMethod` (see §6.3).

Standardizing this shape across SDK implementations enables cross-stack debugging when a verifier and signer disagree, and matches what APS gateways emit on the receipt-rejection path.

## 6. Resolutions for the original open questions

The original four open questions are now resolved (working baseline) per `@aeoess`'s 2026-04-30 21:47 UTC reply on [a2aproject/A2A#1742](https://github.com/a2aproject/A2A/issues/1742). Final wording follows once aeoess pushes directly to this branch.

### 6.1 Default overlap window — RESOLVED

24h spec default, verifier MAY shorten, MUST NOT extend beyond 7d ceiling. See **§4.3**.

### 6.2 Resolver cache TTL — RESOLVED

Spec defines `max_emergency_propagation_window` (proposed 1h). Verifiers MUST honor `revoked` status at evaluation time. See **§4.4**.

### 6.3 Multi-key Cards (`usage=sig` scoping) — RESOLVED `[APS-proposed, awaiting aeoess push to confirm wording]`

Working baseline carried from APS posture (`@aeoess` 2026-04-30 21:47 UTC):

- The per-request signature key **MUST** resolve to a verification method whose verification relationship in the resolved DID document is **`assertionMethod`**.
- Other verification relationships (`keyAgreement`, `capabilityInvocation`, `capabilityDelegation`, etc.) **MUST NOT** satisfy the §2 cross-check, **even if the underlying key material matches**.
- Rationale: closes a subtle privilege-escalation path where a key authorized only for encryption would otherwise be accepted as a signing key by a verifier checking only key material identity.
- Verifier emits `IdentityCompositionError(reason="key_purpose_violation" / "KeyPurposeViolation")` when the cross-check fails on this dimension.

### 6.4 Cross-DID-method identity mapping — RESOLVED (out of scope) `[APS-proposed, awaiting aeoess push to confirm wording]`

Working baseline carried from APS posture (`@aeoess` 2026-04-30 21:47 UTC):

- The composition contract is well-defined **within a single DID method**. `did:web` cross-checks `did:web`; `did:agent-did` cross-checks `did:agent-did`.
- Cross-method bridging is **explicitly out of scope** for this draft and is recorded as **Future Work**.
- Rationale: cross-method bridging touches DID method registry semantics still in flux at the broader DIF community level. Landing it here would force premature closure on that question and tie the composition contract's lifecycle to a DID-method-registry timeline that is not under this spec's control.

## 7. References

- A2A upstream thread: https://github.com/a2aproject/A2A/issues/1742
- APS posture source comment (2026-04-30 21:47 UTC): https://github.com/a2aproject/A2A/issues/1742#issuecomment-4355813752
- APS test vectors directory: https://github.com/ScopeBlind/agent-governance-testvectors
- APS conformance suite: https://github.com/aeoess/aps-conformance-suite
- A2A compliance harness: https://github.com/aeoess/a2a-compliance-harness
- Sister cross-over case (Microsoft Agent Framework / `add_verified_handoff`): https://github.com/microsoft/agent-framework/issues/4842
- Internal tracking: https://github.com/edisonduran/agent-did/issues/30
