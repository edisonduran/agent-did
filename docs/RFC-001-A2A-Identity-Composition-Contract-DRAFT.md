# DRAFT — A2A Identity Composition Contract

> **Status**: DRAFT for co-drafting with `@aeoess` (APS).
> **Tracking issue**: [#30](https://github.com/edisonduran/agent-did/issues/30)
> **Upstream thread**: [a2aproject/A2A#1742](https://github.com/a2aproject/A2A/issues/1742)
> **Workflow**: open this branch, both sides edit / review / counter-draft until the rotation-window edge cases and verifier-side semantics are tight enough to land in `RFC-001` and propose normative text upstream in A2A.

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
4. Verifier asserts: `keyid` ∈ DID-document-verification-material ∩ Agent-Card-published-keys (subject to rotation rules in §4).

Mismatch at step 4 → `IdentityCompositionError(reason=...)`.

## 4. Key rotation state machine

Rotation modes:

- **Planned mode** — configurable overlap window (default: 24 hours). Both prior and current keys are listed in the resolved DID document for the duration of the overlap.
- **Emergency mode** — immediate retirement of the prior key. Prior key transitions to `revoked` state in the DID document with no overlap.

### 4.1 Conformance scenarios (4 required)

| # | Scenario | Expected verifier behavior |
|---|----------|----------------------------|
| 3a | Signature under **current key** during planned overlap window | Accept. |
| 3b | Signature under **prior key** during planned overlap window, prior key still listed in resolved DID document | Accept. |
| 3c | Signature under **prior key** after planned overlap window has closed | Reject with `IdentityCompositionError(reason="rotation_window_closed")`. |
| 3d | Signature under **emergency-revoked prior key** at any time | Reject with `IdentityCompositionError(reason="emergency_revoked")`, regardless of in-flight signature timestamps or resolver cache state. |

### 4.2 Resolver cache hazard

A `did:` resolver honoring a 24h-cached DID document during a 1-hour emergency rotation is a silent failure. Conformance MUST be tested against the verifier's externally observable behavior (the 4 scenarios above), not against the resolver's caching strategy. Implementations that defer to a cached resolver are responsible for cache-invalidation semantics that satisfy scenario 3d.

## 5. Error shape

```text
IdentityCompositionError {
  reason: "card_keyid_mismatch"
        | "rotation_window_closed"
        | "emergency_revoked"
        | "card_unresolvable"
        | "did_document_unresolvable"
  request_keyid: string
  card_published_keyids: string[]
  did_document_verification_keyids: string[]
}
```

Standardizing the error shape across SDK implementations enables cross-stack debugging when a verifier and signer disagree.

## 6. Open questions for co-drafting

1. **Default overlap window** — does A2A pin 24h as a default in the spec, or leave it as a verifier-policy knob with no default?
2. **Resolver cache TTL constraint** — does the spec constrain max resolver cache TTL (e.g. ≤ 1h) to bound the silent-failure window during emergency rotation, or is that left entirely to verifier policy + scenario 3d testing?
3. **Multi-key Cards** — when an Agent Card legitimately publishes multiple active keys (e.g. one for signing, one for encryption), is the cross-check scoped to keys with `usage=sig` only?
4. **Cross-DID-method identity** — if an agent operates under multiple DID methods simultaneously, does the composition contract require Card and per-request signature to use keys from the same DID, or only that both resolve to the same agent identity through some declared mapping?

## 7. References

- A2A upstream thread: https://github.com/a2aproject/A2A/issues/1742
- APS test vectors directory: https://github.com/ScopeBlind/agent-governance-testvectors
- Sister cross-over case (Microsoft Agent Framework / `add_verified_handoff`): https://github.com/microsoft/agent-framework/issues/4842
- Internal tracking: https://github.com/edisonduran/agent-did/issues/30
