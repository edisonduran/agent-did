# Threat Model (STRIDE)

Status: **Draft**, covers `1.0.0-rc.3` plus the unreleased `rc.4` train. Work item M-15.

This document analyses the end-to-end Agent-DID flow with STRIDE. It complements, and does not replace:

- [SECURITY.md](../SECURITY.md): how to report vulnerabilities, supported versions, in-scope and out-of-scope threats (T1–T10, O1–O7) and trust assumptions.
- [RFC-001-A2A-Identity-Composition-Contract.md](RFC-001-A2A-Identity-Composition-Contract.md) §0 and §4: the AIVSS-aligned model for A2A composition and the rotation state machine.
- [Anti-Replay-HTTP-Signatures.md](Anti-Replay-HTTP-Signatures.md): the HTTP signature profile and replay controls.
- [External-Conformance-Matrix.md](External-Conformance-Matrix.md): which external specifications are proven in CI.

A mitigation is listed only if the code ships it. "Residual" means the risk remains after the mitigation and is owned by the operator, the relying party or a later work item. Nothing here is a claim of external conformance beyond what the matrix proves.

## 1. System model

### Actors

| Actor | Role |
|---|---|
| **Controller** | Human or organization that holds the Ed25519 `updateKey` of an agent's `did:webvh` log. Authorizes every lifecycle change. |
| **Agent** | Holds an `assertionMethod` key and signs HTTP requests and payloads. |
| **Log host** | Serves `did.jsonl` over HTTPS. Untrusted for integrity, trusted for availability. |
| **Resolver / cache** | `UniversalResolverClient`, custom document sources, operator caches. Untrusted transport. |
| **Verifier (relying party)** | Resolves the DID, verifies signatures, owns replay state and authorization. |
| **Registry** | Derived index (`documentRef`, status). For `did:webvh` it is not a source of truth. |
| **Attacker** | Network attacker, malicious or compromised log host, malicious peer agent, malicious caller of a verifier. May read all public data. |

### Assets

1. Controller private key (`updateKeys`): full control of the identity.
2. Agent signing key: ability to act as the agent.
3. Integrity and freshness of the DID log as seen by verifiers.
4. Prompt and model commitment salts (confidentiality of `systemPrompt` / `coreModel`).
5. Verifier replay state (`NonceStore`).

### Trust boundaries

```
 Controller host ──(1 create)──> Log host ──(3 fetch)──> Resolver/cache ──> Verifier
        │                            ▲                                          ▲
        └──(2 publish, 6 revoke)─────┘                                          │
 Agent host ──────────(4 signed HTTP request / 5 A2A handoff)───────────────────┘
```

The controller key and the agent key never cross a boundary. Everything that does cross one (log, documents, signatures, headers) is public and attacker-readable.

## 2. Flow 1: Creation

`AgentIdentity.create()` / `create_agent` builds the genesis entry of a `did.jsonl` log, signed by an explicit Ed25519 controller, and computes salted metadata commitments.

| STRIDE | Threat | Mitigation | Residual |
|---|---|---|---|
| **S**poofing | Attacker obtains control of a new identity by deriving the controller key. | The controller is an explicit `AgentSigner`, or, in the implicit `agents.local` profile, a bootstrap controller with a CSPRNG-generated key whose private key is returned once to the caller. No key material is derived from DID strings or other public data (M-01, GHSA-g97p-4qrw-9hvf). | The `agents.local` profile is for local use: a verifier should not treat its DIDs as trustworthy identities unless it resolves and authorizes the domain. The returned bootstrap key is the caller's to store. |
| **T**ampering | Genesis entry altered after creation. | Self-certifying SCID derived from the genesis entry; `entryHash` chain; `eddsa-jcs-2022` proof by the controller key. Verified by the DIF test-suite job. | None beyond key compromise. |
| **R**epudiation | Controller denies having created the agent. | Genesis proof binds the controller key. | The signed `versionTime` is signer-asserted. No trusted timestamp. |
| **I**nformation disclosure | `systemPrompt` / `coreModel` guessed from their published hashes. | Commitments are `hash://hmac-sha256/<hex>` with a random 32-byte salt returned once to the caller (M-07). Constant-time verification. | **Salt custody is the controller's.** Losing the salt blocks `updateDidDocument` for that field; leaking it re-enables guessing. Legacy `hash://sha256/` commitments are still verifiable. |
| **D**enial of service | Entropy or key-generation failure produces weak keys. | `@noble/*`, `secrets` / `os.urandom`. | Platform RNG is trusted. |
| **E**levation | Agent key reused as controller. | Controller and agent keys are separate; `updateKeys` is the controller key only. | Operators can still choose to reuse a key; not prevented. |

## 3. Flow 2: Log publication

The controller (or its operator) uploads `did.jsonl` to the location the DID maps to. Updates, rotations and deactivation append entries.

| STRIDE | Threat | Mitigation | Residual |
|---|---|---|---|
| **S** | Someone else publishes a log for a DID they do not control. | The DID embeds the SCID; a log that does not hash to it is rejected. Each entry must be signed by an `updateKey` of the previous entry. | None for integrity. |
| **T** | Log host or an intermediary edits, reorders or truncates entries. | Full-log verification: hash chain, proofs, monotonic `versionTime`. Edits and reordering fail. | **Truncation to an earlier valid prefix and withholding the newest entries are not detectable from the log alone** (rollback / freshness). See §4. |
| **R** | Controller denies a rotation or revocation. | Each entry is signed by an `updateKey`. | Same timestamp caveat as §2. |
| **I** | Log leaks information. | The log is public by design. It contains only the document and commitments. | Do not put secrets in `agentMetadata`; commitments are salted for this reason. |
| **D** | Host goes down or deletes the log. | Operator HA, resolver cache, [Resolver HA runbook](RFC-001-Resolver-HA-Runbook.md). | Availability is the host's. A verifier with an empty cache cannot verify. |
| **E** | Compromised host replaces the log with an attacker-created one. | Different log hashes to a different SCID, so it cannot masquerade under the same DID. The attacker can only withhold or serve an old prefix. | Witnesses are not supported: logs that declare witnesses are rejected. |

## 4. Flow 3: Resolution

`UniversalResolverClient`, `WebvhDIDDocumentSource` and the `AgentIdentity.resolve` path fetch the log (or a document by registry `documentRef`) and verify before use.

| STRIDE | Threat | Mitigation | Residual |
|---|---|---|---|
| **S** | Resolver or origin returns a different document for the same `id`. | `did:webvh`: whole-log verification. `documentRef`: the fetched document must hash (JCS, SHA-256) to the reference and carry the requested `id` (M-06). | References with other schemes (e.g. `ipfs://`) are unverified and rejected unless listed in `unverifiedDocumentRefSchemes`; each use emits a `source-fetched` event. |
| **T** | Integrity failure silently handled by another source. | `DocumentIntegrityError` never falls back. Only availability failures trigger fallback, and the fallback result is not re-cached as primary. | None known. |
| **T** | DID-to-URL confusion sends the resolver to the wrong host. | Derivation follows did:webvh v1.0; negative DID-URL vectors run in CI. | Hostile DNS or TLS is out of scope (O7). |
| **R** | Not applicable to resolution. | Resolver events (`source-fetched`, fallback) give observability. | No built-in audit log. |
| **I** | Resolver learns which verifiers check which agents. | None. | Inherent in any DID resolution; use a local cache or a private resolver. |
| **D** | Oversized or hostile log, slow origin, repeated misses. | Parsing is fuzzed for the documented error type only (M-14). SSRF guard on HTTP targets (every non-globally-routable IPv4 and IPv6 range, including IPv4-embedded IPv6 forms). The default HTTP client of both SDKs gives each request one deadline covering lookup, connection and the whole body (10 s by default), caps the body (1 MiB by default, declared or streamed) and accepts only unencoded bodies, so the cap bounds what is parsed. The resolver cache is bounded (1000 documents by default; expired entries first, then least recently used). | The `Signature-Agent` DID, and so the host fetched, is chosen by whoever sends the request: each verification of an unknown DID costs at most one bounded fetch per candidate URL, and a cache miss is not rate-limited by the SDK. Verifiers exposed to untrusted traffic should rate-limit and allow-list. Custom `fetchFn` / `http_client` and document sources own their limits. Log verification cost for a log within the size cap is not separately bounded (candidate for M-16). |
| **D** | Attacker redirects the resolver at internal services. | `validateHttpTarget` blocks private and reserved targets, and the default fetch does not follow redirects and checks resolved addresses. | Applies to the SDK's own default fetches. The default fetch also resolves host names and rejects any that point at a non-global address; the connection is made to the address that was validated (the name is resolved once), so DNS rebinding after the check does not redirect the request. Network-level egress controls remain a sensible second layer. Custom `fetchFn` and document sources must apply equivalent checks, including their own redirect policy. |
| **E** | Stale document used after revocation. | See §7. | Cache TTL is operator policy. |

**Rollback and freshness.** did:webvh authenticates history, not currency. A malicious host can serve an older valid prefix, for example the log from before a revocation. The SDK cannot detect this on its own. Mitigations are operational: bounded cache TTL (§7), fetching from several independent mirrors, and, for A2A, the `max_emergency_propagation_window`.

## 5. Flow 4: HTTP signing and verification

`signHttpRequest` / `verifyHttpRequestSignature` implement the Agent-DID profile of RFC 9421.

| STRIDE | Threat | Mitigation | Residual |
|---|---|---|---|
| **S** | Forged request in the name of an agent. | Ed25519 over the RFC 9421 base; `keyid` must be an active `assertionMethod` key of the DID in `Signature-Agent`, whose controller chain is active. | Authentication proves control of a DID, **not that the DID is trusted**. Anyone can make a DID. The verifier must allow-list or otherwise authorize it (O3). |
| **S** | Signature reused in another protocol. | `tag="agent-did"` is required. | None known. |
| **T** | Method, path, query, body or headers altered. | Covered components: `@method @authority @path @query content-digest date signature-agent`. `Content-Digest` (RFC 9530) must match the body. `@signature-params` is re-serialized from the parsed input. | Headers outside the covered set are not protected. |
| **T** | Parser confusion or crafted `Signature-Input`. | RFC 8941 library in both SDKs, duplicate parameters rejected, property tests and nightly fuzzing (M-14), cross-verification with independent RFC 9421 libraries. | Fuzzing shows absence of crashes, not absence of logic flaws. |
| **R** | Agent denies a request. | Signature is non-repudiable with respect to the key. | `created` is signer-asserted. After a key compromise, a forged `created` cannot be told apart from a genuine earlier one without an external timestamp. |
| **I** | Signature exposes request contents. | Signing is not encryption (O4). | Use TLS. |
| **D** | Flooding the nonce store. | The nonce is recorded only after the signature verifies, so unauthenticated traffic cannot consume entries. `InMemoryNonceStore` refuses new nonces when full instead of evicting live ones. | **A holder of a valid key can fill the store** and cause legitimate requests to be rejected. Rate-limit per `keyid`; short `expires` keeps the store small. |
| **D** | Replay of a captured request. | `created` skew (default 300 s, `maxCreatedSkewSeconds`), `expires`, and `(keyid, nonce)` in a `NonceStore`. | **The default store is per process.** Several verifier instances need a shared atomic store (Redis example documented). Without it a replay can succeed once per instance within the window. |
| **E** | `keyAgreement` or non-signing keys used to sign. | Purpose binding: `assertionMethod` by default; mismatches return `key_purpose_violation`. | None known. |
| **E** | Verifier trusts the request because the signature is valid. | Documented boundary: a valid signature proves who called, not that the call is authorized or the reasoning correct (RFC-001 §8). | Relying-party responsibility. |

## 6. Flow 5: A2A handoff

An agent presents an Agent Card whose key material is a member of its DID document, and signs each request with the Flow 4 profile (see the composition contract).

| STRIDE | Threat | Mitigation | Residual |
|---|---|---|---|
| **S** | Card advertises keys the DID does not hold (AIVSS 3.6.5). | Per-request `keyid` must be in the resolved document, modulated by the rotation state machine. | Verifier must resolve, not trust the card. |
| **T** | Card or handoff payload altered. | Payload signing with canonical JSON (JCS); composition helpers fail deterministically with stable reasons in both SDKs. | None known. |
| **R** | Peer denies a handoff. | Signed request and card. | As in §5. |
| **I** | Card exposes more metadata than intended. | Only commitments, not plaintext prompts, are published. | Card contents are the operator's choice. |
| **D** | Peer withholds or delays a handoff. | Out of scope for identity. | Application-level timeouts. |
| **E** | Key valid for the agent but not for the purpose (AIVSS 3.6.2). | `assertionMethod` purpose scoping. | Capability enforcement stays with the relying party (O3). |
| **E** | Privilege escalation across delegation chains (AIVSS 3.6.3). | Not covered by the composition contract. | Open; belongs to the RFC-001 delegation model. |

## 7. Flow 6: Rotation and revocation

`rotateVerificationMethod`, `updateDidDocument` and `revokeDid` append controller-signed entries. Revocation is `deactivated: true` in the log.

| STRIDE | Threat | Mitigation | Residual |
|---|---|---|---|
| **S** | Third party revokes or rotates an identity. | Every lifecycle change needs a valid signature from a current `updateKey`. Without it, no state change. `registry.revoke` alone does not revoke a `did:webvh` DID. | None beyond controller key compromise. |
| **T** | Revocation reverted or hidden. | A deactivated log is refused on resolution; entries are chained. | Rollback to a pre-revocation prefix (§4). |
| **R** | Controller denies revoking, or a revoked agent denies acting before. | Signed entries. | Timestamps are signer-asserted. |
| **I** | Rotation reveals key history. | History is public by design. | Inherent. |
| **D** | Attacker triggers false revocation by corrupting the stored log. | A stored log that fails verification makes `resolve` fail instead of reporting the DID as active, and instead of reporting it revoked. | Availability suffers; no silent downgrade. |
| **E** | **Controller key compromised.** | Revocation requires the controller key, so the attacker can lock the owner out or rotate to their own keys. | **Recoverable only if pre-rotation was in force before the compromise** (RFC-001 §6.6 item 8; `webvh.nextUpdateKeys` at creation, `rotateControllerKey` afterwards): the compromised key can no longer sign and the holder of a committed key takes the DID back. **Unrecoverable otherwise**, and an attacker holding the active key of a DID without commitments can start pre-rotation with their own keys. Keep committed keys offline and protect the active key with an HSM or KMS (O1). |
| **E** | Agent key compromised. | Controller rotates or revokes; verifiers reject the revoked key once they see the new log. | **Propagation delay.** The contract bounds it by `max_emergency_propagation_window` (proposed 1 h) and a 24 h default overlap (hard ceiling 7 d) for planned rotation. Cache TTL beyond that window is a verifier misconfiguration. |
| **E** | Signatures made by a key before it was revoked, or forged with it afterwards and backdated. | `verifySignatureAtTime` checks the key against the verified log at the stated time (RFC-001 §6.2.2). A key retired after the stated time is **indeterminate**, never accepted, unless the verifier supplies trusted time evidence earlier than the retirement (`trustedTimeNotAfter`). | Persistence of history is the operator's. Without trusted time evidence, signatures by a retired key cannot be accepted, including genuine ones. The deprecated `verifyHistoricalSignature` accepts any retained retired key with no time check; it is scheduled for removal before `v1.0.0`. |

## 8. Cross-cutting findings

These are the residual risks that matter most, in priority order.

1. **Controller key compromise is recoverable only for DIDs that committed to pre-rotation keys in advance** (§7). The SDKs expose pre-rotation (`nextUpdateKeys`, `rotateControllerKey` / `rotate_controller_key`), but it is opt-in: DIDs created without it have no in-protocol recovery and rely on an operator control (HSM/KMS). Committed keys held on the same host as the active key add nothing.
2. **Rollback and withholding by a log host** (§4). Operator mitigation only: bounded TTL, mirrors.
3. **Signer-asserted time** (§5, §7). No trusted timestamp, so post-compromise forgery of `created` cannot be excluded.
4. **Replay protection is per process by default** (§5). Shared `NonceStore` is mandatory for multi-instance verifiers.
5. **Valid signature is not trust** (§5). Verifiers must authorize DIDs; the SDK only authenticates.
6. **Resolver cost is bounded per fetch, not per verifier** (§4). Each fetch has a deadline and a size cap and the cache is bounded, but a sender can name unknown DIDs to force fetches; rate-limiting is the verifier's. Log verification cost within the size cap remains a candidate for M-16.
7. **Salt custody** (§2). Lost salt blocks metadata updates; leaked salt re-enables guessing.

## 9. Out of scope

Prompt injection, key custody on the host, authorization policy, payload confidentiality, controller trust, registry and package-registry compromise, and the deferred EVM profile: see SECURITY.md §3.2.

## 10. Maintenance

Update this document in the same PR whenever a change touches signature bases, the log format, resolution or fallback behavior, the `NonceStore` contract or lifecycle authorization. New findings follow SECURITY.md: do not describe unpatched vulnerabilities here.
