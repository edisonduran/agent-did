# ADR-002: did:webvh v1.0 Implementation Strategy

- **Status:** Accepted (2026-11-02)
- **Date:** 2026-11-02
- **Work item:** M-02 (`1.0.0-rc.3` train)
- **Deciders:** Agent-DID maintainers
- **Related:** [ADR-001 (pivot to the did:webvh pattern)](../_bmad-output/planning-artifacts/ADR-001-Pivot-to-didwebvh-Pattern.md), [RFC-001](RFC-001-Agent-DID-Specification.md), [RELEASE-1.0-CRITERIA](RELEASE-1.0-CRITERIA.md)

## Context

RFC-001 names `did:webvh` as the canonical DID method for Agent-DID. The `did.jsonl` history the SDKs currently emit and read is an Agent-DID-specific format that predates the DIF [`did:webvh` v1.0 specification](https://identity.foundation/didwebvh/v1.0/). In particular it has none of these:

- a self-certifying SCID;
- a `versionId` / `entryHash` chain;
- `parameters` with `updateKeys`;
- `eddsa-jcs-2022` Data Integrity proofs.

As a result, `did:webvh` resolvers built to the specification cannot resolve our identifiers, and we cannot resolve theirs. Until that changes, Agent-DID cannot honestly claim to be "a pattern on top of `did:webvh`".

v1.0 requires, at minimum:

- **SCID:** `base58btc(multihash(SHA-256(JCS(genesis entry with "{SCID}" placeholders))))`.
- **Entry hashes:** each `versionId` is `<n>-<entryHash>`, chained to the previous entry.
- **Parameters:** `method` (`did:webvh:1.0`), `scid`, `updateKeys`, `nextKeyHashes` (pre-rotation), `portable`, `witness`, `watchers`, `deactivated` and `ttl`.
- **Proofs:** an `eddsa-jcs-2022` proof on every entry, from a key in the active `updateKeys`.
- **Resolution:** follows the spec's validation rules (`versionTime` ordering and skew, SCID binding, pre-rotation, witness thresholds) and its URL derivation rules (IDNA, no IP hosts, no path traversal).

The DIF also maintains [`didwebvh-test-suite`](https://github.com/decentralized-identity/didwebvh-test-suite): 13 positive and 18 negative scenarios, with logs produced by seven implementations and cross-resolved by each of them. Release criterion **C-EXT-1** requires our logs to resolve in a third-party resolver, and vice versa.

The decision is whether to **adopt the DIF reference implementations** or **write our own** in both SDKs.

## Evaluation

### Candidates

| | TypeScript: [`didwebvh-ts`](https://github.com/decentralized-identity/didwebvh-ts) 3.0.0 | Python: [`did-webvh`](https://github.com/decentralized-identity/didwebvh-py) 1.0.1 |
|---|---|---|
| Owner, license | DIF, Apache-2.0 (the README still says MIT; the repository `LICENSE` is Apache-2.0) | DIF, Apache-2.0 |
| Spec version | v1.0, including witnesses, pre-rotation, portability and a parallel `did:web` | v1.0, including witnesses and pre-rotation (the README still says 0.4; the package and code target v1.0) |
| Test suite (upstream `status.md`) | All 13 creation scenarios and all 18 negative scenarios pass | All 13 creation scenarios pass. Of the 18 negative scenarios, 13 pass and 5 are skipped because they test URL parsing, not logs |
| Cross-resolution against other implementations | Differences only in `didDocumentMetadata` formatting; no failures | Same |
| Signing | `Signer { sign(), getVerificationMethodId() }`; pluggable `Verifier` | Abstract `SigningKey` / `VerifyingKey` base classes |
| Dependencies | `@noble/curves` ^2, `@noble/hashes` ^2, `@scure/base`, `did-resolver`, `json-canonicalize` | `aries-askar` (native; imported at module load), `aiohttp`, `jcs`, `base58`, `multiformats` |
| Runtime | Node ≥ 22.12 (ESM with a CJS build; relies on `require(esm)`) | Python ≥ 3.10 |
| Maintenance | 28 npm releases; latest 3.0.0 on 2026-10-29; DIF trusted publishing | Last commit 2026-09-19; low-level API (`DocumentState`) |

### Prototype (throwaway, not committed)

A prototype exercised both libraries with Agent-DID documents: a custom `agentMetadata` member, `controller`, and a Multikey assertion key.

| Check | Result |
|---|---|
| TS: create, then update with our own Ed25519 signer (`@noble/curves`), then resolve the log | ✅ `agentMetadata` preserved; `versionId` `2-Qm…` |
| TS: resolve a log whose last entry was edited without re-signing | ✅ rejected (`invalidDid`) |
| TS: append an entry signed by a key that is not in `updateKeys` | ✅ rejected ("not authorized to update") |
| Python: create, then update with a `pynacl` signer (no Askar keystore), then resolve | ✅ |
| Python resolves the log produced by TS | ✅ |
| TS resolves the log produced by Python | ✅ same DID and document |

### Costs and risks found

1. **TS engine floor.** `didwebvh-ts` needs Node ≥ 22.12, because its CJS build loads ESM-only `@noble` v2. `@agentdid/sdk` currently declares Node ≥ 22.0, and the CHANGELOG already recommends ≥ 22.23.4, so raising the floor costs little. The SDK would ship both `@noble` v1, which it uses itself, and `@noble` v2, which `didwebvh-ts` uses, until we move to v2.
2. **Python native dependency.** `aries-askar` 0.5.0 publishes wheels only for `manylinux2014` (x86_64, aarch64), macOS universal2 and `win_amd64`. There is **no `musllinux` wheel**, so `pip install agent-did-sdk` would fail on Alpine-based images, as well as on Windows ARM64. It adds about 8 MB, and the signing paths we need do not use it.
3. **Python HTTP stack.** `did-webvh` brings `aiohttp`; the SDK standardizes on `httpx` with SSRF guards. We would fetch `did.jsonl` ourselves and hand the text to the library, so `aiohttp` would be installed but never used.
4. **Two JCS implementations per SDK.** TS would have ours plus `json-canonicalize`, and Python would have `rfc8785` plus `jcs`. This is acceptable only if CI pins agreement through the RFC 8785 vectors and the did:webvh test suite.
5. **Upstream velocity.** The DIF reports that vulnerabilities were found in implementations, not in the specification, after v1.0. Adopting the libraries means taking their fixes; owning an implementation means finding those issues ourselves.

## Options

### A. Adopt the reference implementations in both SDKs, behind an Agent-DID adapter

- **Pros:**
  - Conformance and the hardening against the 18 negative scenarios come from maintained, cross-tested code.
  - Interoperability is proven in both directions.
  - Witnesses, pre-rotation and portability are available when we need them.
  - The least new security-critical code is ours.
- **Cons:**
  - Python packaging: Askar (Alpine), `aiohttp`, and a lower-level API that needs more glue.
  - TS: the Node floor rises and `@noble` is duplicated.
  - We depend on upstream release cadence.

### B. Implement v1.0 ourselves in both SDKs

- **Pros:** no new dependencies; full control over API and errors; reuses our RFC 8785 and Ed25519 code.
- **Cons:**
  - The largest effort, estimated at 3 to 4 weeks for both SDKs to reach parity on 31 scenarios.
  - It re-implements exactly the class of validation logic that upstream implementations got wrong after v1.0.
  - We would carry the conformance burden forever.

### C. Hybrid: adopt `didwebvh-ts`; implement our own in Python, validated against the TS library and the test suite

- **Pros:** avoids Askar and `aiohttp` in the Python SDK.
- **Cons:** the Python verifier becomes our security-critical code, carrying the risks of option B for one SDK; it also creates permanent asymmetry between the SDKs.

## Decision

**Option A**, with these conditions:

1. **Adapter boundary.** Each SDK gets a `did:webvh` module that alone imports the reference library and exposes Agent-DID operations: create, update, deactivate, export or import `did.jsonl`, and resolve from log text. `AgentIdentity` and `UniversalResolverClient` never touch library types. This keeps option C open if upstream stalls.
2. **Our transport, their verification.** Logs are fetched with the SDKs' existing HTTP sources, which keep the SSRF guards and our document sources. The library only verifies text that we fetched.
3. **Key model.**
   - `updateKeys` hold the **controller's** key or keys. Every log entry, including revocation through `deactivated: true`, is therefore signed by the controller.
   - The agent's own key stays an `assertionMethod` verification method in the document.
   - Signing goes through the existing `AgentSigner` abstraction, so KMS and HSM signers work.
   - In the local bootstrap profile, the bootstrap controller key returned by `create()` (M-01) is the update key.
4. **Python packaging.** Pin `did-webvh` and open an upstream PR that makes `aries-askar` and `aiohttp` optional, through a lazy import and an extra. Until it lands, document the Alpine and Windows ARM64 limitation in the Python README. If upstream declines, re-evaluate option C for Python only.
5. **TS packaging.** Raise `engines.node` to `>=22.12.0` and plan the move to `@noble` v2.
6. **Conformance evidence (C-EXT-1).** A CI job pins a commit of `didwebvh-test-suite`. With it, each SDK:
   - resolves every implementation's positive vectors and compares `didDocument`;
   - rejects every negative vector with the expected error;
   - has its own create scenarios resolved by the TS and Python reference resolvers.

   README conformance claims are made only after this job is green.
7. **Scope for `1.0.0-rc.3`.** v1.0 create, update, deactivate and resolve, plus `updateKeys` rotation. Pre-rotation, witnesses, watchers and portability are deferred to after 1.0, but the adapter must not prevent them. *Update (rc.5): pre-rotation was exposed after all, because it is the only in-protocol recovery from controller key compromise: `nextUpdateKeys` at creation, `rotateControllerKey`, and `nextKeyHashes` in the resolution metadata, in both SDKs. Witnesses, watchers and portability remain deferred.*

## Implementation status

- Step 1, adapters over the reference libraries: done (#119).
- Step 2, CI against `didwebvh-test-suite`, pinned in `fixtures/didwebvh-test-suite.json`: done (#120).
- Step 3, `AgentIdentity` and the resolvers on the adapters, DID-to-URL derivation, migration guides: done in the `rc.3` train.
- Follow-ups: the upstream PR making `aries-askar` and `aiohttp` optional in `did-webvh`; the `@noble` v2 migration in TS; registering Agent-DID in `didwebvh-test-suite`; witnesses, watchers and pre-rotation after 1.0.

## Consequences

- **Breaking:** new `did:webvh` identifiers carry a spec-derived SCID, and existing Agent-DID `did.jsonl` histories cannot be upgraded in place. The `rc.2 → rc.3` migration guides must explain re-issuance. Integrations that only call `AgentIdentity` are unaffected at the API level.
- **Lifecycle authority:** document changes on the `did:webvh` path require a controller signature by construction, which is the basis for M-03.
- **Dependencies:** both SDKs gain new runtime dependencies, which the SBOM and dependency review must cover.
- **Follow-ups:**
  - the upstream PR for optional Askar and `aiohttp` in `did-webvh`;
  - the `@noble` v2 migration in TS;
  - registering Agent-DID as an implementation in `didwebvh-test-suite` once it is conformant.

## Resolved questions

1. ~~Is the Python packaging limitation in condition 4 acceptable for `rc.3`?~~ **Resolved (2026-11-02):** the Alpine and Windows ARM64 limitation is **not** blocking for `rc.3`; it is documented and tracked through the upstream PR.
2. ~~Should `didDocumentMetadata` expose the full did:webvh parameters (`updateKeys`, `ttl`, `witness`) in Agent-DID resolution results, or only what RFC-001 needs?~~ **Resolved (2026-11-02):** the adapters expose `versionId`, `versionNumber`, `versionTime`, `created`, `updated`, `scid`, `updateKeys`, `deactivated` and `ttl` (the did:webvh default, `3600`, when the log does not set one). Witness and watcher configuration stay internal until the SDKs support them (condition 7).
