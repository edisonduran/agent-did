# Changelog

All notable changes to the **Agent-DID** ecosystem are documented here.

The format follows [Keep a Changelog 1.1.0](https://keepachangelog.com/en/1.1.0/) and, starting with version `1.0.0`, this project adheres to [Semantic Versioning 2.0.0](https://semver.org/spec/v2.0.0.html) per [docs/DEPRECATION-POLICY.md](docs/DEPRECATION-POLICY.md).

> **Scope:** this root CHANGELOG records the *release train* of the core ecosystem (RFC + SDKs + integrations co-versioned starting at 1.0.0). Per-package `CHANGELOG.md` files are still pending (`C-DOC-1` in [docs/RELEASE-1.0-CRITERIA.md](docs/RELEASE-1.0-CRITERIA.md)).

---

## [Unreleased]

### Planned (path to 1.0.0)

See [docs/RELEASE-1.0-CRITERIA.md](docs/RELEASE-1.0-CRITERIA.md). Remaining after `1.0.0-rc.4`:

- `agent-did-in-action` demo switched to the RC, plus a focused feedback window of at least one week.
- Stable `v1.0.0` remains gated by the 30-day green window on the core release-critical workflows.

---

## [1.0.0-rc.4] - 2026-11-04

Breaking release candidate, tag `v1.0.0-rc.4`. All nine co-versioned packages move to `1.0.0-rc.4` (npm, dist-tag `next`) / `1.0.0rc4` (PyPI); `@agentdid/evm` is published for the first time. There are no wire-format changes for the canonical `did:webvh` profile, so rc.3 and rc.4 identities, logs and signatures interoperate; the breaking changes are in the SDK API. Follow [sdk/MIGRATION-1.0-rc.3-to-rc.4.md](sdk/MIGRATION-1.0-rc.3-to-rc.4.md) or [sdk-python/MIGRATION-1.0-rc.3-to-rc.4.md](sdk-python/MIGRATION-1.0-rc.3-to-rc.4.md).
### Documentation

- **Historical documents moved to `docs/archive/`** (M-21). F1-/F2- design docs, plans and maturity-gap assessments, the strategic assessments, the outreach plan, the analysis reports and the 92 KB research report formerly at the repository root now live under `docs/archive/`, each with a historical banner. Documents still referenced by CI or governance (parity matrices, checklists) stay live. `docs/INDEX.md` lists the archive in its own section.
- **Conformance headline is external evidence** (M-20). The README, `sdk/README.md`, `CONTRIBUTING.md`, the compliance checklist and the release criteria no longer present "11/11 MUST" as the headline; they point to the External Conformance Matrix and state that the checklist is a self-assessment against RFC-001. A matrix badge replaces the claim in the README header.

### Changed (breaking)

- **The EVM registry adapter left the core SDKs** (M-09). `EvmAgentRegistry`, `EthersAgentRegistryContractClient` and the `Evm*` types now live in the new optional package `@agentdid/evm` (`evm/`); in Python they moved to `agent_did_sdk.evm` and the `web3` dependency became the `agent-did-sdk[evm]` extra. `@agentdid/sdk` no longer depends on `ethers`, and `agent-did-sdk` no longer depends on `web3` / `eth_utils`. Nothing in the core imports the EVM adapter.
- **The controller is an Ed25519 `AgentSigner`, not an EVM wallet.** `AgentIdentityConfig.signer: ethers.Signer` is now `controllerSigner: AgentSigner` (Python: `signer_address: str` is now `controller_signer: AgentSigner`), and `AgentDidClient.createAgent` / `create_agent` takes the signer instead of an address. The controller is identified by a `did:key` derived from its public key (new `didKeyFromPublicKey` / `did_key_from_public_key`). The legacy `did:agent` profile now sets `controller` to that `did:key` instead of `did:ethr:<address>`, derives its identifier from SHA-256 (hex, no `0x` prefix) instead of Keccak-256, and no longer attaches a random `blockchainAccountId` to the verification method.
- `@agentdid/sdk` uses `@noble/hashes` instead of `ethers` for the random nonce and the AWS SigV4 HMAC/SHA-256; `agent-did-sdk` uses `hashlib` / `os.urandom` instead of `eth_utils`.
- The LangChain (JS), LangChain (Python), CrewAI, Semantic Kernel, Microsoft Agent Framework and A2A examples and tests create identities with a `LocalKeySigner` controller. Migration: [sdk/MIGRATION-1.0-rc.3-to-rc.4.md](sdk/MIGRATION-1.0-rc.3-to-rc.4.md), [sdk-python/MIGRATION-1.0-rc.3-to-rc.4.md](sdk-python/MIGRATION-1.0-rc.3-to-rc.4.md).

### Added

- The `https://agent-did.org/v1` JSON-LD context is now defined in [`contexts/v1.jsonld`](contexts/v1.jsonld), pinned by SHA-256 and immutable once published (M-19, [ADR-003](docs/ADR-003-JSON-LD-Context-and-agentMetadata.md)). It defines the `agentMetadata` and `complianceCertifications` terms and the terms and types the W3C DID v1 context lacks (`created`, `updated`, `publicKeyMultibase`, `deactivated`, `Ed25519VerificationKey2020`, `Multikey`, `EcdsaSecp256k1RecoveryMethod2020`). `agentMetadata` stays in the DID document; the controller-issued VC form is not part of 1.0. New `CI — JSON-LD Context` workflow (`npm run check:jsonld-context`) expands the documents in JSON-LD safe mode. RFC-001 gains §4.1.1. No wire change: document hashes, SCIDs and interop vectors are unchanged. The maintainers still have to serve the file at the URL.
- `CI — Third-party did:webvh Resolver` workflow (M-17): `npm run interop:third-party-resolver` serves logs written by `AgentIdentity` in both SDKs (including a log with an update and a key rotation) over HTTPS and resolves them with the DIF Universal Resolver did:webvh driver, run from its published image pinned in `fixtures/third-party-resolver.json`; the driver must also refuse a tampered log. The conformance matrix row for C-EXT-1 moves from PARTIAL to PASS (scoped). Tests only; no behavior change.
- [docs/Threat-Model.md](docs/Threat-Model.md) (M-15): STRIDE threat model of creation, log publication, resolution, HTTP signing, A2A handoff and revocation, with the residual risks that remain after the rc.3 fixes. `docs/S1-3-Adversarial-Review-Crypto-Signing.md` is now labeled historical and gains a post-rc.3 addendum; RFC-001 gains an informative §8.1 (security considerations by flow). `SECURITY.md` links the model and drops its stale "no fuzzing" limitation.

- Property tests and fuzzing of the input parsers (M-14): `fast-check` (`sdk/tests/Fuzz.property.test.ts`) and `hypothesis` (`sdk-python/tests/test_fuzz_properties.py`) cover the `Signature-Input` / `Signature` Structured Fields parsers, `did.jsonl` resolution (arbitrary text, arbitrary JSON lines, mutated and truncated valid logs) and `publicKeyMultibase`. Malformed input must only raise the documented error type; valid input must round-trip. The new `CI — Fuzz` workflow runs them nightly with a much larger budget.
- `decodePublicKeyMultibase` / `decode_public_key_multibase` reject an empty string with the documented error (Python raised `IndexError`, found by the new fuzzing).
- `CI — Structured Field Tests` workflow: runs the [`httpwg/structured-field-tests`](https://github.com/httpwg/structured-field-tests) (RFC 8941) dictionary cases, pinned in `fixtures/structured-field-tests.json`, through the `Signature-Input` and `Signature` parsers of both SDKs: malformed input is rejected, valid input inside the accepted subset parses to the expected value and valid input outside it is rejected. Both SDKs also reproduce the RFC 9530 `Content-Digest` example. Tests only; no behavior change.
- [docs/External-Conformance-Matrix.md](docs/External-Conformance-Matrix.md) (M-12): conformance with external specifications (did:webvh test suite, RFC 9421 Appendix B and independent implementations, RFC 8785 vectors), each row tied to the CI job that proves it. W3C DID Core is marked not covered.
- HTTP `Signature-Input` / `Signature` parsing (RFC 8941 Structured Fields) now uses a maintained library (`structured-headers` in `@agentdid/sdk`, `http-sf` in `agent-did-sdk`) instead of hand-written parsers (M-10). The accepted grammar is unchanged: inner lists of string components, integer / string / token / boolean parameters, duplicate parameters rejected. No wire format changes. `@agentdid/sdk` maps the type-only import of `structured-headers` through `tsconfig` `paths` because its package metadata is `exports`-only.
- New optional npm package `@agentdid/evm` (`evm/`) with its own CI job (`ci-evm.yml`).
- **`AgentDidClient`** (`@agentdid/sdk`, `agent-did-sdk`): an instance that owns all identity state that used to be process-global static state of `AgentIdentity` (resolver, registry, HTTP-signature replay store, document history, did:webvh logs and controller signers). Options: `resolver`, `registry`, `nonceStore` / `nonce_store`, `clock`, `webvhDomain` / `webvh_domain`. Two clients never share state, so tests and multi-tenant hosts no longer need to reset or poke private statics. `AgentIdentity` takes an optional `client` in its config and exposes `getDefaultClient()` / `setDefaultClient()` (`get_default_client()` / `set_default_client()`).
- The static `AgentIdentity` API (`resolve`, `verifySignature`, lifecycle operations, history import/export, `setResolver`, `useProductionResolver*`...) keeps working unchanged as a facade over the default client and is now documented as deprecated, with removal planned for 2.0. This is additive: no behavior or wire format changes.
- The LangChain (JS and Python), CrewAI, Semantic Kernel, Microsoft Agent Framework and A2A integrations now resolve, verify and rotate through `agentIdentity.client` instead of the static `AgentIdentity` API, so an integration built around an identity with its own `AgentDidClient` no longer touches the process-wide default state. Identities without an explicit client behave as before.
- `AgentDidClient` / `client.py` no longer hold all the logic (M-10). The pure parts moved into internal modules, mirrored in both SDKs and not exported: `webvh/documents` (genesis templates, history from a did:webvh log), `lifecycle/documents` (update and rotation builders, timestamps), `verification/signature` (signature checks against a resolved document) and `http-signatures/verify-request` (Agent-DID request profile and replay check). The client keeps state, resolution, revocation and authorization. No behavior, wire format or public API changes; only the private members of the TS signature snapshot changed.

---

## [1.0.0-rc.3] - 2026-11-03

Breaking release candidate, tagged `v1.0.0-rc.3`. All eight co-versioned packages move to `1.0.0-rc.3` (npm, dist-tag `next`) / `1.0.0rc3` (PyPI). Every user of `1.0.0-rc.2` / `1.0.0rc2` should upgrade: `did:webvh` DIDs, document references, metadata commitments and HTTP signatures change format, so rc.2 and rc.3 do not interoperate. Follow [sdk/MIGRATION-1.0-rc.2-to-rc.3.md](sdk/MIGRATION-1.0-rc.2-to-rc.3.md) or [sdk-python/MIGRATION-1.0-rc.2-to-rc.3.md](sdk-python/MIGRATION-1.0-rc.2-to-rc.3.md).

### Changed (breaking)

- **`documentRef` canonicalization is now RFC 8785 (JCS)** in `@agentdid/sdk` and `agent-did-sdk`. `canonicalizeJson` / `canonicalize_json` and `generateCanonicalDocumentHash` / `generate_canonical_document_hash` sort members by UTF-16 code units, serialize numbers per ECMAScript, and no longer rewrite `created` / `updated` / `timestamp` values before hashing. Python keeps `None` members as `null` instead of dropping them. Document references computed by `1.0.0-rc.2` or earlier do not match the new ones; see `sdk/MIGRATION-1.0-rc.2-to-rc.3.md` and `sdk-python/MIGRATION-1.0-rc.2-to-rc.3.md`.
- `UniversalResolverClient` (TS and Python) now stores documents under the same canonical `documentRef` that `AgentIdentity` registers. Previously each resolver hashed a non-canonical serialization, so stored keys differed from registered references and between the two SDKs.
- `agent-did-sdk` adds the `rfc8785` dependency (Trail of Bits, zero dependencies). `@agentdid/sdk` hashes with `@noble/hashes` instead of `ethers` in `crypto/hash`.
- **`UniversalResolverClient` verifies documents resolved through a registry `documentRef`** (TS and Python). The fetched document must hash to the `hash://sha256/` reference and carry the requested `id`; otherwise resolution fails with `DocumentIntegrityError` and never falls back to another source. Fallback still applies to availability failures. References with any other scheme (for example `ipfs://`) are rejected unless listed in the new `unverifiedDocumentRefSchemes` / `unverified_document_ref_schemes` option, which also emits a `source-fetched` event marking the resolution as unverified. In TS, a document returned by the fallback resolver is no longer re-checked and re-cached as if it came from the primary source.

- **`systemPromptHash` and `coreModelHash` are salted commitments**: `hash://hmac-sha256/<hex>` (HMAC-SHA256 keyed with a random 32-byte salt), replacing the unsalted `hash://sha256/` digests whose short or predictable inputs could be confirmed by guessing. `create()` generates one salt per field (or uses `coreModelSalt` / `systemPromptSalt`) and returns them once in `CreateAgentResult.metadataCommitmentSalts` / `metadata_commitment_salts`. `updateDidDocument` / `update_did_document` now **require** the matching salt when `coreModel` / `systemPrompt` changes, since the method returns only the document.

- **`did:webvh` DIDs are did:webvh v1.0 DIDs** in both SDKs ([ADR-002](docs/ADR-002-did-webvh-v1.0-Implementation.md), step 3). Identifiers created by `1.0.0-rc.2` or earlier cannot be carried over; re-issue them (see the migration guides).
  - `AgentIdentity.create()` writes the agent document as the genesis entry of a `did.jsonl` log with a self-certifying SCID, signed (`eddsa-jcs-2022`) by the controller key, which is the log's only `updateKeys` entry. `updateDidDocument`, `rotateVerificationMethod` and `revokeDid` append controller-signed entries; `revokeDid` appends `deactivated: true`.
  - Explicit profile: `webvh.controllerSigner` / `controller_signer` (an `AgentSigner`) is required and `webvh.scid` is removed, since the SCID is derived from the genesis entry. `controllerDid: '{DID}'` creates a self-controlled DID. Implicit `agents.local` profile: the bootstrap controller is also a v1.0 log; its DID is no longer derived from the wallet address.
  - Lifecycle methods take an optional controller signer (`{ controllerSigner }` / `controller_signer=`). It defaults to the signer retained when the DID was created in the same process and is required for DIDs loaded with `importDidWebvhHistory`.
  - `exportDidWebvhHistory` returns the v1.0 log; `importDidWebvhHistory` (and the file/source restore helpers) accept only logs that verify.
  - `UniversalResolverClient` resolves `did:webvh` DIDs by fetching `did.jsonl` from the URL the DID maps to under did:webvh v1.0 and verifying the log before use. A log that fails verification raises `DocumentIntegrityError` and never falls back; a deactivated DID is refused. The default `webvhDocumentSource` is `WebvhDIDDocumentSource`, and a custom one must implement `getDidLogByReference` / `get_did_log_by_reference`. `WebvhDIDDocumentSource.getByReference` returns only verified state.
  - `AgentIdentity.resolve` takes a `did:webvh` DID's revocation state from its verified log: the DID is revoked only by a controller-signed `deactivated: true` entry, and the registry record is a derived index that is not consulted. `registry.revoke` alone no longer revokes a `did:webvh` DID, and a stored log that fails verification makes `resolve` fail rather than report the DID as active.
- **HTTP request signatures are RFC 9421 HTTP Message Signatures** in both SDKs (RFC-001 §6.5). `signHttpRequest` / `sign_http_request` cover `"@method" "@authority" "@path" "@query" "content-digest" "date" "signature-agent"` with parameters `created`, `expires`, `nonce`, `keyid`, `alg="ed25519"` and `tag="agent-did"`; the `X-Request-Nonce` header is gone. `verifyHttpRequestSignature` / `verify_http_request_signature` parse `Signature-Input` / `Signature` as RFC 8941 dictionaries, rebuild the RFC 9421 §2.5 signature base, require the profile, and record `(keyid, nonce)` in a `NonceStore` after the signature verifies, so a replayed request returns `false`. Signatures from rc.2 do not verify under rc.3 and vice versa.
- **`@agentdid/sdk` requires Node.js `>=22.12.0`** (was `>=22.0.0`), the floor of the `didwebvh-ts` dependency below.

### Added

- Internal `did:webvh` v1.0 adapter modules, the first step of [ADR-002](docs/ADR-002-did-webvh-v1.0-Implementation.md): `sdk/src/webvh/adapter.ts` over [`didwebvh-ts`](https://github.com/decentralized-identity/didwebvh-ts) `~3.0.0` and `agent_did_sdk.webvh.adapter` over [`did-webvh`](https://github.com/decentralized-identity/didwebvh-py) `>=1.0.1,<1.1` (both DIF, Apache-2.0). They create, update, rotate `updateKeys`, deactivate and verify `did.jsonl` logs, signing through `AgentSigner`. They are not exported and not yet used by `AgentIdentity` or the resolvers. New runtime dependencies: `didwebvh-ts` (TS); `did-webvh`, which pulls `aries-askar` and `aiohttp` (Python). `aries-askar` publishes no `musllinux` or Windows ARM64 wheels, so `agent-did-sdk` does not install on Alpine-based images or Windows ARM64 for now (tracked upstream).
- `fixtures/webvh-log-vectors.json`: `did:webvh` log vectors generated by the TS adapter. Both SDKs reproduce the deterministic logs byte for byte, resolve every positive log to the same document and metadata, and reject every negative log; checked in `interop:check`.
- `DidWebvhError` (with `code`) and `DidWebvhLifecycleOptions` (TS) are exported from both packages.
- `NonceStore` and `InMemoryNonceStore`, and the RFC 9421 helpers `buildSignatureBase` / `parseSignatureInputHeader` / `parseSignatureHeader` / `serializeSignatureInput` (TS) and `build_signature_base` / `parse_signature_input_header` / `parse_signature_header` / `serialize_signature_input` (Python), plus `AGENT_DID_HTTP_SIGNATURE_COMPONENTS` and `AGENT_DID_HTTP_SIGNATURE_TAG`. `verifyHttpRequestSignature` accepts `nonceStore` / `nonce_store`.
- HTTP signature tests: RFC 9421 Appendix B.2.6 reproduced byte for byte, and cross-verification in both directions with the independent `http-message-signatures` packages (npm and PyPI, dev dependencies only). `fixtures/interop-vectors.json` (format 4) now carries the expected signature base, built by `scripts/regenerate-interop-vectors.js` independently of the SDKs.
- `scripts/regenerate-webvh-public-target.js` regenerates the public `did:webvh` smoke target as a v1.0 log.
- `CI — did:webvh Test Suite` workflow: runs the DIF [`didwebvh-test-suite`](https://github.com/decentralized-identity/didwebvh-test-suite) vectors, pinned in `fixtures/didwebvh-test-suite.json`, through both adapters. They resolve every implementation's positive logs (document and metadata checked) and reject the negative logs. Logs that declare witnesses are rejected as unsupported. Its DID-URL negative vectors run against the DID-to-URL derivation (`deriveDidWebvhLogUrl` / `derive_did_webvh_log_url`). The adapters never perform network I/O and reject a log on any unexpected library error.
- `generateCommitmentSalt`, `createMetadataCommitment`, `verifyMetadataCommitment` (TS) and `generate_commitment_salt`, `create_metadata_commitment`, `verify_metadata_commitment` (Python). Verification uses a constant-time comparison and also accepts legacy `hash://sha256/` commitments.
- `fixtures/metadata-commitment-vectors.json`: shared commitment vectors (expected values computed with Python's `hmac`), checked by both SDKs in `interop:check`.
- `fixtures/jcs-vectors.json`: RFC 8785 reference documents and Appendix B number vectors, verified by both SDKs in `interop:check`.
- `DocumentIntegrityError` (TS: `Error` subclass; Python: `ValueError` subclass), exported from both packages.
- Top-level exports of `canonicalizeJson` / `generateCanonicalDocumentHash` (TS) and `canonicalize_json` / `generate_canonical_document_hash` (Python), so verifiers and migrations can recompute a `documentRef`.

### Fixed

- `@agentdid/sdk` no longer declares the private monorepo root (`"agent-did": "file:.."`) as a runtime dependency. The SDK never imported it; the entry only made published manifests reference a local path.

### Build

- `scripts/check-npm-package-manifest.js` inspects the `package.json` inside the packed tarball and rejects runtime dependency specs that do not resolve from the registry (`file:`, `link:`, `workspace:`, paths, git or URL specs). It runs in the TypeScript SDK and LangChain JS CI and gates `publish-release-train.yml` and `publish-sdk.yml` before publication.

---

## [1.0.0-rc.2] - 2026-11-02

Security release for the `1.0.0-rc.1` train. All eight co-versioned packages move to `1.0.0-rc.2` (npm, dist-tag `next`) / `1.0.0rc2` (PyPI). Every user of `1.0.0-rc.1` / `1.0.0rc1` should upgrade.

### Security

- Fixes [GHSA-g97p-4qrw-9hvf](https://github.com/edisonduran/agent-did/security/advisories/GHSA-g97p-4qrw-9hvf): bootstrap controller keys in `@agentdid/sdk@1.0.0-rc.1` and `agent-did-sdk==1.0.0rc1` were derived from public data. See the advisory for impact and remediation.

### Added

- `CreateAgentResult.controllerPrivateKey` (TS) / `CreateAgentResult.controller_private_key` (Python): when `create()` registers the local bootstrap controller for the implicit `did:webvh` profile, the controller's Ed25519 private key is returned once to the caller.

### Changed

- Bootstrap controller keys are now generated with a CSPRNG for each new bootstrap controller document; no key material is derived from DID strings.
- `create()` no longer registers a bootstrap controller document when `webvh` options with an explicit `controllerDid` are supplied. That controller must be published and resolvable through the configured resolver for controller-chain verification to succeed.

---

## [1.0.0-rc.1] - 2026-11-01

First co-versioned release candidate, tagged `v1.0.0-rc.1`. npm packages publish `1.0.0-rc.1` under dist-tag `next`; Python packages publish `1.0.0rc1` as PyPI prereleases.

### Added

- `docs/RELEASE-1.0-CRITERIA.md` — non-negotiable exit criteria and per-sprint work plan toward `1.0.0`.
- Root `CHANGELOG.md` (this document).
- `docs/RELEASE-1.0-INTEGRATION-EVIDENCE.md` — explicit release evidence matrix for the shipped integrations in the core release train.
- `sdk/MIGRATION-0.x-to-1.0.md` and `sdk-python/MIGRATION-0.x-to-1.0.md` — executable migration guides for adopters moving onto the `1.0.0` path.

### Changed

- `README.md`, `sdk/README.md`, `sdk-python/README.md`, and `SECURITY.md` now consistently frame EVM/on-chain material as an optional deferred profile rather than a core `1.0.0` assumption.
- `docs/RELEASE-1.0-CRITERIA.md`, `README.md`, and this changelog now treat `1.0.0-rc.1` as the default first prerelease and reserve the 30-day green-window gate for the final stable `v1.0.0` tag.
- RFC-001 is now marked Stable in-repo for the `1.0.0-rc.1` release train, with `docs/INDEX.md`, `docs/RFC-001-CHANGELOG.md`, and `docs/DEPRECATION-POLICY.md` aligned to the frozen release contract.
- Core package manifests are now pinned to the `1.0.0-rc.1` release train (`1.0.0-rc.1` on npm packages, `1.0.0rc1` on Python packages) and a unified `publish-release-train.yml` workflow now orchestrates prerelease publication across npm and PyPI.
- `agent-did-microsoft-agent-framework` now accepts `agent-framework>=1.0.1,<2` (validated against `1.24.0`); the previous `<1.1` cap had become unresolvable.

### Fixed

- `agent-did-langchain` no longer emits duplicate LangSmith child runs with `langsmith>=0.14`.

### Build

- `publish-release-train.yml` upgrades npm to `>=11.5.1` for OIDC trusted publishing and publishes each PyPI package from its own GitHub environment (`pypi-<package>`).
- `@agentdid/langchain` declares `repository` metadata, required for npm provenance.

### Security

- HTTP message signatures in `@agentdid/sdk` and `agent-did-sdk` now cover the signature parameters (`created`, `expires`, `keyid`, `alg`) through an `"@signature-params"` line in the signature base (RFC 9421 §2.5). Previously those parameters were unsigned, so a captured request could be replayed with rewritten `created`/`expires` values. **Breaking wire change:** signatures produced by `@agentdid/sdk` ≤ 0.2.0 or `agent-did-sdk` ≤ 0.1.0 do not verify with this release, and vice versa. The shared interop fixture moves to `formatVersion: 3`.
- `@agentdid/sdk` and `@agentdid/langchain` now declare `engines.node >=22.0.0`. Node 18 and 20 are end-of-life and did not receive the October 2026 Node.js security releases; DID resolution fetches documents from arbitrary hosts, so verifiers should run Node 22.23.4+, 24.22.1+ or 26.12.1+. CI and publish workflows move to Node 24 (contract audit to Node 22 for Hardhat 2 compatibility).

---

## Pre-1.0 History (summary)

> For granular detail prior to the introduction of this CHANGELOG, see:
> - [docs/RFC-001-Implementation-Backlog.md](docs/RFC-001-Implementation-Backlog.md) — full execution log of epics P1, P2 and P3 (16/16 ✅).
> - [docs/RFC-001-Compliance-Checklist.md](docs/RFC-001-Compliance-Checklist.md) — MUST/SHOULD conformance status per release.
> - Release history on [GitHub Releases](https://github.com/edisonduran/agent-did/releases) and per-package CHANGELOG.

### Notable pre-1.0 milestones

- **`@agentdid/sdk@0.2.0`** published on npm.
- **`agent-did-sdk@0.1.0`** published on PyPI.
- Native integrations for LangChain (JS + Python), CrewAI, Semantic Kernel, Microsoft Agent Framework and Google A2A.
- RFC-001 conformance: MUST `11/11 PASS`, SHOULD `5/5 PASS`.
- Security hardening: HTTP signature anti-replay, SSRF guards, signer abstraction (KMS/HSM-ready), atomic registration, W3C-compliant multibase, post-rotation historical verification.

---

[Unreleased]: https://github.com/edisonduran/agent-did/compare/v1.0.0-rc.2...HEAD
[1.0.0-rc.2]: https://github.com/edisonduran/agent-did/releases/tag/v1.0.0-rc.2
[1.0.0-rc.1]: https://github.com/edisonduran/agent-did/releases/tag/v1.0.0-rc.1
