# Security Policy

> **Project status: Public Review (pre-1.0).** Agent-DID is an open standard and reference implementation under active community review. APIs and on-wire formats may evolve. Treat all security findings as high-priority signal: this is the moment to harden the protocol before broad production adoption.

This policy describes **how to report security vulnerabilities**, **what we consider in scope**, and **how the project actually thinks about security** — including known limitations, threat model assumptions, and the layered defenses that exist today.

---

## 1. Reporting a Vulnerability

**Please do NOT open public GitHub issues for security vulnerabilities.**

### Channels

- **Email**: [security@agent-did.org](mailto:security@agent-did.org)
  - **Subject prefix**: `[SECURITY]` followed by a short descriptor (e.g. `[SECURITY] HTTP signature replay across resolver cache`).
- **GitHub**: [report a vulnerability privately](https://github.com/edisonduran/agent-did/security/advisories/new) from the repository's Security tab. The report stays private between you and the maintainers.

Either channel is fine; use the one you prefer.

### What to include

A useful report contains, at minimum:

1. **Affected component(s)** — `sdk/` (TypeScript), `sdk-python/`, one of the `integrations/<framework>/`, the resolver, the HTTP signature layer, the EVM profile in `edisonduran/agent-did-evm`, etc.
2. **Affected version(s)** — package version and/or commit hash.
3. **Vulnerability class** — e.g. signature forgery, replay, key leakage, denial of service, supply chain, dependency CVE, smart contract logic bug.
4. **Reproduction steps** — minimal repro, ideally a script or test case.
5. **Impact assessment** — what an attacker can do, under what assumptions.
6. **Suggested mitigation** — optional, but appreciated.

### Encrypting your report (optional)

Encryption is not required. To encrypt an email report, use the project's OpenPGP key:

- **Key**: [`.github/security/agent-did-security.asc`](.github/security/agent-did-security.asc) (`Agent-DID Security <security@agent-did.org>`)
- **Fingerprint**: `9C56 A739 51F4 9EB7 F4FE  FF43 1037 7F82 E83D 3A8A`

Check the fingerprint before you use the key. The key file is owned by the maintainers in `CODEOWNERS`, and the fingerprint above is the one to trust: a pull request that changes either is a change to this policy. A machine-readable summary of these contacts is in [`.github/security/security.txt`](.github/security/security.txt) (RFC 9116).

### Coordinated disclosure

We follow a **coordinated disclosure** model with a **fix coordinated to severity**:

- We will **acknowledge receipt** of your report and **work with you in private** on validation and remediation.
- The remediation timeline (patch development, release, public disclosure) is **calibrated to the severity** and exploitability of the issue, not to a fixed clock. Critical issues with active exploit paths are prioritized aggressively; low-severity hardening items are batched into normal release cycles.
- We will **credit you publicly** in the release notes and `SECURITY.md` history when the fix ships, unless you ask us not to.
- Please **do not publish** details (blog posts, tweets, conference talks, public PRs) until we have agreed on a disclosure date.

### Out of scope for this policy

- Bugs in third-party dependencies that have already been disclosed and patched upstream — please open a normal issue or a dependency-bump PR.
- Reports based exclusively on automated scanner output without a demonstrated impact path. We accept these but treat them as low priority and may close them if they match the **accepted known noise** documented in [`contracts/reports/security/README.md`](contracts/reports/security/README.md).
- Theoretical issues that depend on assumptions we explicitly **do not** make (see §3 "Threat model").

---

## 2. Supported Versions

Until Agent-DID reaches v1.0, security fixes are applied to the **latest published release candidate** of each package. We do not yet maintain LTS branches.

| Package | Channel | Currently supported |
|---|---|---|
| `@agentdid/sdk`, `@agentdid/langchain` | npm | latest published (`1.0.0-rc.5` line) |
| `agent-did-sdk` and the Python integrations | PyPI | latest published (`1.0.0rc5` line) |
| Deferred EVM profile (`AgentRegistry` contract, `@agentdid/evm`, `agent-did-evm`) | repo `edisonduran/agent-did-evm` | `main` branch (optional profile only; no public testnet or mainnet deployment claimed). Report through this policy |
| Framework integrations | repo `integrations/*/` | `main` branch |

The `0.x` releases (`@agentdid/sdk` 0.2.0, `agent-did-sdk` 0.1.0) predate the 1.0 profile and are not supported: their DIDs and HTTP signatures do not interoperate with the release candidates (see the migration guides). Older release candidates are not supported either; upgrade to the latest one. Backports may be made at maintainer discretion. The deprecation and breaking-change policy is documented in [`docs/DEPRECATION-POLICY.md`](docs/DEPRECATION-POLICY.md).

---

## 3. Threat Model — What Agent-DID Defends Against (and What It Does Not)

A security policy that doesn't state its threat model is theater. Here is what Agent-DID actually assumes.

### 3.1 In scope (Agent-DID is responsible)

| # | Threat | Defense mechanism |
|---|---|---|
| T1 | **Identity impersonation of an agent** (an attacker claims to be a known agent) | Ed25519 signatures bound to a published DID document; verifier resolves the DID and checks signature against the declared `verificationMethod`. |
| T2 | **Tampering with a signed payload in transit** | Ed25519 detached signature + canonical serialization of the signed payload. |
| T3 | **Replay of a signed HTTP request** | RFC 9421 HTTP Message Signatures with the Agent-DID profile in [`docs/Anti-Replay-HTTP-Signatures.md`](docs/Anti-Replay-HTTP-Signatures.md): `created`/`expires` window, method/authority/path/query binding, and a `nonce` the verifier records in a `NonceStore` after the signature verifies. |
| T4 | **Use of a key after compromise / agent retirement** | Revocation lifecycle on the canonical `did:webvh` controller chain, propagated through resolver clients with cache invalidation. Resolver HA drill (`npm run smoke:ha`) exercises the core web-native path; `npm run smoke:e2e` checks that a revoked DID's signatures stop verifying, also for a verifier that only has the published logs. |
| T5 | **Unauthorized revocation** of an agent identity by a third party | On `did:webvh`, revocation is a log entry signed by a current `updateKey`: a third party's key cannot revoke, rotate or update the DID, and a registry record alone does not revoke it. Validated by `npm run smoke:policy` and `sdk-python/scripts/revocation_policy_smoke.py`. The optional EVM profile has its own contract-level policy (owner, delegated revoker, ownership transfer) in `edisonduran/agent-did-evm`. |
| T6 | **DID document forgery via a malicious resolver** | DID document content is verified against the controller's signing material; resolvers are **untrusted transport**, not trusted authorities. The TS and Python SDKs verify the document on receipt, not on-trust. |
| T7 | **Cross-SDK divergence enabling parser confusion** | Conformance suite (`npm run conformance:rfc001`) runs against shared fixtures in `fixtures/`. Both TS and Python SDKs are required to agree on every conformance vector. |
| T8 | **Supply chain tampering of the published packages** | npm and PyPI packages are published from CI through tagged release workflows (`.github/workflows/publish-sdk.yml`, `.github/workflows/publish-python-sdk.yml`). Manual pipeline runs are auditable in repo history. npm publication is wired for GitHub Actions provenance, and PyPI publication is wired for Trusted Publishing via OIDC. Sigstore and extra attestations remain on the hardening roadmap; see §6. |
| T9 | **Smart contract vulnerabilities in the deferred EVM profile** | The contract and its Slither + Mythril CI, triage rules and reports live in [edisonduran/agent-did-evm](https://github.com/edisonduran/agent-did-evm). The core SDKs do not depend on it. |
| T10 | **Key-purpose confusion** where a valid DID key is used outside its intended verification relationship | SDK verification enforces purpose binding: payload and HTTP signatures require `assertionMethod` by default, `keyAgreement` is never accepted for signing, and mismatches surface `key_purpose_violation`. |

### 3.2 Out of scope (Agent-DID does NOT solve)

State this clearly so reports based on these assumptions are not surprising:

| # | Threat | Why out of scope |
|---|---|---|
| O1 | **Compromise of the agent's private key on its host** | Key custody is the responsibility of the deploying operator. Agent-DID provides revocation as the recovery path, not key sealing or HSM integration (planned, not shipped). |
| O2 | **Prompt injection or jailbreak of the underlying LLM** | Agent-DID provides identity and integrity for *what the agent says it did*, not semantic safety of *what the LLM generated*. This is intentional — see [`docs/PHILOSOPHY.md`](docs/PHILOSOPHY.md). |
| O3 | **Authorization (what an agent is allowed to do)** | Agent-DID provides authentication and binding of declared capabilities; it does not enforce them. Authorization is the relying party's responsibility. |
| O4 | **Confidentiality of agent payloads** | Signing ≠ encryption. Use TLS / channel encryption / payload encryption at the transport or application layer as required. |
| O5 | **Front-running or MEV against revocation transactions** | Revocation latency is bounded by L1 finality of the chain in use. Operators in adversarial environments should pre-stage revocation infrastructure. |
| O6 | **Trust of the controller (the human or org behind the agent)** | A `did:webvh` agent that names a controller verifies only if the proof of the last entry of its log was made by a key that is active under `capabilityInvocation` of the controller's document, for every link of the controller chain (RFC-001 §6.6 item 7); a verifier that does not hold the agent's log cannot check it and rejects. Residual: whoever holds a controller key listed there can endorse any agent for that controller, so the controller is the root of trust and its key custody (KMS/HSM, pre-rotation) is out of scope of the agent's log. Trust in the controller itself is an external concern (KYC, organizational identity, etc.). |
| O7 | **Operational compromise of a registry node, resolver host, or PyPI/npm account** | Standard infrastructure security applies. We document the published channels (§2) so detection of unexpected releases is possible. |

The per-flow STRIDE analysis (creation, log publication, resolution, HTTP signing, A2A handoff, rotation and revocation) with residual risks is in [`docs/Threat-Model.md`](docs/Threat-Model.md).

### 3.3 Trust assumptions

We assume:

- The verifier has access to a faithful copy of the controller's DID document (directly resolved or via a verifying resolver).
- The cryptographic primitives we depend on (Ed25519, SHA-256 used in canonicalization, the chain's signature scheme) are not broken.
- Time is reasonably synchronized between agent and verifier within the configured anti-replay window.
- The deploying operator protects the agent's private key with controls appropriate to the deployment (file permissions, KMS, HSM, enclave — not specified by the protocol).

---

## 4. Security-Sensitive Surfaces

If you are auditing the project, these are the surfaces with the highest blast radius if compromised:

1. **Signature verification paths** in `sdk/src/` and `sdk-python/`:
   - `verifySignature` / `verify_signature`
   - `verifyHttpRequestSignature` / `verify_http_request_signature`
   - DID document validation on resolution
2. **Canonicalization** of payloads before signing/verification — divergence between TS and Python implementations is a critical class of bug.
3. **Resolver client** cache and failover (`UniversalResolverClient`): a malicious cache entry must not be trusted across resolution rounds.
4. **Optional EVM `AgentRegistry` contract** access control: `owner`, delegated revoker, ownership transfer.
5. **Integration adapters** in `integrations/*/`: identity must be injected without being mutable by the LLM-generated content.

The conformance suite (`npm run conformance:rfc001`) and the smoke drills (`npm run smoke:e2e`, `npm run smoke:ha`, `npm run smoke:rpc`, `npm run smoke:policy`) are the primary defensive testing surface today.

---

## 5. Known Limitations During Public Review

These are publicly acknowledged limitations in the current Public Review baseline. Reports about them are welcome but expected — they are documented work, not undisclosed risk:

- **No formal external audit yet.** Roadmap item F3-04 (formal contract audit for mainnet deployment) is planned. The repository runs automated audit tools in CI but has not been reviewed by an independent firm.
- **Resolver persistence is not bundled by default.** The universal resolver core is shipped, but F2-03 tracks operator-grade persistent backend hardening and optional additional transports such as Arweave. Operators running their own resolver should harden persistence and access control.
- **EVM/on-chain profile is deferred outside core 1.0** and lives in `edisonduran/agent-did-evm`. Core `did:webvh` verification does not depend on public testnet deployment or on-chain overlay behavior. Any future EVM profile will require a separate scope decision and security review.
- **Fuzzing covers the input parsers, not the whole verifier.** Property tests and nightly fuzzing (`ci-fuzz.yml`) exercise the `Signature-Input` / `Signature` parsers, `did.jsonl` resolution and `publicKeyMultibase`. Adversarial tests for replay, header injection, and signature stripping beyond that remain an open contribution area.
- **Cross-SDK interop tests** now run as a dedicated release workflow via `.github/workflows/ci-cross-sdk-interop.yml`, but the evidence still focuses on the repo-managed TS/Python fixture corpus rather than a third-party implementation matrix.
- **Supply chain hardening beyond registry-native provenance** is still incomplete. npm provenance and PyPI Trusted Publishing are wired in repo workflows, but Sigstore signing and broader artifact attestations remain roadmap work; see §6.

---

## 6. Hardening Roadmap (security-relevant)

Items the maintainers track as security-relevant work, in addition to the public roadmap in `README.md`:

- Keep npm Trusted Publishing configuration aligned with `.github/workflows/publish-sdk.yml` and verify provenance on each release.
- Keep PyPI Trusted Publishing configuration aligned with `.github/workflows/publish-python-sdk.yml`.
- Add Sigstore signing for release artifacts.
- Keep the dedicated `cross-sdk-interop` CI workflow green and extend it further when third-party fixture coverage becomes available.
- Done: property-based / fuzz tests for the HTTP signature parsers and DID log resolution (M-14).
- Done: STRIDE threat model of the end-to-end flow in [`docs/Threat-Model.md`](docs/Threat-Model.md) (M-15). RFC-001 §8.1 summarizes it.
- Done: did:webvh pre-rotation (`nextKeyHashes`) is exposed in both SDKs, the only in-protocol recovery from controller key compromise (see the threat model). It is opt-in and protects only if committed before the compromise.
- If the deferred EVM profile is ever re-scoped into active development, stand up a public testnet deployment of `AgentRegistry` with a published address and verification instructions as a separate gate.
- Engage an external auditor before any maintainer-recommended mainnet deployment.

If you want to contribute to any of these, see [`CONTRIBUTING.md`](CONTRIBUTING.md) and tag your issue or PR `[Security]`.

---

## 7. Acknowledgements

Researchers and contributors who responsibly disclose vulnerabilities will be credited here, with their permission, once their reported issue is fixed and disclosed.

_(This list will grow as the project matures. Be the first.)_

---

## 8. Contact Summary

- **Reports**: [security@agent-did.org](mailto:security@agent-did.org) (subject prefix `[SECURITY]`), or a [private report on GitHub](https://github.com/edisonduran/agent-did/security/advisories/new)
- **OpenPGP key**: [`.github/security/agent-did-security.asc`](.github/security/agent-did-security.asc), fingerprint `9C56 A739 51F4 9EB7 F4FE  FF43 1037 7F82 E83D 3A8A`
- **Public discussion of non-sensitive security topics**: GitHub Discussions (category `Q&A` or `Ideas`)
- **General contribution guidance**: [`CONTRIBUTING.md`](CONTRIBUTING.md)
- **Project status and governance**: [`docs/Documentation-Governance.md`](docs/Documentation-Governance.md)
