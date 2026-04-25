# Security Policy

> **Project status: Public Review (pre-1.0).** Agent-DID is an open standard and reference implementation under active community review. APIs and on-wire formats may evolve. Treat all security findings as high-priority signal: this is the moment to harden the protocol before broad production adoption.

This policy describes **how to report security vulnerabilities**, **what we consider in scope**, and **how the project actually thinks about security** — including known limitations, threat model assumptions, and the layered defenses that exist today.

---

## 1. Reporting a Vulnerability

**Please do NOT open public GitHub issues for security vulnerabilities.**

### Preferred channel

- **Email**: [agent.ai.did@gmail.com](mailto:agent.ai.did@gmail.com)
- **Subject prefix**: `[SECURITY]` followed by a short descriptor (e.g. `[SECURITY] HTTP signature replay across resolver cache`).

### What to include

A useful report contains, at minimum:

1. **Affected component(s)** — `sdk/` (TypeScript), `sdk-python/`, `contracts/`, one of the `integrations/<framework>/`, the resolver, the EVM registry, the HTTP signature layer, etc.
2. **Affected version(s)** — package version and/or commit hash.
3. **Vulnerability class** — e.g. signature forgery, replay, key leakage, denial of service, supply chain, dependency CVE, smart contract logic bug.
4. **Reproduction steps** — minimal repro, ideally a script or test case.
5. **Impact assessment** — what an attacker can do, under what assumptions.
6. **Suggested mitigation** — optional, but appreciated.

PGP encryption is **not** required today. If you require encrypted communication, mention it in your first email and we will agree on a key out-of-band.

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

Until Agent-DID reaches v1.0, security fixes are applied to the **latest published version** of each package. We do not yet maintain LTS branches.

| Package | Channel | Currently supported |
|---|---|---|
| `@agentdid/sdk` | npm | latest published (`v0.2.x` line) |
| `agent-did-sdk` | PyPI | latest published (`v0.1.x` line) |
| Reference smart contracts | repo `contracts/` | `master` branch (no mainnet deployment claimed) |
| Framework integrations | repo `integrations/*/` | `master` branch |

Older versions may receive backports for critical issues at maintainer discretion. The deprecation and breaking-change policy is documented in [`docs/DEPRECATION-POLICY.md`](docs/DEPRECATION-POLICY.md).

---

## 3. Threat Model — What Agent-DID Defends Against (and What It Does Not)

A security policy that doesn't state its threat model is theater. Here is what Agent-DID actually assumes.

### 3.1 In scope (Agent-DID is responsible)

| # | Threat | Defense mechanism |
|---|---|---|
| T1 | **Identity impersonation of an agent** (an attacker claims to be a known agent) | Ed25519 signatures bound to a published DID document; verifier resolves the DID and checks signature against the declared `verificationMethod`. |
| T2 | **Tampering with a signed payload in transit** | Ed25519 detached signature + canonical serialization of the signed payload. |
| T3 | **Replay of a signed HTTP request** | HTTP message signing per the canonical scheme documented in [`docs/Anti-Replay-HTTP-Signatures.md`](docs/Anti-Replay-HTTP-Signatures.md): timestamp window, nonce, request-target binding, and `created`/`expires` parameters. |
| T4 | **Use of a key after compromise / agent retirement** | Revocation lifecycle on the EVM registry (or the equivalent for `did:web` / `did:wba`) propagated through resolver clients with cache invalidation. Resolver HA drill (`npm run smoke:ha`) exercises this path. |
| T5 | **Unauthorized revocation** of an agent identity by a third party | On-chain access policy: only `owner`, an explicitly delegated revoker (`setRevocationDelegate`), or the new owner after `transferAgentOwnership` may revoke. Validated by `npm run smoke:policy`. |
| T6 | **DID document forgery via a malicious resolver** | DID document content is verified against the controller's signing material; resolvers are **untrusted transport**, not trusted authorities. The TS and Python SDKs verify the document on receipt, not on-trust. |
| T7 | **Cross-SDK divergence enabling parser confusion** | Conformance suite (`npm run conformance:rfc001`) runs against shared fixtures in `fixtures/`. Both TS and Python SDKs are required to agree on every conformance vector. |
| T8 | **Supply chain tampering of the published packages** | npm and PyPI packages are published from CI through tagged release workflows (`.github/workflows/publish-*.yml`). Manual pipeline runs are auditable in repo history. Provenance (npm provenance, PyPI trusted publishing) is on the hardening roadmap; see §6. |
| T9 | **Smart contract vulnerabilities in the EVM registry** | Slither + Mythril run in CI via `.github/workflows/contract-audit.yml`. Findings tracked in [`contracts/reports/security/README.md`](contracts/reports/security/README.md) with explicit accepted-noise rules in [`contracts/audit-triage-rules.json`](contracts/audit-triage-rules.json). Current state: 0 actionable, 0 blocking. |

### 3.2 Out of scope (Agent-DID does NOT solve)

State this clearly so reports based on these assumptions are not surprising:

| # | Threat | Why out of scope |
|---|---|---|
| O1 | **Compromise of the agent's private key on its host** | Key custody is the responsibility of the deploying operator. Agent-DID provides revocation as the recovery path, not key sealing or HSM integration (planned, not shipped). |
| O2 | **Prompt injection or jailbreak of the underlying LLM** | Agent-DID provides identity and integrity for *what the agent says it did*, not semantic safety of *what the LLM generated*. This is intentional — see [`docs/PHILOSOPHY.md`](docs/PHILOSOPHY.md). |
| O3 | **Authorization (what an agent is allowed to do)** | Agent-DID provides authentication and binding of declared capabilities; it does not enforce them. Authorization is the relying party's responsibility. |
| O4 | **Confidentiality of agent payloads** | Signing ≠ encryption. Use TLS / channel encryption / payload encryption at the transport or application layer as required. |
| O5 | **Front-running or MEV against revocation transactions** | Revocation latency is bounded by L1 finality of the chain in use. Operators in adversarial environments should pre-stage revocation infrastructure. |
| O6 | **Trust of the controller (the human or org behind the agent)** | Agent-DID binds the agent to its controller cryptographically; trust in the controller itself is an external concern (KYC, organizational identity, etc.). |
| O7 | **Operational compromise of a registry node, resolver host, or PyPI/npm account** | Standard infrastructure security applies. We document the published channels (§2) so detection of unexpected releases is possible. |

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
4. **EVM `AgentRegistry` contract** access control: `owner`, delegated revoker, ownership transfer.
5. **Integration adapters** in `integrations/*/`: identity must be injected without being mutable by the LLM-generated content.

The conformance suite (`npm run conformance:rfc001`) and the smoke drills (`npm run smoke:e2e`, `npm run smoke:ha`, `npm run smoke:rpc`, `npm run smoke:policy`) are the primary defensive testing surface today.

---

## 5. Known Limitations During Public Review

These are publicly acknowledged limitations in the current Public Review baseline. Reports about them are welcome but expected — they are documented work, not undisclosed risk:

- **No formal external audit yet.** Roadmap item F3-04 (formal contract audit for mainnet deployment) is planned. The repository runs automated audit tools in CI but has not been reviewed by an independent firm.
- **Resolver backend is in-memory by default.** F2-03 tracks production resolver work. Operators running their own resolver should harden persistence and access control.
- **No public testnet deployment of `AgentRegistry`.** F2-06 tracks this. Until then, third-party verification of on-chain behavior depends on running the contract locally.
- **No fuzzing of the HTTP signature verifier.** Property-based / adversarial tests for replay, header injection, and signature stripping are an open contribution area.
- **Cross-SDK interop tests** exist via the shared conformance fixtures but are not yet exercised as a dedicated CI matrix that signs in one SDK and verifies in the other end-to-end on every PR.
- **Supply chain provenance** (npm `--provenance`, PyPI Trusted Publishers, Sigstore) is not yet enabled on the publish workflows; see §6.

---

## 6. Hardening Roadmap (security-relevant)

Items the maintainers track as security-relevant work, in addition to the public roadmap in `README.md`:

- Enable npm `--provenance` on `publish-sdk.yml`.
- Enable PyPI Trusted Publishing for `agent-did-sdk`.
- Add Sigstore signing for release artifacts.
- Add a dedicated `cross-sdk-interop` CI workflow that signs payloads and HTTP requests in TS and verifies in Python, and vice versa, on every PR.
- Add property-based / fuzz tests for the HTTP signature parser/verifier and DID document parser.
- Add a documented threat model and security considerations section to the published RFC-001 (currently lives partially here and partially in `docs/Anti-Replay-HTTP-Signatures.md`).
- Stand up a public testnet deployment of `AgentRegistry` with a published address and verification instructions.
- Engage an external auditor before any maintainer-recommended mainnet deployment.

If you want to contribute to any of these, see [`CONTRIBUTING.md`](CONTRIBUTING.md) and tag your issue or PR `[Security]`.

---

## 7. Acknowledgements

Researchers and contributors who responsibly disclose vulnerabilities will be credited here, with their permission, once their reported issue is fixed and disclosed.

_(This list will grow as the project matures. Be the first.)_

---

## 8. Contact Summary

- **Reports**: [agent.ai.did@gmail.com](mailto:agent.ai.did@gmail.com) — subject prefix `[SECURITY]`
- **Public discussion of non-sensitive security topics**: GitHub Discussions (category `Q&A` or `Ideas`)
- **General contribution guidance**: [`CONTRIBUTING.md`](CONTRIBUTING.md)
- **Project status and governance**: [`docs/Documentation-Governance.md`](docs/Documentation-Governance.md)
