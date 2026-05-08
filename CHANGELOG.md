# Changelog

All notable changes to the **Agent-DID** ecosystem are documented here.

The format follows [Keep a Changelog 1.1.0](https://keepachangelog.com/en/1.1.0/) and, starting with version `1.0.0`, this project adheres to [Semantic Versioning 2.0.0](https://semver.org/spec/v2.0.0.html) per [docs/DEPRECATION-POLICY.md](docs/DEPRECATION-POLICY.md).

> **Scope:** this root CHANGELOG records the *release train* of the core ecosystem (RFC + SDKs + integrations co-versioned starting at 1.0.0). Each publishable package additionally maintains its own `CHANGELOG.md` with granular detail.

---

## [Unreleased]

### Added

- `docs/RELEASE-1.0-CRITERIA.md` — non-negotiable exit criteria and per-sprint work plan toward `1.0.0`.
- Root `CHANGELOG.md` (this document).

### Planned (path to 1.0.0)

See [docs/RELEASE-1.0-CRITERIA.md](docs/RELEASE-1.0-CRITERIA.md). Summary:

- Co-versioning of the core SDK and integration packages (`@agentdid/sdk`, `agent-did-sdk`, `@agentdid/langchain`, `agent-did-langchain`, `agent-did-crewai`, `agent-did-semantic-kernel`, `agent-did-microsoft-agent-framework`, `agent-did-a2a`) under a single `v1.0.0` tag.
- EVM/on-chain profile work is deferred outside core `1.0.0`; the release train is centered on the `did:webvh` path.
- Promotion of **RFC-001** from `Public Review v1` to `Stable`.
- Public-API freeze per SDK with a blocking snapshot in CI.
- SBOM (CycloneDX) and SLSA L2 provenance for every published package.
- `0.x → 1.0` migration guides per SDK.
- Package × package compatibility matrix.
- Explicit roadmap reconciliation before RC so the README clearly distinguishes what `1.0.0` includes versus which public roadmap tracks remain post-1.0.

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

[Unreleased]: https://github.com/edisonduran/agent-did/compare/main...HEAD
