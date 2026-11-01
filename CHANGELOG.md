# Changelog

All notable changes to the **Agent-DID** ecosystem are documented here.

The format follows [Keep a Changelog 1.1.0](https://keepachangelog.com/en/1.1.0/) and, starting with version `1.0.0`, this project adheres to [Semantic Versioning 2.0.0](https://semver.org/spec/v2.0.0.html) per [docs/DEPRECATION-POLICY.md](docs/DEPRECATION-POLICY.md).

> **Scope:** this root CHANGELOG records the *release train* of the core ecosystem (RFC + SDKs + integrations co-versioned starting at 1.0.0). Per-package `CHANGELOG.md` files are still pending (`C-DOC-1` in [docs/RELEASE-1.0-CRITERIA.md](docs/RELEASE-1.0-CRITERIA.md)).

---

## [Unreleased]

### Planned (path to 1.0.0)

See [docs/RELEASE-1.0-CRITERIA.md](docs/RELEASE-1.0-CRITERIA.md). Remaining after `1.0.0-rc.1`:

- Clean-machine install smokes of the published RC packages from npm and PyPI.
- `agent-did-in-action` demo switched to the RC, plus a focused feedback window of at least one week.
- Stable `v1.0.0` remains gated by the 30-day green window on the core release-critical workflows.

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

[Unreleased]: https://github.com/edisonduran/agent-did/compare/v1.0.0-rc.1...HEAD
[1.0.0-rc.1]: https://github.com/edisonduran/agent-did/releases/tag/v1.0.0-rc.1
