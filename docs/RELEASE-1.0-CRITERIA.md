# Release 1.0.0 Criteria — Agent-DID

**Status:** Draft
**Audience:** Contributors, Reviewers, Maintainers
**Last updated:** 2026-05-04
**Owner:** Maintainers (`edison.munoz` + team)
**Governed by:** [Documentation-Governance.md](Documentation-Governance.md)

---

## 1. Scope of 1.0.0

This document defines the exit criteria for reaching version **1.0.0 of the Agent-DID ecosystem**: RFC + 9 published packages + integrations + contracts, all co-versioned under a single *release train*.

**A user installing `agent-did 1.0` must obtain a coherent, mutually compatible set:**

| Package | Current version | Target 1.0 | Registry |
|---|---|---|---|
| `@agentdid/sdk` (TypeScript) | 0.2.0 | 1.0.0 | npm |
| `agent-did-sdk` (Python) | 0.1.0 | 1.0.0 | PyPI |
| `contracts` (Solidity) | 0.1.0 | 1.0.0 | EVM mainnet/testnet (anchored) |
| `@agentdid/langchain` (LangChain JS) | 0.1.0 | 1.0.0 | npm |
| `agent-did-langchain` (LangChain Python) | 0.1.0 | 1.0.0 | PyPI |
| `agent-did-crewai` | 0.1.0 | 1.0.0 | PyPI |
| `agent-did-semantic-kernel` | 0.1.0 | 1.0.0 | PyPI |
| `agent-did-microsoft-agent-framework` | 0.1.0 | 1.0.0 | PyPI |
| `agent-did-a2a` | 0.1.0 | 1.0.0 | PyPI |

**RFC-001** must simultaneously transition from `Public Review v1` (Draft) to `Stable`.

## 1.1 Roadmap Alignment

This release plan is intended to be **consistent with the public roadmap in [README.md](../README.md)** and should be read as a **stabilization and release-maturation milestone**, not as completion of every open roadmap track.

The current intent is:

- **Covered by the 1.0 plan**: stabilization and co-versioned release of the already delivered tracks F1-01, F1-02, F1-03, F1-05, F1-06, F2-01, F2-02, F2-04, F2-05, and F2-09.
- **Pulled into 1.0 by release criteria**: F2-06 public testnet deployment, because a public 1.0 contracts release requires a declared deployed address and bytecode hash.
- **Explicitly out of scope for 1.0 unless maintainers change scope**: F1-04 (submit RFC-001 to DIF), F2-03 production-resolver hardening beyond the shipped universal-resolver baseline (persistent backend / operator profile and optional Arweave transport), F2-07 (formal whitepaper publication), F2-08 (Azure AI Agent Service integration), and the full Phase 3 standardization/maturity track.
- **Already available and therefore not a blocker for 1.0**: the universal resolver baseline itself is shipped in both SDKs, including cache, registry lookup, HTTP/IPFS gateway fetching, JSON-RPC support, direct `did:wba` web resolution, and failover-oriented tests/smokes.

---

## 2. Exit Criteria (Non-Negotiable)

### 2.1 Specification

- [ ] **C-SPEC-1** — RFC-001 marked as `Stable` in [docs/INDEX.md](INDEX.md) and on its own header.
- [ ] **C-SPEC-2** — `RFC-001-Compliance-Checklist.md` reports MUST `11/11 PASS` and SHOULD `5/5 PASS`.
- [ ] **C-SPEC-3** — Security section of the RFC reviewed and signed off by ≥1 reviewer external to the lead maintainer.
- [ ] **C-SPEC-4** — Public errata procedure documented in the RFC (how corrections are proposed and accepted post-1.0 without a major bump).

### 2.2 SDKs and Public API

- [ ] **C-API-1** — Public **export-name** baseline frozen and enforced per SDK (first stage of the API gate):
  - TypeScript: versioned export-name snapshot artifact checked into the repo (`sdk/public-api.snapshot.txt`), generated from `sdk/src/index.ts` named exports.
  - Python: explicit `__all__` in public modules + versioned export-name snapshot artifact checked into the repo (`sdk-python/public-api.snapshot.txt`), generated from `__all__` literals.
  - Snapshot drift is a blocking CI failure in `ci.yml` (TS) and `ci-python.yml` (Python).
  - Scope limitation: this stage detects **added/removed/renamed** public exports only. It does **not** detect signature, type, or class-member changes — those are covered by C-API-2.
- [ ] **C-API-2** — Signature-level public API compatibility gate (follow-up to C-API-1):
  - TypeScript: emit `.d.ts` (or use `@microsoft/api-extractor`) and diff the generated API report on every PR.
  - Python: capture signatures and class members via `griffe` or `mypy stubgen` and diff per PR.
  - Any change to this signature-level snapshot requires a major bump (post-1.0).
  - Tracking issue: see `RELEASE-1.0-CRITERIA` follow-up issue *Harden public API snapshot to signature-level gate*.
- [ ] **C-API-3** — `@internal` / private symbols clearly marked; not part of the public contract.
- [ ] **C-API-4** — `MIGRATION-0.x-to-1.0.md` per SDK (TS and Python) with executable `before/after` examples.

### 2.3 Conformance and Interoperability

- [ ] **C-INTEROP-1** — `conformance:rfc001` suite running as a **blocking gate** in CI (not informational).
- [ ] **C-INTEROP-2** — Shared fixtures in `fixtures/` consumed by **both** SDKs in every PR.
- [ ] **C-INTEROP-3** — Equivalent DID documents produce the same `documentRef` (canonical hash) in TS and Python.
- [ ] **C-INTEROP-4** — Compatibility matrix published (package × package, version × version) in `docs/`.

### 2.4 Contracts (Solidity)

- [ ] **C-CONTRACT-1** — `AgentRegistry.sol` ABI **frozen** for 1.0.
- [ ] **C-CONTRACT-2** — Deployed address and bytecode hash for the 1.0 release declared in `contracts/README.md`.
- [ ] **C-CONTRACT-3** — Full triage of audit findings (`audit-triage-rules.json`); no **high**-severity finding left unresolved or without documented justification.
- [ ] **C-CONTRACT-4** — Post-1.0 upgrade policy documented (new contract vs migration).

### 2.5 Coverage and Quality

- [ ] **C-QA-1** — Coverage ≥**85%** lines in `sdk/` and `sdk-python/`.
- [ ] **C-QA-2** — Coverage **100%** in critical modules: `crypto`, `signing`, `verification`, `resolver`.
- [ ] **C-QA-3** — Coverage ≥**75%** per integration (LangChain JS/Py, CrewAI, SK, MS AF, A2A).
- [ ] **C-QA-4** — E2E tests for **anti-replay** (clock skew ±60s, nonce reuse, expired signature).
- [ ] **C-QA-5** — E2E tests for **key rotation** (≥3 cycles) + working historical verification.
- [ ] **C-QA-6** — E2E tests for **revocation** in `did:wba` and EVM with verified propagation.
- [ ] **C-QA-7** — **SSRF** tests covering loopback, link-local, AWS/GCP/Azure metadata, IPv6 mapped.
- [ ] **C-QA-8** — All 11 release-critical GitHub Actions workflows green for **≥30 consecutive days** prior to tagging.
- [ ] **C-QA-9** — Clean-machine smoke install from npm/PyPI validated for the 9 RC packages.
- [ ] **C-QA-10** — Adversarial review (BMad core task `adversarial-review`) completed over crypto and signing code.

### 2.6 Operations and Resolver

- [ ] **C-OPS-1** — Resolver HA drill scheduled in GitHub Actions (`schedule:` weekly), green for ≥4 documented runs.
- [ ] **C-OPS-2** — `RFC-001-Resolver-HA-Runbook.md` validated by a recent dry run.

### 2.7 Supply Chain

- [ ] **C-SUPPLY-1** — SBOM (CycloneDX) generated and published per package.
- [ ] **C-SUPPLY-2** — SLSA L2 provenance via OIDC for npm/PyPI publication.
- [ ] **C-SUPPLY-3** — npm/PyPI publication uses short-lived tokens (no static PATs).

### 2.8 Documentation

- [ ] **C-DOC-1** — Root `CHANGELOG.md` with per-package section and `1.0.0` entry.
- [ ] **C-DOC-2** — `MIGRATION-0.x-to-1.0.md` per SDK.
- [ ] **C-DOC-3** — `DEPRECATION-POLICY.md` updated with strict SemVer post-1.0.
- [ ] **C-DOC-4** — Quickstart validated by ≥1 external contributor on a clean machine.
- [ ] **C-DOC-5** — `docs/INDEX.md` with a **"Releases"** section pointing to CHANGELOG and compatibility matrix.
- [ ] **C-DOC-6** — README no longer carries the *"Public Review v1"* phrasing (replaced with *"Stable 1.0"*) — only at the moment of the final tag.

### 2.9 Demo and Anchor Adopter

- [ ] **C-DEMO-1** — `agent-did-in-action` serving the `1.0.0-rc.N` build during the feedback period.
- [ ] **C-DEMO-2** — Visual smoke without regressions on the public demo with the RC.
- [ ] **C-DEMO-3** — *(Recommended, non-blocking)* At least one external *anchor adopter* willing to publicly state production use of 1.0.

### 2.10 Release Engineering

- [ ] **C-REL-1** — All 9 packages bumped to `1.0.0-rc.1` simultaneously under a single monorepo tag.
- [ ] **C-REL-2** — Public feedback window of **≥1 week** on the RC, announced on GitHub Discussions.
- [ ] **C-REL-3** — `v1.0.0` tag only after every criterion above is met.
- [ ] **C-REL-4** — Public announcement (README badges, Discussions, blog post if applicable) coordinated with the tag.

### 2.11 Roadmap Consistency

- [ ] **C-ROADMAP-1** — README roadmap statuses reconciled against current implementation evidence before `1.0.0-rc.1`.
- [ ] **C-ROADMAP-2** — Any roadmap item still open but not included in `1.0.0` is explicitly documented as post-1.0 scope.
- [ ] **C-ROADMAP-3** — Any roadmap item claimed as part of `1.0.0` has a linked implementation, CI, or release artifact proving readiness.

---

## 3. Work Plan (3 Sprints)

> Detailed and tracked as GitHub issues under the `v1.0.0` milestone.

### Sprint 0 — Release Foundation

Goal: lay the groundwork so Sprints 1 and 2 can execute without scope re-litigation. **Not blocked by any PR currently in review.**

| ID | Task | Suggested owner | Criteria covered |
|---|---|---|---|
| S0-1 | Publish this `RELEASE-1.0-CRITERIA.md` (✅ created) | tech-writer | C-DOC-* |
| S0-2 | Create root `CHANGELOG.md` + per-package CHANGELOG (✅ root created) | tech-writer | C-DOC-1 |
| S0-3 | Audit the 9 CI pipelines: green ≥30 days? File an issue per failure | qa | C-QA-8 |
| S0-4 | Inventory `TODO`/`FIXME`/`@deprecated`/`@internal` across SDKs and integrations | dev | C-API-3 |
| S0-5 | Initial public API snapshot artifacts and verification commands for TS and Python — baseline | architect + dev | C-API-1, C-API-2 |
| S0-6 | Explicit inventory of pending breaking changes that **must** land before 1.0 | architect | C-API-1 |
| S0-7 | Tentative compatibility matrix (package × package) | architect | C-INTEROP-4 |
| S0-8 | Confirm `fixtures/` is consumed by both TS and Python CI on every PR | qa | C-INTEROP-2 |
| S0-9 | Reconcile README roadmap with shipped evidence and classify open items as `1.0` or post-`1.0` (✅ F2-03 classification documented) | pm + architect + tech-writer | C-ROADMAP-1, C-ROADMAP-2, C-ROADMAP-3 |

### Sprint 1 — Hardening and Contracts

Goal: close every quality, security and supply-chain gap. Starts after the currently pending PR is merged.

| ID | Task | Suggested owner | Criteria covered |
|---|---|---|---|
| S1-1 | Implement breaking changes from S0-6 inventory (last train) | dev | C-API-1 |
| S1-2 | Mark `__all__` (Py) and explicit exports (TS) → API surface frozen | dev | C-API-1, C-API-3 |
| S1-3 | Adversarial review (BMad task `adversarial-review`) over crypto/signing | qa | C-QA-10 |
| S1-4 | Resolver HA drill scheduled in GitHub Actions (weekly cron) | architect | C-OPS-1 |
| S1-5 | Raise coverage where missing (targets C-QA-1/2/3) | qa + dev | C-QA-1, C-QA-2, C-QA-3 |
| S1-6 | SBOM (CycloneDX) in each package build | architect | C-SUPPLY-1 |
| S1-7 | SLSA L2 provenance via OIDC for npm/PyPI publish | architect | C-SUPPLY-2, C-SUPPLY-3 |
| S1-8 | Migration guide 0.x→1.0 (TS and Python) with executable `before/after` | tech-writer + dev | C-API-4, C-DOC-2 |
| S1-9 | Full triage of contracts audit findings | qa | C-CONTRACT-3 |
| S1-10 | E2E anti-replay, key rotation, revocation, SSRF | qa | C-QA-4..7 |

### Sprint 2 — Release Candidate and Tag

Goal: publish RC, gather feedback, tag 1.0.0.

| ID | Task | Suggested owner | Criteria covered |
|---|---|---|---|
| S2-1 | Bump the 9 packages to `1.0.0-rc.1` (single tag) | dev | C-REL-1 |
| S2-2 | Publish RC to npm/PyPI under dist-tag `next` / pre-release | dev | C-REL-1 |
| S2-3 | Clean smoke install of the 9 packages from public registries | qa | C-QA-9 |
| S2-4 | `agent-did-in-action` demo serving the RC | dev | C-DEMO-1, C-DEMO-2 |
| S2-5 | Public feedback window (≥1 week) announced on Discussions | pm | C-REL-2 |
| S2-6 | Mark RFC-001 as `Stable` in `INDEX.md` and the document header | tech-writer | C-SPEC-1 |
| S2-7 | `DEPRECATION-POLICY.md` updated with strict SemVer post-1.0 | tech-writer | C-DOC-3 |
| S2-8 | `v1.0.0` tag + consolidated release notes + final publication | dev + pm | C-REL-3 |
| S2-9 | Public announcement (README `1.0` badge, Discussions, blog post if applicable) | pm | C-REL-4, C-DOC-6 |

---

## 4. Post-1.0 Change Rules

From `1.0.0` onward **strict SemVer** applies, per [DEPRECATION-POLICY.md](DEPRECATION-POLICY.md):

- **MAJOR (`2.0.0`)**: any incompatible change to a SDK's public API, the contracts ABI, or the DID Document format.
- **MINOR (`1.x.0`)**: backwards-compatible new functionality.
- **PATCH (`1.0.x`)**: backwards-compatible bugfix or documentation errata.
- **RFC errata**: handled through the C-SPEC-4 procedure without a major bump as long as it does not alter normative behavior.

---

## 5. Document State

This document is updated at the close of each Sprint. The *Criteria covered* column traces every task back to a checkbox in section 2.

**Next expected revision:** end of Sprint 0.
