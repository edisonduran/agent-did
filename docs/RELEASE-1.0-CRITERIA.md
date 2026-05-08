# Release 1.0.0 Criteria — Agent-DID

**Status:** Draft
**Audience:** Contributors, Reviewers, Maintainers
**Last updated:** 2026-05-08
**Owner:** Maintainers (`edison.munoz` + team)
**Governed by:** [Documentation-Governance.md](Documentation-Governance.md)

---

## 1. Scope of 1.0.0

This document defines the exit criteria for reaching version **1.0.0 of the Agent-DID core ecosystem after ADR-001**: the RFC, SDKs, and framework integrations that implement Agent-DID as an application pattern on top of `did:webvh`.

The old path assumed `did:agent` might need to become a new DID method. That is no longer the 1.0 gate. Standards collaboration with DIF/W3C remains valuable, but it is a post-1.0 or parallel adoption track, not approval required for a stable release.

**A user installing `agent-did 1.0` must obtain a coherent, mutually compatible web-native set:**

| Package | Current version | Target 1.0 | Registry |
|---|---|---|---|
| `@agentdid/sdk` (TypeScript) | 0.2.0 | 1.0.0 | npm |
| `agent-did-sdk` (Python) | 0.1.0 | 1.0.0 | PyPI |
| `@agentdid/langchain` (LangChain JS) | 0.1.0 | 1.0.0 | npm |
| `agent-did-langchain` (LangChain Python) | 0.1.0 | 1.0.0 | PyPI |
| `agent-did-crewai` | 0.1.0 | 1.0.0 | PyPI |
| `agent-did-semantic-kernel` | 0.1.0 | 1.0.0 | PyPI |
| `agent-did-microsoft-agent-framework` | 0.1.0 | 1.0.0 | PyPI |
| `agent-did-a2a` | 0.1.0 | 1.0.0 | PyPI |

The Solidity contracts and EVM deployment material are **out of scope for core `1.0.0`**. Existing contract work is retained as deferred research/profile material, but there is no EVM package, testnet, deployed-address, or ABI gate for the core web-native release. If a concrete need appears later, the maintainers will reopen the topic as a separate scope decision after `1.0.0`.

**RFC-001** must simultaneously transition from `Public Review v1` (Draft) to `Stable`.

## 1.1 Roadmap Alignment

This release plan is intended to be **consistent with the public roadmap in [README.md](../README.md)** and should be read as a **stabilization and release-maturation milestone**, not as completion of every open roadmap track.

The current post-ADR-001 intent is:

- **Covered by the 1.0 plan**: stabilization and co-versioned release of the already delivered tracks F1-01, F1-02, F1-03, F1-05, F1-06, F2-01, F2-02, F2-04, F2-05, and F2-09.
- **Pulled into core 1.0 by release criteria**: only work required to make the shipped `did:webvh` default reliable, documented, versioned, and installable across SDKs/integrations.
- **EVM explicitly excluded from core 1.0**: F2-06 public testnet deployment, contract deployment metadata, and EVM package/profile release work are deferred. They do not ship in the core `1.0.0` tag.
- **Explicitly out of scope for core 1.0 unless maintainers change scope**: F1-04 as a formal DIF submission, F2-03 production-resolver hardening beyond the shipped universal-resolver/source-adapter baseline, F2-07 formal whitepaper publication, F2-08 Azure AI Agent Service integration, and the full Phase 3 standardization/maturity track.
- **Already available and therefore not a blocker for 1.0**: the universal resolver baseline itself is shipped in both SDKs, including cache, registry lookup, HTTP/IPFS gateway fetching, JSON-RPC support, direct `did:wba` web resolution, and failover-oriented tests/smokes.

## 1.2 Release Path After ADR-001

The path to `1.0.0` is now:

1. **Freeze the core contract**: RFC-001 Stable, public SDK APIs frozen, DID document shape stable, A2A composition semantics stable.
2. **Harden the release surface**: CI gates, coverage targets, API snapshots, migration guides, compatibility matrix, clean install smokes.
3. **Publish a release candidate**: SDKs + integrations under `1.0.0-rc.1`, with a short feedback window. Because the project is still pre-adoption, this is a validation window, not a broad marketing launch.
4. **Tag core `v1.0.0`**: only after the core gates pass.
5. **Defer non-core tracks**: Azure integration, whitepaper, standards working-note outreach, certification service, and any future EVM/on-chain profile evaluation stay outside the core `1.0.0` release path.

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
- [ ] **C-INTEROP-4** — Compatibility matrix published (package × package, version × version) in `docs/`, currently tracked in [RELEASE-1.0-COMPATIBILITY-MATRIX.md](RELEASE-1.0-COMPATIBILITY-MATRIX.md).

### 2.4 Deferred EVM / On-Chain Profile

Core `1.0.0` excludes any EVM/on-chain profile. The Solidity contracts remain in the repository as deferred profile material only. There are no ABI-freeze, public testnet, deployed-address, audit-triage, or contract-upgrade gates for the core release.

If future user demand creates a concrete EVM/on-chain need, the project will evaluate it after `1.0.0` as a separate profile with its own scope, versioning, security review, and release gates.

### 2.5 Coverage and Quality

- [ ] **C-QA-1** — Coverage ≥**85%** lines in `sdk/` and `sdk-python/`.
- [ ] **C-QA-2** — Coverage **100%** in critical modules: `crypto`, `signing`, `verification`, `resolver`.
- [ ] **C-QA-3** — Coverage ≥**75%** per integration (LangChain JS/Py, CrewAI, SK, MS AF, A2A).
- [ ] **C-QA-4** — E2E tests for **anti-replay** (clock skew ±60s, nonce reuse, expired signature).
- [ ] **C-QA-5** — E2E tests for **key rotation** (≥3 cycles) + working historical verification.
- [ ] **C-QA-6** — E2E tests for **revocation** in the canonical `did:webvh` path and explicit compatibility paths included in the release.
- [ ] **C-QA-7** — **SSRF** tests covering loopback, link-local, AWS/GCP/Azure metadata, IPv6 mapped.
- [ ] **C-QA-8** — All 10 core release-critical GitHub Actions validation workflows green for **≥30 consecutive days** prior to tagging.
- [ ] **C-QA-9** — Clean-machine smoke install from npm/PyPI validated for the core RC packages.
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

- [ ] **C-REL-1** — All core packages bumped to `1.0.0-rc.1` simultaneously under a single monorepo tag.
- [ ] **C-REL-2** — Public feedback window of **≥1 week** on the RC, announced on GitHub Discussions.
- [ ] **C-REL-3** — `v1.0.0` tag only after every criterion above is met.
- [ ] **C-REL-4** — Release note and README status update coordinated with the tag. Broad public announcement is optional and should follow the visibility gates in `docs/Estrategia-Divulgacion-2-Semanas-Agent-DID.md`.

### 2.11 Roadmap Consistency

- [ ] **C-ROADMAP-1** — README roadmap statuses reconciled against current implementation evidence before `1.0.0-rc.1`.
- [ ] **C-ROADMAP-2** — Any roadmap item still open but not included in `1.0.0` is explicitly documented as post-1.0 scope.
- [ ] **C-ROADMAP-3** — Any roadmap item claimed as part of `1.0.0` has a linked implementation, CI, or release artifact proving readiness.

---

## 3. Work Plan (3 Sprints)

> Detailed and tracked as GitHub issues under the `v1.0.0` milestone. The executed issue map is archived in [_bmad-output/planning-artifacts/RELEASE-1.0-ISSUE-PACK.md](../_bmad-output/planning-artifacts/RELEASE-1.0-ISSUE-PACK.md).

### Sprint 0 — Scope Freeze and Release Foundation

Goal: align the post-ADR-001 release scope so Sprints 1 and 2 can execute without re-litigating standards approval, EVM centrality, or optional integrations. **Not blocked by any PR currently in review.**

| ID | Task | Suggested owner | Criteria covered |
|---|---|---|---|
| S0-1 | Publish this `RELEASE-1.0-CRITERIA.md` (✅ created) | tech-writer | C-DOC-* |
| S0-2 | Create root `CHANGELOG.md` + per-package CHANGELOG (✅ root created) | tech-writer | C-DOC-1 |
| S0-3 | Audit release-critical CI pipelines: green ≥30 days? File an issue per failure | qa | C-QA-8 |
| S0-4 | Inventory `TODO`/`FIXME`/`@deprecated`/`@internal` across SDKs and integrations | dev | C-API-3 |
| S0-5 | Initial public API snapshot artifacts and verification commands for TS and Python — baseline | architect + dev | C-API-1, C-API-2 |
| S0-6 | Explicit inventory of pending breaking changes that **must** land before 1.0 | architect | C-API-1 |
| S0-7 | Tentative compatibility matrix (package × package) | architect | C-INTEROP-4 |
| S0-8 | Confirm `fixtures/` is consumed by both TS and Python CI on every PR | qa | C-INTEROP-2 |
| S0-9 | Reconcile README roadmap with shipped evidence and classify open items as core `1.0`, optional profile, or post-`1.0` | pm + architect + tech-writer | C-ROADMAP-1, C-ROADMAP-2, C-ROADMAP-3 |
| S0-10 | Record the final scope decision: EVM/on-chain is excluded from core `1.0.0`; mark F2-06 as deferred future re-evaluation | maintainer + architect | C-ROADMAP-2 |

### Sprint 1 — Core Hardening

Goal: close every core quality, security and supply-chain gap for the `did:webvh` default path and shipped integrations.

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
| S1-9 | Final docs/security sweep to remove EVM/testnet assumptions from core release messaging | qa + tech-writer | C-ROADMAP-2, C-DOC-* |
| S1-10 | E2E anti-replay, key rotation, revocation, SSRF for core paths | qa | C-QA-4..7 |

### Sprint 2 — Release Candidate and Tag

Goal: publish RC, gather focused validation feedback, tag core 1.0.0.

| ID | Task | Suggested owner | Criteria covered |
|---|---|---|---|
| S2-1 | Bump the core packages to `1.0.0-rc.1` (single tag) | dev | C-REL-1 |
| S2-2 | Publish RC to npm/PyPI under dist-tag `next` / pre-release | dev | C-REL-1 |
| S2-3 | Clean smoke install of the core packages from public registries | qa | C-QA-9 |
| S2-4 | `agent-did-in-action` demo serving the RC | dev | C-DEMO-1, C-DEMO-2 |
| S2-5 | Focused RC feedback window (≥1 week) with GitHub Discussions as the canonical reference | pm | C-REL-2 |
| S2-6 | Mark RFC-001 as `Stable` in `INDEX.md` and the document header | tech-writer | C-SPEC-1 |
| S2-7 | `DEPRECATION-POLICY.md` updated with strict SemVer post-1.0 | tech-writer | C-DOC-3 |
| S2-8 | `v1.0.0` tag + consolidated release notes + final publication | dev + pm | C-REL-3 |
| S2-9 | README `1.0` badge/status update and release note; broader announcement only if visibility gates are met | pm | C-REL-4, C-DOC-6 |

---

## 4. Post-1.0 Change Rules

From `1.0.0` onward **strict SemVer** applies, per [DEPRECATION-POLICY.md](DEPRECATION-POLICY.md):

- **MAJOR (`2.0.0`)**: any incompatible change to a SDK's public API or the DID Document format.
- **MINOR (`1.x.0`)**: backwards-compatible new functionality.
- **PATCH (`1.0.x`)**: backwards-compatible bugfix or documentation errata.
- **RFC errata**: handled through the C-SPEC-4 procedure without a major bump as long as it does not alter normative behavior.

---

## 5. Document State

This document is updated at the close of each Sprint. The *Criteria covered* column traces every task back to a checkbox in section 2.

**Next expected revision:** after Sprint 0 issues #48, #51, #52, and #67-#71 are closed or explicitly deferred with maintainer approval.
