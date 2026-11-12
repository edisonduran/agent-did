# Documentation Index

This index is the fast path through the repository documentation.

## Status Legend

- **Stable**: maintained as live project guidance or source-of-truth governance.
- **Draft**: under active review, still evolving, or narrative material that may change without a formal deprecation window.
- **Historical**: retained for context; not a current source of truth.

## Audience Legend

- **Users**: adopters trying to understand or use Agent-DID.
- **Contributors**: people changing code, docs, integrations, or workflows.
- **Reviewers**: people evaluating the RFC, governance, architecture, or maturity claims.

## Interactive Demo

- [Agent-DID in Action](https://edisonduran.github.io/agent-did-in-action/) — external live browser demo gallery showing real signed handoffs, live tamper detection, and the published `@agentdid/sdk` across multiple scenarios.

## Releases

| Document | Audience | Status | Purpose |
|---|---|---|---|
| [../CHANGELOG.md](../CHANGELOG.md) | Users, Contributors, Reviewers | Stable | Root changelog for the co-versioned core ecosystem release train (RFC + SDKs + integrations). |
| [RFC-001-CHANGELOG.md](RFC-001-CHANGELOG.md) | Users, Contributors, Reviewers | Draft | Tracks normative/document-history changes specific to RFC-001, including the recorded v0.3 pivot to the `did:webvh` application-pattern model. |
| [RELEASE-1.0-CRITERIA.md](RELEASE-1.0-CRITERIA.md) | Contributors, Reviewers, Maintainers | Draft | Non-negotiable exit criteria and 3-sprint plan toward `v1.0.0`. |
| [RELEASE-1.0-COMPATIBILITY-MATRIX.md](RELEASE-1.0-COMPATIBILITY-MATRIX.md) | Contributors, Reviewers, Maintainers | Draft | Initial package compatibility view for the co-versioned core `v1.0.0` release train. |
| [RELEASE-1.0-INTEGRATION-EVIDENCE.md](RELEASE-1.0-INTEGRATION-EVIDENCE.md) | Contributors, Reviewers, Maintainers | Draft | Release evidence matrix for the shipped integrations, used in place of synthetic adapter-only coverage thresholds. |
| [../sdk/MIGRATION-0.x-to-1.0.md](../sdk/MIGRATION-0.x-to-1.0.md) | Users, Contributors | Draft | Migration guide for TypeScript SDK adopters moving from `0.x` assumptions to the core `1.0.0` web-native path. |
| [../sdk-python/MIGRATION-0.x-to-1.0.md](../sdk-python/MIGRATION-0.x-to-1.0.md) | Users, Contributors | Draft | Migration guide for Python SDK adopters moving from `0.x` assumptions to the core `1.0.0` web-native path. |
| [../sdk/MIGRATION-1.0-rc.2-to-rc.3.md](../sdk/MIGRATION-1.0-rc.2-to-rc.3.md) | Users, Contributors | Active | Breaking changes in the TypeScript SDK between `1.0.0-rc.2` and `1.0.0-rc.3`. |
| [../sdk-python/MIGRATION-1.0-rc.2-to-rc.3.md](../sdk-python/MIGRATION-1.0-rc.2-to-rc.3.md) | Users, Contributors | Active | Breaking changes in the Python SDK between `1.0.0rc2` and `1.0.0rc3`. |
| [../sdk/MIGRATION-1.0-rc.4-to-rc.5.md](../sdk/MIGRATION-1.0-rc.4-to-rc.5.md) | Users, Contributors | Active | Breaking changes in the TypeScript SDK between `1.0.0-rc.4` and `1.0.0-rc.5`: HTTP hardening, typed verifier result, controller binding, payload signature prefix, removals. |
| [../sdk-python/MIGRATION-1.0-rc.4-to-rc.5.md](../sdk-python/MIGRATION-1.0-rc.4-to-rc.5.md) | Users, Contributors | Active | Breaking changes in the Python SDK between `1.0.0rc4` and `1.0.0rc5`: the same set as the TypeScript guide. |
| [../sdk/MIGRATION-1.0-rc.3-to-rc.4.md](../sdk/MIGRATION-1.0-rc.3-to-rc.4.md) | Users, Contributors | Active | Breaking changes in the TypeScript SDK between `1.0.0-rc.3` and `1.0.0-rc.4` (API only; no wire changes). |
| [../sdk-python/MIGRATION-1.0-rc.3-to-rc.4.md](../sdk-python/MIGRATION-1.0-rc.3-to-rc.4.md) | Users, Contributors | Active | Breaking changes in the Python SDK between `1.0.0rc3` and `1.0.0rc4` (API only; no wire changes). |

## Core Specification, Governance, and Operations

| Document | Audience | Status | Purpose |
|---|---|---|---|
| [INDEX.md](INDEX.md) | Users, Contributors, Reviewers | Stable | Entry point for navigating the docs set. |
| [Documentation-Governance.md](Documentation-Governance.md) | Contributors, Reviewers | Stable | Defines canonical sources of truth and live-document update rules. |
| [../GOVERNANCE.md](../GOVERNANCE.md) | Users, Contributors, Reviewers | Stable | Who decides, who can merge and release, how normative changes are made and how to become a maintainer. Describes the single-maintainer reality and the two-maintainer goal. |
| [DEPRECATION-POLICY.md](DEPRECATION-POLICY.md) | Users, Contributors, Reviewers | Stable | Explains RC freeze, post-`1.0` SemVer, and compatibility expectations for the published packages. |
| [RFC-001-Agent-DID-Specification.md](RFC-001-Agent-DID-Specification.md) | Users, Contributors, Reviewers | Stable | Canonical Agent-DID specification, version `1.0-rc.5`: the `1.0` release contract, with pinned normative references and lifecycle authorization. |
| [ADR-002-did-webvh-v1.0-Implementation.md](ADR-002-did-webvh-v1.0-Implementation.md) | Contributors, Reviewers | Accepted | Decision record for implementing `did:webvh` v1.0 (M-02): evaluation of the DIF reference implementations, prototype results, and the proposed adapter-based adoption. |
| [ADR-003-JSON-LD-Context-and-agentMetadata.md](ADR-003-JSON-LD-Context-and-agentMetadata.md) | Contributors, Reviewers | Accepted | Decision record for the `https://agent-did.org/v1` JSON-LD context (published as `contexts/v1.jsonld`, pinned by hash) and for keeping `agentMetadata` in the DID document (M-19). |
| [ADR-004-EVM-Profile-Satellite.md](ADR-004-EVM-Profile-Satellite.md) | Contributors, Reviewers | Accepted | Decision record for moving the deferred EVM profile (contracts, `@agentdid/evm`, `agent_did_sdk.evm`) to `edisonduran/agent-did-evm` with its history, and replacing the Hardhat smokes with `did:webvh` smokes. |
| [RFC-001-EVM-Profile.md](RFC-001-EVM-Profile.md) | Contributors, Reviewers | Moved | Pointer: the optional EVM profile now lives in `edisonduran/agent-did-evm`. Was: optional deployment profile for EVM anchoring, contract policy, and smart-account behavior on top of core RFC-001. |
| [RFC-001-A2A-Identity-Composition-Contract.md](RFC-001-A2A-Identity-Composition-Contract.md) | Contributors, Reviewers | Draft | Defines the A2A Agent Card and per-request signing composition contract co-drafted with APS. |
| [RFC-001-Compliance-Checklist.md](RFC-001-Compliance-Checklist.md) | Contributors, Reviewers | Stable | Tracks RFC conformance claims against implemented behavior. |
| [External-Conformance-Matrix.md](External-Conformance-Matrix.md) | Users, Contributors, Reviewers | Stable | Conformance with external specifications (did:webvh, RFC 9421, RFC 8785, RFC 9530, RFC 8941, DID Core), each row linked to the CI job that proves it. |
| [RFC-001-Implementation-Backlog.md](RFC-001-Implementation-Backlog.md) | Contributors, Reviewers | Stable | Execution history and remaining implementation work. |
| [RFC-001-Resolver-HA-Runbook.md](RFC-001-Resolver-HA-Runbook.md) | Contributors, Reviewers | Stable | Operational guidance for resolver high-availability drills. |
| [Anti-Replay-HTTP-Signatures.md](Anti-Replay-HTTP-Signatures.md) | Users, Contributors, Reviewers | Stable | Security guidance for nonce, expiry, and verifier-side replay protection. |
| [Threat-Model.md](Threat-Model.md) | Users, Contributors, Reviewers | Draft | STRIDE threat model of creation, log publication, resolution, HTTP signing, A2A handoff and revocation, with residual risks. |
| [S1-3-Adversarial-Review-Crypto-Signing.md](S1-3-Adversarial-Review-Crypto-Signing.md) | Contributors, Reviewers | Historical | Sprint 1 adversarial review of the signing surfaces (2026-05-08), with a post-rc.3 addendum. |
| [SDK-Release-Checklist.md](SDK-Release-Checklist.md) | Contributors | Stable | Release checklist for published SDK packages. |
| [PHILOSOPHY.md](PHILOSOPHY.md) | Users, Contributors, Reviewers | Stable | Design philosophy and scope boundaries for the project. |

## LangChain Governance and Design

| Document | Audience | Status | Purpose |
|---|---|---|---|
| [F1-03-LangChain-Integration-Parity-Review-Checklist.md](F1-03-LangChain-Integration-Parity-Review-Checklist.md) | Contributors, Reviewers | Stable | Review checklist for TS/Python LangChain parity and governance. |
| [F1-03-LangChain-TS-Python-Integration-Parity-Matrix.md](F1-03-LangChain-TS-Python-Integration-Parity-Matrix.md) | Contributors, Reviewers | Stable | Matrix of feature parity across LangChain TS and Python integrations. |
| [F1-03-LangChain-Python-Implementation-Checklist.md](F1-03-LangChain-Python-Implementation-Checklist.md) | Contributors, Reviewers | Stable | Checklist for delivered LangChain Python implementation scope. |
| [F1-03-LangChain-didwba-Demo-Walkthrough.md](F1-03-LangChain-didwba-Demo-Walkthrough.md) | Users, Contributors | Draft | Walkthrough of the `did:wba` LangChain demonstration. |

## Python SDK Parity and Core SDK Planning

| Document | Audience | Status | Purpose |
|---|---|---|---|
| [F2-01-TS-Python-Parity-Matrix.md](F2-01-TS-Python-Parity-Matrix.md) | Contributors, Reviewers | Stable | Cross-SDK parity matrix between TypeScript and Python. |

## Semantic Kernel Governance

| Document | Audience | Status | Purpose |
|---|---|---|---|
| [F2-04-Semantic-Kernel-Implementation-Checklist.md](F2-04-Semantic-Kernel-Implementation-Checklist.md) | Contributors, Reviewers | Stable | Delivery checklist for the Semantic Kernel integration. |
| [F2-04-Semantic-Kernel-Integration-Review-Checklist.md](F2-04-Semantic-Kernel-Integration-Review-Checklist.md) | Contributors, Reviewers | Stable | Review checklist for shipped Semantic Kernel behavior. |
| [F2-04-Semantic-Kernel-Parity-Matrix.md](F2-04-Semantic-Kernel-Parity-Matrix.md) | Contributors, Reviewers | Stable | Matrix of integration coverage and parity expectations. |

## CrewAI Governance

| Document | Audience | Status | Purpose |
|---|---|---|---|
| [F2-05-CrewAI-Implementation-Checklist.md](F2-05-CrewAI-Implementation-Checklist.md) | Contributors, Reviewers | Stable | Delivery checklist for the CrewAI integration. |
| [F2-05-CrewAI-Integration-Review-Checklist.md](F2-05-CrewAI-Integration-Review-Checklist.md) | Contributors, Reviewers | Stable | Review checklist for CrewAI integration quality. |

## Microsoft Agent Framework Governance

| Document | Audience | Status | Purpose |
|---|---|---|---|
| [F2-09-Microsoft-Agent-Framework-Implementation-Checklist.md](F2-09-Microsoft-Agent-Framework-Implementation-Checklist.md) | Contributors, Reviewers | Stable | Delivery checklist for the Microsoft Agent Framework integration. |
| [F2-09-Microsoft-Agent-Framework-Integration-Review-Checklist.md](F2-09-Microsoft-Agent-Framework-Integration-Review-Checklist.md) | Contributors, Reviewers | Stable | Review checklist for Microsoft Agent Framework behavior. |
| [F2-09-Microsoft-Agent-Framework-Parity-Matrix.md](F2-09-Microsoft-Agent-Framework-Parity-Matrix.md) | Contributors, Reviewers | Stable | Matrix of feature coverage and parity expectations. |

## Notes

- If a live document becomes obsolete and the team decides not to keep it current, it should be relabeled as historical in both the document and this index.
- For overall project status, start with the repository `README.md`.

## Archive (historical)

Moved out of the live set by M-21. Nothing here is a source of truth; each file carries a banner with its scope. See [archive/README.md](archive/README.md).

| Document | Audience | Status | Purpose |
|---|---|---|---|
| [Estrategia-Divulgacion-2-Semanas-Agent-DID.md](archive/Estrategia-Divulgacion-2-Semanas-Agent-DID.md) | Contributors, Reviewers | Historical | Defines the minimum visibility, outreach gates, and trigger conditions for post-pivot project communication. |
| [F1-03-LangChain-Python-Integration-Design.md](archive/F1-03-LangChain-Python-Integration-Design.md) | Contributors, Reviewers | Historical | Integration design rationale for LangChain Python. |
| [F1-03-LangChain-Python-Technical-Plan.md](archive/F1-03-LangChain-Python-Technical-Plan.md) | Contributors, Reviewers | Historical | Technical planning notes for LangChain Python work. |
| [F2-01-Python-SDK-Blueprint.md](archive/F2-01-Python-SDK-Blueprint.md) | Contributors, Reviewers | Historical | Blueprint and design notes for the Python SDK. |
| [F2-04-Semantic-Kernel-Integration-Design.md](archive/F2-04-Semantic-Kernel-Integration-Design.md) | Contributors, Reviewers | Historical | Design notes for Semantic Kernel integration choices. |
| [F2-04-Semantic-Kernel-Maturity-Gap-Assessment.md](archive/F2-04-Semantic-Kernel-Maturity-Gap-Assessment.md) | Contributors, Reviewers | Historical | Gap assessment between current and target Semantic Kernel maturity. |
| [F2-05-CrewAI-Integration-Design.md](archive/F2-05-CrewAI-Integration-Design.md) | Contributors, Reviewers | Historical | Design notes for CrewAI integration decisions. |
| [F2-05-CrewAI-LangChain-Maturity-Rubric.md](archive/F2-05-CrewAI-LangChain-Maturity-Rubric.md) | Contributors, Reviewers | Historical | Comparative rubric for CrewAI and LangChain maturity. |
| [F2-05-CrewAI-Maturity-Gap-Assessment.md](archive/F2-05-CrewAI-Maturity-Gap-Assessment.md) | Contributors, Reviewers | Historical | Current gap assessment for CrewAI integration maturity. |
| [F2-09-Microsoft-Agent-Framework-Integration-Design.md](archive/F2-09-Microsoft-Agent-Framework-Integration-Design.md) | Contributors, Reviewers | Historical | Design notes for Microsoft Agent Framework integration. |
| [F2-09-Microsoft-Agent-Framework-Maturity-Gap-Assessment.md](archive/F2-09-Microsoft-Agent-Framework-Maturity-Gap-Assessment.md) | Contributors, Reviewers | Historical | Gap assessment for Microsoft Agent Framework maturity. |
| [Project-Analysis-Report.md](archive/Project-Analysis-Report.md) | Contributors, Reviewers | Historical | Point-in-time analysis retained for background context. |
| [Strategic-Assessment-Agent-DID-EN.md](archive/Strategic-Assessment-Agent-DID-EN.md) | Users, Contributors, Reviewers | Historical | English strategic framing of the project and its positioning. |
| [Strategic-Assessment-Agent-DID-ES.md](archive/Strategic-Assessment-Agent-DID-ES.md) | Users, Contributors, Reviewers | Historical | Spanish strategic framing of the project and its positioning. |
| [agent-did-due-diligence-2026-03-29.md](archive/agent-did-due-diligence-2026-03-29.md) | Contributors, Reviewers | Historical | Dated due-diligence snapshot retained for review history. |
| [Seguridad-de-Agentes-de-IA-Firma-Digital.md](archive/Seguridad-de-Agentes-de-IA-Firma-Digital.md) | Contributors, Reviewers | Historical | Early research report on AI-agent digital signatures (Spanish), formerly at the repository root. |
| [Complete-Agent-DID-SDK-Course-EN.md](archive/Complete-Agent-DID-SDK-Course-EN.md) | Users, Contributors | Historical | Long-form English training course for the SDK and RFC. |
| [Complete-Agent-DID-SDK-Course-ES.md](archive/Complete-Agent-DID-SDK-Course-ES.md) | Users, Contributors | Historical | Long-form Spanish training course for the SDK and RFC. |
| [RFC-001-2h-Practical-Course.md](archive/RFC-001-2h-Practical-Course.md) | Users, Contributors | Historical | Practical workshop-style learning material for RFC-001. |
| [RFC-001-Training-Manual.md](archive/RFC-001-Training-Manual.md) | Users, Contributors | Historical | Training manual for onboarding and internal teaching. |
