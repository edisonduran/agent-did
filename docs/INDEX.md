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

## Core Specification, Governance, and Operations

| Document | Audience | Status | Purpose |
|---|---|---|---|
| [INDEX.md](INDEX.md) | Users, Contributors, Reviewers | Stable | Entry point for navigating the docs set. |
| [Documentation-Governance.md](Documentation-Governance.md) | Contributors, Reviewers | Stable | Defines canonical sources of truth and live-document update rules. |
| [DEPRECATION-POLICY.md](DEPRECATION-POLICY.md) | Users, Contributors, Reviewers | Stable | Explains breaking-change and support expectations during Public Review. |
| [RFC-001-Agent-DID-Specification.md](RFC-001-Agent-DID-Specification.md) | Users, Contributors, Reviewers | Draft | Canonical Agent-DID specification under Public Review. |
| [RFC-001-EVM-Profile.md](RFC-001-EVM-Profile.md) | Contributors, Reviewers | Draft | Optional deployment profile for EVM anchoring, contract policy, and smart-account behavior on top of core RFC-001. |
| [RFC-001-A2A-Identity-Composition-Contract.md](RFC-001-A2A-Identity-Composition-Contract.md) | Contributors, Reviewers | Draft | Defines the A2A Agent Card and per-request signing composition contract co-drafted with APS. |
| [RFC-001-Compliance-Checklist.md](RFC-001-Compliance-Checklist.md) | Contributors, Reviewers | Stable | Tracks RFC conformance claims against implemented behavior. |
| [RFC-001-Implementation-Backlog.md](RFC-001-Implementation-Backlog.md) | Contributors, Reviewers | Stable | Execution history and remaining implementation work. |
| [RFC-001-Resolver-HA-Runbook.md](RFC-001-Resolver-HA-Runbook.md) | Contributors, Reviewers | Stable | Operational guidance for resolver high-availability drills. |
| [Anti-Replay-HTTP-Signatures.md](Anti-Replay-HTTP-Signatures.md) | Users, Contributors, Reviewers | Stable | Security guidance for nonce, expiry, and verifier-side replay protection. |
| [SDK-Release-Checklist.md](SDK-Release-Checklist.md) | Contributors | Stable | Release checklist for published SDK packages. |
| [PHILOSOPHY.md](PHILOSOPHY.md) | Users, Contributors, Reviewers | Stable | Design philosophy and scope boundaries for the project. |
| [F1-05-Contract-Audit-Triage.md](F1-05-Contract-Audit-Triage.md) | Contributors, Reviewers | Stable | Governs how automated contract audit findings are triaged. |

## LangChain Governance and Design

| Document | Audience | Status | Purpose |
|---|---|---|---|
| [F1-03-LangChain-Integration-Parity-Review-Checklist.md](F1-03-LangChain-Integration-Parity-Review-Checklist.md) | Contributors, Reviewers | Stable | Review checklist for TS/Python LangChain parity and governance. |
| [F1-03-LangChain-TS-Python-Integration-Parity-Matrix.md](F1-03-LangChain-TS-Python-Integration-Parity-Matrix.md) | Contributors, Reviewers | Stable | Matrix of feature parity across LangChain TS and Python integrations. |
| [F1-03-LangChain-Python-Implementation-Checklist.md](F1-03-LangChain-Python-Implementation-Checklist.md) | Contributors, Reviewers | Stable | Checklist for delivered LangChain Python implementation scope. |
| [F1-03-LangChain-Python-Integration-Design.md](F1-03-LangChain-Python-Integration-Design.md) | Contributors, Reviewers | Draft | Integration design rationale for LangChain Python. |
| [F1-03-LangChain-Python-Technical-Plan.md](F1-03-LangChain-Python-Technical-Plan.md) | Contributors, Reviewers | Draft | Technical planning notes for LangChain Python work. |
| [F1-03-LangChain-didwba-Demo-Walkthrough.md](F1-03-LangChain-didwba-Demo-Walkthrough.md) | Users, Contributors | Draft | Walkthrough of the `did:wba` LangChain demonstration. |

## Python SDK Parity and Core SDK Planning

| Document | Audience | Status | Purpose |
|---|---|---|---|
| [F2-01-Python-SDK-Blueprint.md](F2-01-Python-SDK-Blueprint.md) | Contributors, Reviewers | Draft | Blueprint and design notes for the Python SDK. |
| [F2-01-TS-Python-Parity-Matrix.md](F2-01-TS-Python-Parity-Matrix.md) | Contributors, Reviewers | Stable | Cross-SDK parity matrix between TypeScript and Python. |

## Semantic Kernel Governance

| Document | Audience | Status | Purpose |
|---|---|---|---|
| [F2-04-Semantic-Kernel-Implementation-Checklist.md](F2-04-Semantic-Kernel-Implementation-Checklist.md) | Contributors, Reviewers | Stable | Delivery checklist for the Semantic Kernel integration. |
| [F2-04-Semantic-Kernel-Integration-Design.md](F2-04-Semantic-Kernel-Integration-Design.md) | Contributors, Reviewers | Draft | Design notes for Semantic Kernel integration choices. |
| [F2-04-Semantic-Kernel-Integration-Review-Checklist.md](F2-04-Semantic-Kernel-Integration-Review-Checklist.md) | Contributors, Reviewers | Stable | Review checklist for shipped Semantic Kernel behavior. |
| [F2-04-Semantic-Kernel-Maturity-Gap-Assessment.md](F2-04-Semantic-Kernel-Maturity-Gap-Assessment.md) | Contributors, Reviewers | Stable | Gap assessment between current and target Semantic Kernel maturity. |
| [F2-04-Semantic-Kernel-Parity-Matrix.md](F2-04-Semantic-Kernel-Parity-Matrix.md) | Contributors, Reviewers | Stable | Matrix of integration coverage and parity expectations. |

## CrewAI Governance

| Document | Audience | Status | Purpose |
|---|---|---|---|
| [F2-05-CrewAI-Implementation-Checklist.md](F2-05-CrewAI-Implementation-Checklist.md) | Contributors, Reviewers | Stable | Delivery checklist for the CrewAI integration. |
| [F2-05-CrewAI-Integration-Design.md](F2-05-CrewAI-Integration-Design.md) | Contributors, Reviewers | Draft | Design notes for CrewAI integration decisions. |
| [F2-05-CrewAI-Integration-Review-Checklist.md](F2-05-CrewAI-Integration-Review-Checklist.md) | Contributors, Reviewers | Stable | Review checklist for CrewAI integration quality. |
| [F2-05-CrewAI-LangChain-Maturity-Rubric.md](F2-05-CrewAI-LangChain-Maturity-Rubric.md) | Contributors, Reviewers | Stable | Comparative rubric for CrewAI and LangChain maturity. |
| [F2-05-CrewAI-Maturity-Gap-Assessment.md](F2-05-CrewAI-Maturity-Gap-Assessment.md) | Contributors, Reviewers | Stable | Current gap assessment for CrewAI integration maturity. |

## Microsoft Agent Framework Governance

| Document | Audience | Status | Purpose |
|---|---|---|---|
| [F2-09-Microsoft-Agent-Framework-Implementation-Checklist.md](F2-09-Microsoft-Agent-Framework-Implementation-Checklist.md) | Contributors, Reviewers | Stable | Delivery checklist for the Microsoft Agent Framework integration. |
| [F2-09-Microsoft-Agent-Framework-Integration-Design.md](F2-09-Microsoft-Agent-Framework-Integration-Design.md) | Contributors, Reviewers | Draft | Design notes for Microsoft Agent Framework integration. |
| [F2-09-Microsoft-Agent-Framework-Integration-Review-Checklist.md](F2-09-Microsoft-Agent-Framework-Integration-Review-Checklist.md) | Contributors, Reviewers | Stable | Review checklist for Microsoft Agent Framework behavior. |
| [F2-09-Microsoft-Agent-Framework-Maturity-Gap-Assessment.md](F2-09-Microsoft-Agent-Framework-Maturity-Gap-Assessment.md) | Contributors, Reviewers | Stable | Gap assessment for Microsoft Agent Framework maturity. |
| [F2-09-Microsoft-Agent-Framework-Parity-Matrix.md](F2-09-Microsoft-Agent-Framework-Parity-Matrix.md) | Contributors, Reviewers | Stable | Matrix of feature coverage and parity expectations. |

## Training and Narrative Material

| Document | Audience | Status | Purpose |
|---|---|---|---|
| [Estrategia-Divulgacion-2-Semanas-Agent-DID.md](Estrategia-Divulgacion-2-Semanas-Agent-DID.md) | Contributors, Reviewers | Draft | Defines the minimum visibility, outreach gates, and trigger conditions for post-pivot project communication. |
| [Complete-Agent-DID-SDK-Course-EN.md](Complete-Agent-DID-SDK-Course-EN.md) | Users, Contributors | Draft | Long-form English training course for the SDK and RFC. |
| [Complete-Agent-DID-SDK-Course-ES.md](Complete-Agent-DID-SDK-Course-ES.md) | Users, Contributors | Draft | Long-form Spanish training course for the SDK and RFC. |
| [RFC-001-2h-Practical-Course.md](RFC-001-2h-Practical-Course.md) | Users, Contributors | Draft | Practical workshop-style learning material for RFC-001. |
| [RFC-001-Training-Manual.md](RFC-001-Training-Manual.md) | Users, Contributors | Draft | Training manual for onboarding and internal teaching. |
| [Strategic-Assessment-Agent-DID-EN.md](Strategic-Assessment-Agent-DID-EN.md) | Users, Contributors, Reviewers | Draft | English strategic framing of the project and its positioning. |
| [Strategic-Assessment-Agent-DID-ES.md](Strategic-Assessment-Agent-DID-ES.md) | Users, Contributors, Reviewers | Draft | Spanish strategic framing of the project and its positioning. |

## Historical Analysis and Critique

| Document | Audience | Status | Purpose |
|---|---|---|---|
| [Analisis-criticas/Project-Analysis-Report.md](Analisis-criticas/Project-Analysis-Report.md) | Contributors, Reviewers | Historical | Point-in-time analysis retained for background context. |
| [Analisis-criticas/agent-did-due-diligence-2026-03-29.md](Analisis-criticas/agent-did-due-diligence-2026-03-29.md) | Contributors, Reviewers | Historical | Dated due-diligence snapshot retained for review history. |

## Notes

- If a live document becomes obsolete and the team decides not to keep it current, it should be relabeled as historical in both the document and this index.
- For overall project status, start with the repository `README.md`.