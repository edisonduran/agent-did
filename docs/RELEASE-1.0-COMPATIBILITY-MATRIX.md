# Release 1.0 Compatibility Matrix

**Status:** Draft  
**Audience:** Contributors, Reviewers, Maintainers  
**Last updated:** 2026-05-08  
**Owner:** Maintainers (`edison.munoz` + team)  
**Governed by:** [Documentation-Governance.md](Documentation-Governance.md)

---

## 1. Scope

This document defines the initial package compatibility view for the **core `v1.0.0` Agent-DID release train after ADR-001**.

The compatibility story is intentionally limited to the co-versioned web-native core:

- `@agentdid/sdk`
- `agent-did-sdk`
- `@agentdid/langchain`
- `agent-did-langchain`
- `agent-did-crewai`
- `agent-did-semantic-kernel`
- `agent-did-microsoft-agent-framework`
- `agent-did-a2a`

EVM/on-chain/contracts material is **not** part of the core `v1.0.0` compatibility surface.

---

## 2. Compatibility Model

The release train uses three compatibility relationships:

- **Direct dependency (`D`)**: the package imports or builds against that SDK directly.
- **Contract interoperability (`I`)**: compatibility is defined through RFC-001 semantics, shared fixtures, and cross-SDK verification behavior rather than a direct package dependency.
- **Co-versioned only (`C`)**: packages ship under the same release train but do not directly couple at runtime.

---

## 3. Package x Package View

| Package | TS SDK | Python SDK | JS LangChain | Py LangChain | CrewAI | Semantic Kernel | Microsoft Agent Framework | A2A |
|---|---|---|---|---|---|---|---|---|
| `@agentdid/sdk` | self | I | D | I | I | I | I | I |
| `agent-did-sdk` | I | self | I | D | D | D | D | D |
| `@agentdid/langchain` | D | I | self | C | C | C | C | C |
| `agent-did-langchain` | I | D | C | self | C | C | C | C |
| `agent-did-crewai` | I | D | C | C | self | C | C | C |
| `agent-did-semantic-kernel` | I | D | C | C | C | self | C | C |
| `agent-did-microsoft-agent-framework` | I | D | C | C | C | C | self | C |
| `agent-did-a2a` | I | D | C | C | C | C | C | self |

---

## 4. Package Evidence

| Package | Runtime / registry | Expected 1.0 relationship | Primary evidence |
|---|---|---|---|
| `@agentdid/sdk` | npm / TypeScript | Canonical TS implementation of the core RFC surface | [sdk/public-api.snapshot.txt](../sdk/public-api.snapshot.txt), [sdk/tests/AgentIdentity.test.ts](../sdk/tests/AgentIdentity.test.ts), `.github/workflows/ci.yml` |
| `agent-did-sdk` | PyPI / Python | Canonical Python implementation of the core RFC surface | [sdk-python/public-api.snapshot.txt](../sdk-python/public-api.snapshot.txt), [sdk-python/tests/test_identity.py](../sdk-python/tests/test_identity.py), `.github/workflows/ci-python.yml` |
| `@agentdid/langchain` | npm / JS integration | Builds directly on `@agentdid/sdk` and shares RFC fixtures indirectly | [integrations/langchain/package.json](../integrations/langchain/package.json), [sdk/tests/InteropVectors.test.ts](../sdk/tests/InteropVectors.test.ts), `.github/workflows/ci-langchain-js.yml` |
| `agent-did-langchain` | PyPI / Python integration | Builds directly on `agent-did-sdk` and shares RFC fixtures indirectly | [integrations/langchain-python/pyproject.toml](../integrations/langchain-python/pyproject.toml), [sdk-python/tests/test_interop_vectors.py](../sdk-python/tests/test_interop_vectors.py), `.github/workflows/ci-langchain-python.yml` |
| `agent-did-crewai` | PyPI / Python integration | Builds directly on `agent-did-sdk` | [integrations/crewai/pyproject.toml](../integrations/crewai/pyproject.toml), `.github/workflows/ci-crewai.yml` |
| `agent-did-semantic-kernel` | PyPI / Python integration | Builds directly on `agent-did-sdk` | [integrations/semantic-kernel/pyproject.toml](../integrations/semantic-kernel/pyproject.toml), `.github/workflows/ci-semantic-kernel.yml` |
| `agent-did-microsoft-agent-framework` | PyPI / Python integration | Builds directly on `agent-did-sdk` | [integrations/microsoft-agent-framework/pyproject.toml](../integrations/microsoft-agent-framework/pyproject.toml), `.github/workflows/ci-microsoft-agent-framework.yml` |
| `agent-did-a2a` | PyPI / Python integration | Builds directly on `agent-did-sdk` | [integrations/a2a/pyproject.toml](../integrations/a2a/pyproject.toml), `.github/workflows/ci-a2a.yml` |

---

## 5. Unresolved Assumptions

The following assumptions remain explicit for the `1.0.0-rc.1` cut:

1. Cross-language compatibility is **contract-level**, not package-manager-level. The TS and Python SDKs interoperate through RFC-001 semantics and shared fixtures, not by direct package import.
2. The LangChain did:wba demo smoke remains a release-critical cross-package smoke for the current train, even though the core deployment story is now `did:webvh`. It validates multi-package packaging rather than the canonical deployment method.
3. Public-registry clean-install compatibility remains a Sprint 2 release-candidate gate and is not proven by this document alone.

---

## 6. Conclusion

The compatibility cut for core `v1.0.0` is:

- **one TS SDK**,
- **one Python SDK**,
- **six shipped integrations**,
- **shared RFC / fixture interoperability across SDKs**, and
- **single release-train co-versioning**.

Anything beyond that, especially EVM/on-chain/profile work, is outside the core `v1.0.0` compatibility promise.