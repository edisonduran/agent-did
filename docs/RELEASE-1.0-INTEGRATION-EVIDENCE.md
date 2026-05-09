# Release 1.0 Integration Evidence

**Status:** Draft  
**Audience:** Contributors, Reviewers, Maintainers  
**Last updated:** 2026-05-09  
**Owner:** Maintainers  
**Governed by:** [Documentation-Governance.md](Documentation-Governance.md)

---

## 1. Purpose

This document records the release evidence used to satisfy the Sprint 1 integration coverage/evidence closure for the shipped integrations in the core `v1.0.0` release train.

For thin framework adapters, release readiness is not measured by inventing arbitrary per-package line-coverage thresholds. Instead, each shipped integration must provide:

- a dedicated CI workflow
- a documented local validation command
- runtime smoke or operational recipe coverage when host runtime behavior matters
- packaging and quality gates appropriate to the integration surface

The hard numeric coverage gates remain anchored in the core SDK pipelines. Adapter packages are accepted based on executable scenario evidence that proves the contract adopters actually use.

---

## 2. In-Scope Packages

The shipped integration surface for the core `v1.0.0` train is:

- `integrations/langchain`
- `integrations/langchain-python`
- `integrations/crewai`
- `integrations/semantic-kernel`
- `integrations/microsoft-agent-framework`
- `integrations/a2a`

The root workspace now exposes convenience validation commands for all of them through `package.json`.

---

## 3. Evidence Matrix

| Integration | Dedicated CI workflow | Local validation command | Runtime / operational evidence | Notes |
|---|---|---|---|---|
| LangChain JS | `.github/workflows/ci-langchain-js.yml` | `npm run test:langchain` | [../integrations/langchain/README.md](../integrations/langchain/README.md), `tests/agentDidLangChain.test.js`, `tests/agentDidLangChain.didWbaDemo.test.js`, `tests/agentDidLangChain.observability.test.js` | Thin JS adapter; scenario and demo coverage is more meaningful than a synthetic line-only gate. |
| LangChain Python | `.github/workflows/ci-langchain-python.yml` | `npm run test:langchain-python` | [../integrations/langchain-python/README.md](../integrations/langchain-python/README.md), public-factory and observability recipes | Dedicated Python CI covers lint, mypy, pytest, runtime recipe checks, and build. |
| CrewAI | `.github/workflows/ci-crewai.yml` | `npm run test:crewai` and `npm run test:crewai-runtime` | [../integrations/crewai/tests/test_runtime_smoke.py](../integrations/crewai/tests/test_runtime_smoke.py), [../integrations/crewai/README.md](../integrations/crewai/README.md) | Runtime smoke requires the optional `.[runtime]` extra. |
| Semantic Kernel | `.github/workflows/ci-semantic-kernel.yml` | `npm run test:semantic-kernel` and `npm run test:semantic-kernel-runtime` | [../integrations/semantic-kernel/tests/test_runtime_smoke.py](../integrations/semantic-kernel/tests/test_runtime_smoke.py), [../integrations/semantic-kernel/README.md](../integrations/semantic-kernel/README.md) | Runtime evidence covers real plugin registration plus multistep identity lifecycle behavior. |
| Microsoft Agent Framework | `.github/workflows/ci-microsoft-agent-framework.yml` | `npm run test:microsoft-agent-framework` and `npm run test:microsoft-agent-framework-runtime` | [../integrations/microsoft-agent-framework/tests/test_runtime_smoke.py](../integrations/microsoft-agent-framework/tests/test_runtime_smoke.py), [../integrations/microsoft-agent-framework/README.md](../integrations/microsoft-agent-framework/README.md) | Runtime validation should prefer a clean virtualenv on Windows if the global Python environment is contaminated. |
| A2A | `.github/workflows/ci-a2a.yml` | `npm run test:a2a` | [../integrations/a2a/README.md](../integrations/a2a/README.md), full `pytest` suite | No separate runtime smoke is required; the shipped surface is the protocol adapter and JSON-RPC signing flow itself. |

---

## 4. Execution Notes

- CrewAI, Semantic Kernel, and Microsoft Agent Framework runtime smokes intentionally use optional runtime extras and may skip locally when those host packages are not installed. Their dedicated CI workflows install the required extras before executing them.
- Microsoft Agent Framework validation on Windows should prefer a clean virtual environment if the machine has stale global Python executables or conflicting editable installs.
- A2A does not need a separate runtime smoke because the adapter's release-critical behavior is already the request/response protocol surface covered in its main `pytest` suite.

---

## 5. Conclusion

Sprint 1 release evidence for shipped integrations is now explicit instead of implicit:

- each shipped integration has a dedicated CI workflow,
- each shipped integration has a documented local validation path,
- runtime-sensitive integrations have real-host smoke evidence, and
- the release train no longer depends on arbitrary adapter-only coverage percentages to prove readiness.