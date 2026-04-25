# SDK Release Checklist

## Objective

Provide a single repository-level release checklist for the TypeScript SDK in `sdk/`, the Python SDK in `sdk-python/`, the official LangChain integration packages, and integration scaffolds governed with explicit review artifacts.

Documentation status and canonical-source rules are defined in `docs/Documentation-Governance.md`.

This checklist is intended for:

1. Release preparation.
2. PR review of SDK-affecting changes.
3. Regression prevention when RFC-001 behavior changes.

---

## When to Use This Checklist

Use this checklist whenever a change affects one or more of the following:

- `sdk/**`
- `sdk-python/**`
- `integrations/langchain/**`
- `integrations/langchain-python/**`
- `integrations/crewai/**`
- `integrations/semantic-kernel/**`
- `fixtures/**`
- shared RFC-001 lifecycle semantics
- canonical `documentRef` generation
- cross-language interoperability vectors

---

## Global Release Checks

Mark each item before cutting or approving an SDK-affecting release.

- [ ] The change scope is identified: `sdk`, `sdk-python`, or both.
- [ ] The parity matrix in `docs/F2-01-TS-Python-Parity-Matrix.md` is still accurate.
- [ ] If LangChain integrations are affected, the parity matrix in `docs/F1-03-LangChain-TS-Python-Integration-Parity-Matrix.md` is still accurate.
- [ ] If LangChain integrations are affected, the recurring review in `docs/F1-03-LangChain-Integration-Parity-Review-Checklist.md` was completed.
- [ ] If the CrewAI integration is affected, `docs/F2-05-CrewAI-Implementation-Checklist.md` and `docs/F2-05-CrewAI-Integration-Review-Checklist.md` were reviewed.
- [ ] If the Semantic Kernel integration is affected, `docs/F2-04-Semantic-Kernel-Implementation-Checklist.md` and `docs/F2-04-Semantic-Kernel-Integration-Review-Checklist.md` were reviewed.
- [ ] If the Microsoft Agent Framework integration is affected, `docs/F2-09-Microsoft-Agent-Framework-Implementation-Checklist.md` and `docs/F2-09-Microsoft-Agent-Framework-Integration-Review-Checklist.md` were reviewed.
- [ ] Shared fixtures in `fixtures/` still represent the intended cross-language contract.
- [ ] Documentation does not describe existing Python SDK capabilities as future work.
- [ ] CHANGELOG or release notes are prepared if the release is user-visible.

---

## TypeScript SDK Checks

Run from the repository root unless noted otherwise.

- [ ] `npm --prefix sdk test`
- [ ] `npm --prefix sdk run build`
- [ ] If TypeScript public API changed, `sdk/README.md` is updated.
- [ ] If the change affects shared behavior, parity impact on Python was reviewed.
- [ ] `sdk/package.json` versioning and publish metadata are correct for the release.

---

## Python SDK Checks

Canonical local workflow:

```bash
cd sdk-python
python -m pip install -e ".[dev]"
python -m ruff check src/ tests/ scripts/
python -m mypy --strict src/
python -m pytest tests/ -q
python scripts/conformance_rfc001.py
python -m build
python -m twine check dist/*
```

GitHub release automation for the package is defined in `.github/workflows/publish-python-sdk.yml`.
Use `workflow_dispatch` with `repository=testpypi` for rehearsal, and publish to PyPI from tag `sdk-python-vX.Y.Z` or manual dispatch from `main` with `repository=pypi`.

Checklist:

- [ ] `python -m ruff check src/ tests/ scripts/`
- [ ] `python -m mypy --strict src/`
- [ ] `python -m pytest tests/ -q`
- [ ] `python scripts/conformance_rfc001.py`
- [ ] `python -m build`
- [ ] `python -m twine check dist/*`
- [ ] If Python public API changed, `sdk-python/README.md` is updated.
- [ ] `sdk-python/pyproject.toml` metadata and version are correct for the release.
- [ ] PyPI Trusted Publishing is configured for `.github/workflows/publish-python-sdk.yml` in PyPI and, if used, TestPyPI.

---

## LangChain Integration Checks

### LangChain JS

Canonical local workflow:

```bash
npm --prefix sdk run build
npm --prefix integrations/langchain test
```

- [ ] `npm --prefix sdk run build`
- [ ] `npm --prefix integrations/langchain test`
- [ ] If JS integration public API changed, `integrations/langchain/README.md` is updated.
- [ ] If JS integration behavior changed, `docs/F1-03-LangChain-TS-Python-Integration-Parity-Matrix.md` was reviewed.
- [ ] If JS integration observability changed, `docs/F1-03-LangChain-Integration-Parity-Review-Checklist.md` was reviewed.
- [ ] If JS integration behavior changed, parity impact on `integrations/langchain-python/` was reviewed.
- [ ] JS examples still reflect the shipped surface:
	`agentDidLangChain.example.js`, `agentDidLangChain.observability.example.js`, `agentDidLangChain.langsmith.example.js`, and `agentDidLangChain.productionRecipe.example.js`.
- [ ] JS observability still emits sanitized events and keeps sensitive payloads, signatures, bodies, and headers redacted.
- [ ] JS LangSmith adapter still creates sanitized local child runs for tool lifecycle and generic identity events.
- [ ] `integrations/langchain/package.json` compatibility targets and publish metadata are correct.

### LangChain Python

Canonical local workflow:

```bash
cd sdk-python
python -m pip install -e ".[dev]"
cd ../integrations/langchain-python
python -m pip install -e ".[dev]"
python -m ruff check src/ tests/ examples/
python -m mypy src/
python -m pytest tests/ -q
python -m build
```

Checklist:

- [ ] `python -m ruff check src/ tests/ examples/`
- [ ] `python -m mypy src/`
- [ ] `python -m pytest tests/ -q`
- [ ] `python -m build`
- [ ] If Python integration public API changed, `integrations/langchain-python/README.md` is updated.
- [ ] If Python integration behavior changed, `docs/F1-03-LangChain-TS-Python-Integration-Parity-Matrix.md` was reviewed.
- [ ] If Python integration observability changed, `docs/F1-03-LangChain-Integration-Parity-Review-Checklist.md` was reviewed.
- [ ] If Python integration behavior changed, parity impact on `integrations/langchain/` was reviewed.
- [ ] Python examples still reflect the shipped surface, including observability and production-recipe flows.
- [ ] Python observability still emits sanitized events and keeps sensitive payloads, signatures, bodies, and headers redacted.
- [ ] Python LangSmith adapter still projects sanitized events into dedicated child runs.
- [ ] `integrations/langchain-python/pyproject.toml` metadata and version are correct for the release.

---

## Cross-Integration Parity Checks

- [ ] README for `integrations/langchain/` and `integrations/langchain-python/` still describe the same conceptual model.
- [ ] TS and Python retain aligned secure defaults for sensitive tools such as HTTP signing, payload signing, and key rotation.
- [ ] TS and Python retain equivalent HTTP target validation semantics for protocol, loopback/private targets, and embedded credentials.
- [ ] TS and Python retain equivalent observability event taxonomy for identity snapshot refresh, tool start, tool success, and tool failure.
- [ ] TS and Python examples still cover the same minimum journey: base example, observability example, and production-style recipe.
- [ ] TS and Python LangSmith adapters still exist as explicit, documented optional surfaces when shipped.
- [ ] Any intentional TS↔Python integration gap is explicitly documented in `docs/F1-03-LangChain-TS-Python-Integration-Parity-Matrix.md`.

---

## CrewAI Integration Checks

- [ ] `integrations/crewai/README.md` still describes the package as a functional integration and does not over-claim host-runtime coverage beyond the shipped `Agent`/`Task`/`Crew` helper surface.
- [ ] CrewAI docs do not describe the Python SDK as future work.
- [ ] `docs/F2-05-CrewAI-Implementation-Checklist.md` still reflects the shipped completion state or the next concrete delta.
- [ ] `docs/F2-05-CrewAI-Integration-Review-Checklist.md` still reflects the current security and documentation review surface.
- [ ] `integrations/crewai/src/agent_did_crewai/__init__.py` still exposes the expected factory and package status constant.

---

## Semantic Kernel Integration Checks

- [ ] `integrations/semantic-kernel/README.md` still describes the package as a shipped Python integration with optional `.[runtime]` validation.
- [ ] Semantic Kernel docs do not describe the Python SDK as future work.
- [ ] `docs/F2-04-Semantic-Kernel-Implementation-Checklist.md` still reflects the shipped completion state or the next concrete delta.
- [ ] `docs/F2-04-Semantic-Kernel-Integration-Review-Checklist.md` still reflects the current runtime, security and documentation review surface.
- [ ] `integrations/semantic-kernel/src/agent_did_semantic_kernel/__init__.py` still exposes the expected factory and package status constant.

---

## Microsoft Agent Framework Integration Checks

- [ ] `integrations/microsoft-agent-framework/README.md` still describes the package as a shipped Python integration with advanced workflow validation.
- [ ] Microsoft Agent Framework docs do not describe the integration as future work for the governed F2-09 scope.
- [ ] `docs/F2-09-Microsoft-Agent-Framework-Implementation-Checklist.md` still reflects the shipped completion state or the next concrete delta.
- [ ] `docs/F2-09-Microsoft-Agent-Framework-Integration-Review-Checklist.md` still reflects the current runtime, security and documentation review surface.
- [ ] `integrations/microsoft-agent-framework/src/agent_did_microsoft_agent_framework/__init__.py` still exposes the expected factory and package status constant.

---

## Cross-SDK Interoperability Checks

- [ ] TypeScript shared-fixture tests pass.
- [ ] Python shared-fixture tests pass.
- [ ] Equivalent DID documents still yield the same canonical `documentRef` in both SDKs.
- [ ] Timestamp serialization still converges to canonical UTC millisecond output.
- [ ] Any RFC-001 lifecycle change was reviewed for both `camelCase` and `snake_case` APIs.

---

## CI Checks

- [ ] `.github/workflows/ci.yml` remains green for relevant TypeScript changes.
- [ ] `.github/workflows/ci-python.yml` remains green for relevant Python changes.
- [ ] `.github/workflows/ci-langchain-python.yml` remains green for relevant LangChain Python changes.
- [ ] `.github/workflows/ci-langchain-didwba-smoke.yml` remains green when `did:wba` demos, SDKs or LangChain integrations change.
- [ ] `.github/workflows/ci-integration-governance.yml` remains green when integration packages or their governance docs change.
- [ ] If fixtures changed, both workflows were considered part of the validation surface.

---

## Recommended Root Shortcuts

These monorepo shortcuts are optional helpers, not replacements for stack-native workflows:

```bash
npm run python:install-dev
npm run python:test
npm run python:conformance
npm run test:langchain
npm run smoke:langchain-didwba
npm run langchain-python:install-dev
npm run lint:langchain-python
npm run typecheck:langchain-python
npm run test:langchain-python
npm run conformance:rfc001
```

---

## Release Decision Rule

An SDK-affecting change is ready for release when:

1. All relevant stack-specific checks pass.
2. Cross-SDK interoperability checks pass if behavior is shared.
3. Documentation is aligned with the shipped behavior.
4. The parity matrix remains correct after the change.

---

## Related Documents

- `docs/F2-01-TS-Python-Parity-Matrix.md`
- `docs/F1-03-LangChain-TS-Python-Integration-Parity-Matrix.md`
- `docs/F1-03-LangChain-Integration-Parity-Review-Checklist.md`
- `docs/F2-04-Semantic-Kernel-Implementation-Checklist.md`
- `docs/F2-04-Semantic-Kernel-Integration-Review-Checklist.md`
- `docs/F2-05-CrewAI-Implementation-Checklist.md`
- `docs/F2-05-CrewAI-Integration-Review-Checklist.md`
- `docs/RFC-001-Implementation-Backlog.md`
- `README.md`
- `sdk-python/README.md`