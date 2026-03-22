# F1-03 - LangChain Integration Parity Review Checklist

## Objective

Convert parity verification between `integrations/langchain/` and `integrations/langchain-python/` into a repeatable review artifact for release preparation and PR review.

Use this checklist whenever a change touches either LangChain integration, its observability surface, examples, tests or README.

---

## When to Run It

Run this checklist when a change affects one or more of the following:

- `integrations/langchain/**`
- `integrations/langchain-python/**`
- `docs/F1-03-LangChain-TS-Python-Integration-Parity-Matrix.md`
- LangChain observability, secure tool exposure, examples or release metadata

---

## Public Surface

- [ ] Both packages still expose their main factory (`createAgentDidIntegration(...)` / `create_agent_did_langchain_integration(...)`).
- [ ] Identity snapshot helpers remain conceptually aligned.
- [ ] Sensitive tools remain opt-in in both packages.
- [ ] Dedicated LangSmith adapter helpers remain available and documented in both packages.

---

## Security

- [ ] HTTP signing remains opt-in in both packages.
- [ ] Payload signing remains opt-in in both packages.
- [ ] Key rotation remains opt-in in both packages.
- [ ] HTTP target validation still rejects invalid schemes, embedded credentials and private or loopback targets by default.

---

## Observability

- [ ] Both packages still emit the same minimum event taxonomy:
  - `agent_did.identity_snapshot.refreshed`
  - `agent_did.tool.started`
  - `agent_did.tool.succeeded`
  - `agent_did.tool.failed`
- [ ] JSON logging remains sanitized in both packages.
- [ ] LangSmith adapters still create sanitized child runs for tool lifecycle and generic events.
- [ ] Fan-out composition still works with callback + JSON logging + LangSmith.

---

## Documentation And Examples

- [ ] `integrations/langchain/README.md` and `integrations/langchain-python/README.md` still describe the same conceptual model.
- [ ] Both packages still ship, at minimum, base, observability and production-style examples.
- [ ] If both packages ship LangSmith adapters, both READMEs still document them as optional observability surfaces.
- [ ] The parity matrix in `docs/F1-03-LangChain-TS-Python-Integration-Parity-Matrix.md` still reflects reality.

---

## Validation Commands

### TypeScript

- [ ] `npm --prefix integrations/langchain test`

### Python

- [ ] `python -m ruff check integrations/langchain-python/src integrations/langchain-python/tests integrations/langchain-python/examples`
- [ ] `python -m mypy integrations/langchain-python/src`
- [ ] `python -m pytest integrations/langchain-python/tests -q`

---

## Decision Rule

Parity verification is complete when:

1. The checklist above is fully reviewed.
2. The parity matrix stays accurate.
3. Any intentional divergence is explicit in docs, not implicit in code.

---

## Changelog

| Date | Change |
|------|--------|
| 2026-03-22 | Repository license migrated from MIT to Apache-2.0. `pyproject.toml` and `package.json` updated accordingly. No functional changes to the integration surface. |