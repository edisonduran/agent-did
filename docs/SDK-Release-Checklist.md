# SDK Release Checklist

## Objective

Provide a single repository-level release checklist for the TypeScript SDK in `sdk/` and the Python SDK in `sdk-python/`.

This checklist is intended for:

1. Release preparation.
2. PR review of SDK-affecting changes.
3. Regression prevention when RFC-001 behavior changes.

---

## When to Use This Checklist

Use this checklist whenever a change affects one or more of the following:

- `sdk/**`
- `sdk-python/**`
- `fixtures/**`
- shared RFC-001 lifecycle semantics
- canonical `documentRef` generation
- cross-language interoperability vectors

---

## Global Release Checks

Mark each item before cutting or approving an SDK-affecting release.

- [ ] The change scope is identified: `sdk`, `sdk-python`, or both.
- [ ] The parity matrix in `docs/F2-01-TS-Python-Parity-Matrix.md` is still accurate.
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
```

Checklist:

- [ ] `python -m ruff check src/ tests/ scripts/`
- [ ] `python -m mypy --strict src/`
- [ ] `python -m pytest tests/ -q`
- [ ] `python scripts/conformance_rfc001.py`
- [ ] If Python public API changed, `sdk-python/README.md` is updated.
- [ ] `sdk-python/pyproject.toml` metadata and version are correct for the release.

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
- [ ] If fixtures changed, both workflows were considered part of the validation surface.

---

## Recommended Root Shortcuts

These monorepo shortcuts are optional helpers, not replacements for stack-native workflows:

```bash
npm run python:install-dev
npm run python:test
npm run python:conformance
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
- `docs/RFC-001-Implementation-Backlog.md`
- `README.md`
- `sdk-python/README.md`