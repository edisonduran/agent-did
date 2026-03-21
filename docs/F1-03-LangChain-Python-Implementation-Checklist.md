# F1-03 — LangChain Python Implementation Checklist

## Objective

Turn the current `integrations/langchain-python/` design scaffold into a functional Python integration built on top of the implemented Agent-DID Python SDK.

This checklist is the execution companion to:

- `docs/F1-03-LangChain-Python-Integration-Design.md`
- `integrations/langchain-python/README.md`

---

## Current Status

The blocking dependency has changed.

- **Before:** the integration was blocked by the absence of the Python SDK.
- **Now:** the Python SDK exists, has dedicated CI, and parity governance with the TypeScript SDK.

The remaining work is implementation work inside `integrations/langchain-python/`.

---

## Implementation Phases

### Phase 1 — Minimal Functional Integration

- [ ] Replace the placeholder `NotImplementedError` factory with a real integration factory.
- [ ] Define the public integration config for Python.
- [ ] Implement current identity exposure.
- [ ] Implement DID resolution tool.
- [ ] Implement signature verification tool.
- [ ] Keep sensitive operations opt-in by default.

### Phase 2 — Secure Optional Operations

- [ ] Implement HTTP signing as explicit opt-in.
- [ ] Implement payload signing as explicit opt-in.
- [ ] Keep private key material outside model-visible context.
- [ ] Keep key rotation disabled by default.
- [ ] Keep arbitrary signing disabled by default unless explicitly enabled.

### Phase 3 — Context Injection and UX

- [ ] Inject DID, controller, active authentication method, and capabilities into agent context.
- [ ] Align naming and conceptual API with the JS integration where practical.
- [ ] Add a runnable example equivalent to the JS package quick start.
- [ ] Document LangChain Python version expectations.

### Phase 4 — Validation

- [ ] Add Python tests for the integration package.
- [ ] Add tests for identity exposure.
- [ ] Add tests for DID resolution.
- [ ] Add tests for signature verification.
- [ ] Add tests for opt-in HTTP signing.
- [ ] Add regression coverage for secret isolation.

### Phase 5 — Release Readiness

- [ ] Update `pyproject.toml` metadata away from `design-scaffold` semantics.
- [ ] Update `README.md` from design scaffold language to implementation language.
- [ ] Add package-level release checks aligned with `docs/SDK-Release-Checklist.md`.
- [ ] Add CI coverage if the package becomes executable and testable.

---

## Definition of Done

The LangChain Python integration is ready when all of the following are true:

1. `create_agent_did_langchain_integration(...)` is implemented.
2. The integration exposes identity, DID resolution, and verification tools.
3. HTTP signing is opt-in and secret-safe.
4. A runnable example exists.
5. Automated tests exist.
6. Documentation no longer describes the package as blocked by the Python SDK.

---

## Related Files

- `integrations/langchain-python/README.md`
- `integrations/langchain-python/pyproject.toml`
- `integrations/langchain-python/src/agent_did_langchain/__init__.py`
- `docs/F1-03-LangChain-Python-Integration-Design.md`
- `docs/F2-01-TS-Python-Parity-Matrix.md`
- `docs/SDK-Release-Checklist.md`