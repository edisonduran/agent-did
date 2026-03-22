# F2-04 - Semantic Kernel Implementation Checklist

## Objective

Convert the Semantic Kernel package in `integrations/semantic-kernel/` from an SDK-ready scaffold into a functional Python-oriented integration without reopening already settled language-scope decisions.

Use this checklist when implementation work starts or when a PR changes the package shape, runtime hooks, tools, middleware or documentation.

---

## Current Baseline

- [x] The package declares itself as `functional` and that status matches the shipped integration surface.
- [x] `integrations/semantic-kernel/README.md` no longer describes the Python SDK as future work.
- [x] `docs/F2-04-Semantic-Kernel-Integration-Design.md` still matches the intended runtime surface.

---

## Factory And Public Surface

- [x] Keep `createAgentDidSemanticKernelIntegration(...)` as a conceptual alias while the Python-first surface ships as `create_agent_did_semantic_kernel_integration(...)`.
- [x] Define the Python adapter return shape before adding secondary helpers.
- [x] Keep the public concepts centered on Semantic Kernel-native surfaces: tools, middleware, context and observability hooks.

---

## Runtime Integration

- [x] Map Agent-DID tools to host-friendly tool specs suitable for framework tool registration.
- [x] Define middleware or runtime hooks for identity injection without exposing secrets.
- [x] Define how session or workflow context carries identity metadata safely.

---

## Security

- [x] Keep sensitive capabilities opt-in: HTTP signing, payload signing and key rotation.
- [x] Ensure private keys never enter model-visible prompts or runtime context.
- [x] Ensure error, logging and observability paths stay sanitized by default.

---

## Documentation And Examples

- [x] Add at least one runnable example covering the target Python runtime surface.
- [x] Document secure defaults and opt-in exposure flags in `integrations/semantic-kernel/README.md`.
- [x] Keep README, design doc and package metadata aligned in the same PR.

---

## Validation

- [x] Add tests for the adapter factory and tool exposure.
- [x] Add tests for middleware or context injection semantics.
- [x] Add tests for secure defaults and failure handling.
- [x] Add an optional real-runtime smoke path against `semantic-kernel` without forcing the runtime dependency in the default install.

## Current Closure Notes

- The shipped package is Python-native and no longer depends on the legacy JS scaffold.
- The integration exposes tool specs, session context helpers and middleware-like hooks without forcing a hard runtime dependency.
- The package now exposes a `.[runtime]` extra and a semantic-kernel plugin helper for validating real host compatibility.
- The pytest bootstrap for async tests is now resilient to both clean environments and environments where `pytest-asyncio` is already auto-loaded.
- Test bootstrap helpers continue to follow repo style rules, including spaces-only indentation so the Python lint step stays green across CI images.
- Dedicated CI coverage is expected in `.github/workflows/ci-semantic-kernel.yml`.
- Observability is vendor-neutral and sanitized by default, following the same governance line used in the other Python integrations.

---

## Exit Rule

F2-04 is implementation-ready for release review when the package has a functional adapter, runnable example, automated tests and documentation that matches shipped behavior.