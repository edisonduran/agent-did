# F2-04 - Semantic Kernel Integration Review Checklist

## Objective

Turn Semantic Kernel integration review into a repeatable artifact so scaffold updates and future implementation work cannot drift from the repository narrative.

Run this checklist whenever a change affects `integrations/semantic-kernel/**` or the F2-04 design and implementation documents.

---

## When To Run It

Run this checklist when a change affects one or more of the following:

- `integrations/semantic-kernel/**`
- `docs/F2-04-Semantic-Kernel-Integration-Design.md`
- `docs/F2-04-Semantic-Kernel-Implementation-Checklist.md`
- Semantic Kernel tools, middleware, context, README or package metadata

---

## Scaffold Governance

- [ ] The package status is still correct for the shipped state (`functional` for the current Python integration surface).
- [ ] README, design doc and package metadata describe the same current state.
- [ ] No Semantic Kernel document refers to the Python SDK as future work.

---

## Public Surface

- [ ] The intended factory name remains `createAgentDidSemanticKernelIntegration(...)` at the conceptual surface.
- [ ] Public concepts remain centered on runtime-native surfaces: tools, middleware, context and observability.
- [ ] Any newly introduced helper surface is documented in the README and reflected in the implementation checklist.
- [ ] Any runtime helper added for host validation, such as `create_semantic_kernel_plugin(...)`, remains optional and documented as a host-compatibility surface rather than a forced default dependency.

---

## Security

- [ ] Sensitive capabilities remain opt-in.
- [ ] Private keys remain outside model-visible prompts and context.
- [ ] Runtime hooks, logging and future observability paths do not expose raw secrets by default.
- [ ] Runtime smoke tests and operational recipes redact payloads, signatures and sensitive headers in emitted observability events.

---

## Documentation And Delivery

- [ ] `docs/F2-04-Semantic-Kernel-Implementation-Checklist.md` still reflects the next concrete delivery step.
- [ ] The README still points to the implementation and review checklists.
- [ ] If shipped behavior changes, the design doc is updated in the same PR.
- [ ] If runtime compatibility scope changes, the parity matrix and maturity-gap assessment are updated in the same PR.
- [ ] If an operational recipe is added, the README explains when to run it and what it validates.

---

## Runtime Validation

- [ ] The optional `.[runtime]` extra still installs the intended host-validation dependency without bloating the default package install.
- [ ] The semantic-kernel smoke path validates at least one zero-argument tool and one parameterized tool.
- [ ] The test suite still guarantees async pytest support in a clean environment without double-registering `pytest_asyncio` when the plugin is auto-loaded by the host environment.
- [ ] Test bootstrap helpers under `tests/` still follow the repository Python style rules, including spaces-only indentation required by Ruff.

---

## Decision Rule

Semantic Kernel review is complete when the scaffold state is accurately described, runtime validation claims are backed by executable checks, security expectations remain explicit, and all implementation-facing artifacts agree on the delivered scope and next step.