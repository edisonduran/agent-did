# F2-04 - Microsoft Agent Framework Integration Review Checklist

## Objective

Turn Microsoft Agent Framework integration review into a repeatable artifact so scaffold updates and future implementation work cannot drift from the repository narrative.

Run this checklist whenever a change affects `integrations/microsoft-agent-framework/**` or the F2-04 design and implementation documents.

---

## When To Run It

Run this checklist when a change affects one or more of the following:

- `integrations/microsoft-agent-framework/**`
- `docs/F2-04-Microsoft-Agent-Framework-Integration-Design.md`
- `docs/F2-04-Microsoft-Agent-Framework-Implementation-Checklist.md`
- Microsoft Agent Framework tools, middleware, context, README or package metadata

---

## Scaffold Governance

- [ ] The package status is still correct for the shipped state (`functional` for the current Python integration surface).
- [ ] README, design doc and package metadata describe the same current state.
- [ ] No Microsoft Agent Framework document refers to the Python SDK as future work.

---

## Public Surface

- [ ] The intended factory name remains `createAgentDidMicrosoftAgentFrameworkIntegration(...)` at the conceptual surface.
- [ ] Public concepts remain centered on runtime-native surfaces: tools, middleware, context and observability.
- [ ] Any newly introduced helper surface is documented in the README and reflected in the implementation checklist.

---

## Security

- [ ] Sensitive capabilities remain opt-in.
- [ ] Private keys remain outside model-visible prompts and context.
- [ ] Runtime hooks, logging and future observability paths do not expose raw secrets by default.

---

## Documentation And Delivery

- [ ] `docs/F2-04-Microsoft-Agent-Framework-Implementation-Checklist.md` still reflects the next concrete delivery step.
- [ ] The README still points to the implementation and review checklists.
- [ ] If shipped behavior changes, the design doc is updated in the same PR.

---

## Decision Rule

Microsoft Agent Framework review is complete when the scaffold state is accurately described, security expectations remain explicit, and all implementation-facing artifacts agree on the next step.