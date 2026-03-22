# F2-05 - CrewAI Integration Review Checklist

## Objective

Turn CrewAI integration review into a repeatable artifact so future implementation work cannot drift from the repo narrative.

Run this checklist whenever a change affects `integrations/crewai/**` or the CrewAI design and implementation documents.

---

## When To Run It

Run this checklist when a change affects one or more of the following:

- `integrations/crewai/**`
- `docs/F2-05-CrewAI-Integration-Design.md`
- `docs/F2-05-CrewAI-Implementation-Checklist.md`
- CrewAI tools, callbacks, guardrails, README or package metadata

---

## Package Governance

- [ ] The package status is still correct for the shipped state (`functional` while the current `Agent`/`Task`/`Crew` helper surface remains accurate).
- [ ] README, design doc and package metadata describe the same current state.
- [ ] No CrewAI document refers to the Python SDK as future work.

---

## Public Surface

- [ ] The intended factory name remains `create_agent_did_crewai_integration(...)`.
- [ ] Public concepts remain centered on CrewAI-native surfaces: tools, structured observability, callbacks, guardrails and structured outputs.
- [ ] Any newly introduced helper surface is documented in the README and reflected in the implementation checklist.
- [ ] If tool-host wiring changes, `create_agent_kwargs(...)` and `create_task_kwargs(...)` still adapt shipped Agent-DID tools to CrewAI runtime-native `BaseTool` instances when CrewAI is installed.
- [ ] Internal typing changes that affect CI, including helper properties and setters, preserve strict `mypy` compatibility on the supported Python matrix.

---

## Security

- [ ] Sensitive capabilities remain opt-in.
- [ ] Private keys remain outside model-visible prompts and context.
- [ ] Logs, callbacks and observability hooks do not expose raw secrets by default.
- [ ] Guardrail callables remain acceptable to the installed CrewAI runtime, preserving the `(bool, Any)` result contract expected by `Task` validation without exposing a nested runtime return annotation.
- [ ] Python 3.12 runtime inspection still sees the generated guardrail as unannotated at runtime, and regression coverage protects that compatibility behavior.

## Observability

- [ ] The integration still emits the documented minimum event taxonomy for snapshots, tools and CrewAI callbacks.
- [ ] Structured observability remains compatible with fan-out composition and sanitized JSON logging.

---

## Documentation And Delivery

- [ ] `docs/F2-05-CrewAI-Implementation-Checklist.md` still reflects the current shipped completion state or the next concrete delta.
- [ ] The README still points to the implementation and review checklists.
- [ ] The README and design doc still point to `docs/F2-05-CrewAI-Maturity-Gap-Assessment.md` when maturity claims or remaining gaps change.
- [ ] The README and review flow still point to `docs/F2-05-CrewAI-LangChain-Maturity-Rubric.md` when CrewAI maturity claims are updated.
- [ ] If shipped behavior changes, the design doc is updated in the same PR.
- [ ] If the package ships base, observability or production-style examples, the README still describes the current example set and local execution guards.

## Runtime Validation

- [ ] At least one supported CI path still installs the optional `.[runtime]` extra.
- [ ] The real-runtime smoke test still instantiates CrewAI `Agent`, `Task` and `Crew` with the shipped helper bundle.
- [ ] Runtime smoke coverage still proves that the shipped helper bundle is accepted by CrewAI host validation on Python 3.12, including adapted tool objects.

## Test Topology

- [ ] The suite still isolates wiring, tool operations, security, observability and runtime-smoke concerns in separate test modules.
- [ ] New regressions can fail narrowly without pushing unrelated assertions into broad integration files.

---

## Decision Rule

CrewAI review is complete when the current package state is accurately described, security expectations remain explicit, and all implementation-facing artifacts agree on the shipped surface.