# F2-05 - CrewAI Integration Review Checklist

## Objective

Turn CrewAI integration review into a repeatable artifact so future implementation work cannot drift from the repo narrative.

Run this checklist whenever a change affects `integrations/crewai/**` or the CrewAI design and implementation documents.

---

## When To Run It

Run this checklist when a change affects one or more of the following:

- `integrations/crewai/**`
- `docs/archive/F2-05-CrewAI-Integration-Design.md`
- `docs/F2-05-CrewAI-Implementation-Checklist.md`
- CrewAI tools, callbacks, guardrails, README or package metadata

---

## Package Governance

- [ ] The package status is still correct for the shipped state (`functional` while the current `Agent`/`Task`/`Crew` helper surface remains accurate).
- [ ] README, design doc and package metadata describe the same current state.
- [ ] No CrewAI document refers to the Python SDK as future work.
- [ ] If release metadata changes, the README and package metadata still agree on the coordinated `1.0.0rc4` dependency on `agent-did-sdk`.

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
- [ ] Python 3.12 runtime inspection still sees the generated guardrail with its return annotation removed at runtime, and regression coverage protects that compatibility behavior.

## Observability

- [ ] The integration still emits the documented minimum event taxonomy for snapshots, tools and CrewAI callbacks.
- [ ] Structured observability remains compatible with fan-out composition and sanitized JSON logging.

---

## Documentation And Delivery

- [ ] `docs/F2-05-CrewAI-Implementation-Checklist.md` still reflects the current shipped completion state or the next concrete delta.
- [ ] The README still points to the implementation and review checklists.
- [ ] The README and design doc still point to `docs/archive/F2-05-CrewAI-Maturity-Gap-Assessment.md` when maturity claims or remaining gaps change.
- [ ] The README and review flow still point to `docs/archive/F2-05-CrewAI-LangChain-Maturity-Rubric.md` when CrewAI maturity claims are updated.
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

---

## Changelog

| Date | Change |
|------|--------|
| 2026-11-12 | Review gate: an agent created with an external signer signs through the tools; tool rotation refuses it. |
| 2026-11-12 | `sign_http_request` raises `ValueError` when the runtime identity has no active authentication key, because the SDK now requires the verification method id (same behavior as the A2A client). Type-check fix; no other change to the integration surface. |
| 2026-11-12 | RC metadata moved to the `1.0.0rc5` release train (npm `1.0.0-rc.5`); pins the matching `agent-did-sdk`. No functional changes to the integration surface. |
| 2026-11-04 | M-09: CrewAI examples and tests create identities with an Ed25519 `LocalKeySigner` controller (`controllerSigner` / `controller_signer`) instead of an EVM wallet or address. No change to the integration surface; see `sdk/MIGRATION-1.0-rc.3-to-rc.4.md`. |
| 2026-11-04 | RC metadata moved to the `1.0.0rc4` release train (npm `1.0.0-rc.4`); pins the matching `agent-did-sdk`. No functional changes to the integration surface. |
| 2026-11-03 | Tools now resolve, verify and rotate through `agentIdentity.client` (`AgentDidClient`) instead of the deprecated static `AgentIdentity` API. Identities without an explicit client use the default client, so behavior and the public tool surface are unchanged. |
| 2026-11-03 | RC metadata moved to the `1.0.0rc3` release train; the package now pins `agent-did-sdk==1.0.0rc3`. The integration test suite passes unchanged against the rc.3 SDK (did:webvh v1.0 logs, RFC 9421 signatures, salted commitments). No functional changes to the integration surface. |
| 2026-11-02 | RC metadata moved to the `1.0.0rc2` security release train ([GHSA-g97p-4qrw-9hvf](https://github.com/edisonduran/agent-did/security/advisories/GHSA-g97p-4qrw-9hvf)); the package now pins `agent-did-sdk==1.0.0rc2`. No functional changes to the integration surface. |
| 2026-05-08 | Added an explicit review gate for RC metadata alignment so README/package metadata stay synchronized during the `1.0.0rc1` freeze. |
| 2026-03-22 | Repository license migrated from MIT to Apache-2.0. `pyproject.toml` updated accordingly. No functional changes to the integration surface. |