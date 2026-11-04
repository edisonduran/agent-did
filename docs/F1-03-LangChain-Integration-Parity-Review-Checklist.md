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
- [ ] DID documents used for signing demos bind signing keys to `assertionMethod`, not only `authentication` or `keyAgreement`.
- [ ] HTTP target validation still rejects invalid schemes, embedded credentials and private or loopback targets by default.
- [ ] When `allow_private_network_targets` is enabled, `http_security` options are propagated to the SDK's `signHttpRequest` in both packages (or the divergence is documented in the parity matrix).

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
- [ ] If release-candidate metadata changes, both READMEs still document the coordinated prerelease install path (`@next` on npm, `1.0.0rc3` on Python) without implying divergent runtime behavior.
- [ ] If a local quickstart clarifies controller bootstrap or hosted `did:webvh` publication boundaries, both READMEs still describe that deployment split consistently.
- [ ] Both packages still ship, at minimum, base, observability and production-style examples.
- [ ] If one package ships an integrated `did:wba` demo, the other package ships an equivalent integrated `did:wba` demo or the divergence is explicit in docs.
- [ ] If the integrated `did:wba` demo changes, the canonical walkthrough in `docs/F1-03-LangChain-didwba-Demo-Walkthrough.md` still matches the shipped behavior.
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

### Cross-package demo smoke

- [ ] `npm run smoke:langchain-didwba`

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
| 2026-11-04 | M-09: LangChain TS and Python examples and tests create identities with an Ed25519 `LocalKeySigner` controller (`controllerSigner` / `controller_signer`) instead of an EVM wallet or address. No change to the integration surface; see `sdk/MIGRATION-1.0-rc.3-to-rc.4.md`. |
| 2026-11-03 | Tools now resolve, verify and rotate through `agentIdentity.client` (`AgentDidClient`) instead of the deprecated static `AgentIdentity` API. Identities without an explicit client use the default client, so behavior and the public tool surface are unchanged. |
| 2026-11-03 | Coordinated prerelease install path moved to `1.0.0-rc.3` / `1.0.0rc3`. Both integration test suites pass unchanged against the rc.3 SDKs. No functional changes to the integration surface. |
| 2026-11-02 | Coordinated prerelease install path moved to `1.0.0-rc.2` / `1.0.0rc2` (security release, [GHSA-g97p-4qrw-9hvf](https://github.com/edisonduran/agent-did/security/advisories/GHSA-g97p-4qrw-9hvf)). No functional changes to the integration surface. |
| 2026-11-01 | LangChain JS README now states Node.js 22+, matching `engines.node`. Documentation only; no public surface change. |
| 2026-11-01 | LangChain JS `package.json` now declares `repository` (with `directory`), `homepage` and `bugs`, required for npm provenance on trusted publishing. Python metadata unchanged; no public surface change. |
| 2026-11-01 | LangChain JS now declares `engines.node >=22.0.0` (Node 18/20 are EOL and unpatched for the October 2026 Node.js security releases). Python packages are unaffected; no public surface change. |
| 2026-11-01 | LangChain Python LangSmith adapter no longer double-appends child runs when `langsmith>=0.14` already appends inside `RunTree.create_child`. Behavior now matches the TS adapter (one child run per event); no public surface change. |
| 2026-05-08 | Added a governance check for coordinated RC metadata so TS/Python README guidance stays aligned when the release train uses ecosystem-native prerelease versions. |
| 2026-05-08 | Added a review gate for README changes that clarify local controller bootstrap vs hosted `did:webvh` publication so the TS/Python conceptual model stays aligned. |
| 2026-05-04 | Added parity review coverage for `assertionMethod` binding in signing-capable `did:wba` demo DID documents. |
| 2026-03-31 | Repository slug updated to `agent-did` and active LangChain TS/Python package references normalized to `@agentdid/*` in README/examples/metadata. No functional changes to the integration surface; parity artifacts refreshed for governance compliance. |
| 2026-03-23 | Added a canonical walkthrough and a cross-package `did:wba` demo smoke gate so parity review also covers executable demo behavior. |
| 2026-03-22 | Added explicit parity review gate for integrated `did:wba` demos and refreshed the parity matrix after shipping mirrored LangChain TS/Python demos. |
| 2026-03-22 | Repository license migrated from MIT to Apache-2.0. `pyproject.toml` and `package.json` updated accordingly. No functional changes to the integration surface. |
| 2026-03-22 | npm scope rename: `@agent-did/langchain` → `@agentdid/langchain` and `@agent-did/sdk` → `@agentdid/sdk` to align with the `@agentdid` npm org. No changes to the public API or functional surface. |