# CLAUDE.md

Agent-DID: an identity layer for AI agents (W3C DID/VC, `did:webvh` as the canonical path, Ed25519, HTTP Message Signatures). The repo is a monorepo holding the spec, two SDKs that must stay in parity, six framework integrations and deferred EVM contracts. Current train: `1.0.0-rc.3` published (breaking RC: did:webvh v1.0, RFC 9421, JCS).

Maintainers may keep session-specific context in `CLAUDE.local.md`, which is gitignored. Read it when present.

## Layout

| Path | What |
|---|---|
| `sdk/` | TypeScript SDK `@agentdid/sdk` (core: `src/core/AgentIdentity.ts`) |
| `sdk-python/` | Python SDK `agent-did-sdk` (core: `src/agent_did_sdk/core/identity.py`) |
| `integrations/langchain/` | LangChain **JS** (plain `.js`, not TS) |
| `integrations/{langchain-python,crewai,semantic-kernel,microsoft-agent-framework,a2a}/` | Python integrations |
| `fixtures/interop-vectors.json` | Cross-SDK contract; both SDKs must verify it |
| `scripts/` | Conformance (`conformance-rfc001.js`), smokes, governance checks |
| `contracts/` | Solidity/Hardhat, EVM profile, **deferred outside core 1.0** |
| `docs/` | RFC-001 (spec), release criteria, governance, F1-/F2- design docs |
| `_bmad/`, `_bmad-output/`, `.agents/` | BMAD method tooling, not product code |

## Commands

Run these from the repo root unless noted. Requirements: Node 22+, Python 3.10+.

```bash
# TypeScript SDK
npm --prefix sdk test                      # jest
npm --prefix sdk run build                 # tsc
npm --prefix sdk run api:check             # public API snapshot (also api:signature:check)

# Python SDK (cd sdk-python)
python -m ruff check src/ tests/ scripts/ examples/
python -m mypy --strict src/
python -m pytest tests/ -q                 # CI enforces --cov-fail-under=85

# Cross-cutting
npm run interop:check                      # shared vectors, TS + Python
npm run conformance:rfc001                 # TS conformance (Python: npm run python:conformance)
npm run api:check                          # all public API snapshots, TS + Python
npm run check:integration-governance

# Integrations
npm run test:langchain                     # builds sdk first
npm run test:crewai | test:semantic-kernel | test:microsoft-agent-framework | test:a2a | test:langchain-python
```

Run a single test with `npm --prefix sdk test -- AgentIdentity.test.ts -t "name"` or `python -m pytest sdk-python/tests/test_identity.py -k name -q`.

## Rules

- **TS/Python parity is mandatory.** Any change to SDK behavior, wire formats or hashing lands in both SDKs in the same PR, with updated interop vectors (`scripts/regenerate-interop-vectors.js`). Never close a work item in a single SDK.
- **Public API is snapshotted.** If you change exports or signatures intentionally, regenerate them with `npm run api:snapshot` and explain why in the PR. Never regenerate a snapshot just to make a check pass.
- **Wire/format changes are breaking.** This covers signature bases, the canonicalization behind document hashes, DID log formats and hash URIs. They go only into the planned `rc.3` train and need an entry in `CHANGELOG.md` and the migration guides (`sdk/MIGRATION-*.md`, `sdk-python/MIGRATION-*.md`).
- **Crypto hygiene:**
  - Never derive private keys from public data.
  - Use `@noble/*` in TS and `pynacl`/`hashlib`/`secrets` in Python. Canonical JSON for hashing is RFC 8785 (JCS) only: `canonicalizeJson` / `canonicalize_json` (the latter wraps `rfc8785`).
  - Do not add new uses of `ethers`/`web3` in the core; EVM is a deferred, optional profile.
  - Integrity failures must never fall back to another resolution source.
  - Do not claim conformance with an external spec (did:webvh, RFC 9421, RFC 8785…) in docs unless a CI job verifies it against that spec's official vectors or an independent implementation.
- **Security findings stay private.** Never describe unpatched vulnerabilities in commits, PRs, issues or tracked docs; follow `SECURITY.md`.
- **Docs governance** (`docs/Documentation-Governance.md`). When a change affects status, maturity or capabilities, update the impacted live docs (root README, package READMEs, release criteria) in the same PR. Label stale docs as historical rather than leaving them inconsistent.
- **Git:** Conventional Commits (`feat(sdk): …`, `fix(sdk-python): …`, `docs(release): …`). Branch from `main`.
