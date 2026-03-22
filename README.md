# Agent-DID: Verifiable Identity for AI Agents

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Node.js](https://img.shields.io/badge/node-%3E%3D18-brightgreen)](https://nodejs.org)

Reference project for the **Agent-DID (RFC-001)** standard: decentralized identity for AI agents with cryptographic signing, document resolution, revocation, and evolution traceability.

## Current Status

The project is past the specification-only phase: it includes a functional implementation and a validation pipeline.

- **RFC-001** consolidated and operational: [docs/RFC-001-Agent-DID-Specification.md](docs/RFC-001-Agent-DID-Specification.md)
- **Compliance checklist**: [docs/RFC-001-Compliance-Checklist.md](docs/RFC-001-Compliance-Checklist.md)
- **Current result**: MUST `11/11 PASS` and SHOULD `5/5 PASS`

## Main Components

### 1) TypeScript SDK (`sdk/`)

Includes:

- Agent-DID document creation (`create`)
- Ed25519 signing and verification (`signMessage`, `verifySignature`)
- HTTP signing/verification (`signHttpRequest`, `verifyHttpRequestSignature`)
- DID resolution with cache/failover (`UniversalResolverClient`)
- Document sources via `HTTP/IPFS` and `JSON-RPC`
- Revocation, document update, key rotation, and history

### 1b) Python SDK (`sdk-python/`)

Includes the same core lifecycle primitives as the TypeScript SDK:

- Agent-DID document creation (`create`)
- Ed25519 signing and verification (`sign_message`, `verify_signature`)
- HTTP signing/verification (`sign_http_request`, `verify_http_request_signature`)
- DID resolution with cache/failover (`UniversalResolverClient`)
- Revocation, document update, key rotation, and history
- Dedicated Python CI with lint, type-check, coverage, conformance, and smoke tests

### 2) EVM Registry (`contracts/`)

`AgentRegistry` contract with:

- DID registration and revocation
- On-chain document reference (`documentRef`)
- Formal revocation access policy:
	- revocation by `owner` or DID-authorized delegate
	- explicit delegation (`setRevocationDelegate`)
	- ownership transfer (`transferAgentOwnership`)

### 3) Validation and Drills (`scripts/`)

- Full conformance: `npm run conformance:rfc001`
- E2E SDK + contract: `npm run smoke:e2e`
- Resolver high-availability drill: `npm run smoke:ha`
- JSON-RPC resolution smoke: `npm run smoke:rpc`
- Revocation policy smoke: `npm run smoke:policy`

## Integrations

- LangChain JS 1.x: implemented in [integrations/langchain/README.md](integrations/langchain/README.md)
- LangChain Python: functional MVP implemented in [integrations/langchain-python/README.md](integrations/langchain-python/README.md), with dedicated tests, opt-in key rotation, and hardened HTTP signing defaults
- Semantic Kernel: functional Python integration with tools, session-context helpers, middleware-style identity injection and sanitized observability in [integrations/semantic-kernel/README.md](integrations/semantic-kernel/README.md), roadmap item F2-04
- CrewAI: functional MVP implemented in [integrations/crewai/README.md](integrations/crewai/README.md), roadmap item F2-05
- Azure AI Agent Service: planned roadmap item F2-08

## Running Locally

### Requirements

- Node.js 18+
- npm

### Installation

```bash
npm install
npm --prefix sdk install
npm --prefix contracts install
python -m pip install -e "./sdk-python[dev]"
```

### Recommended Quick Verification

```bash
npm run conformance:rfc001
```

This command runs SDK build/tests and operational smokes (policy, HA, RPC, E2E).

If you are working on the LangChain package, also run:

```bash
npm run test:langchain
```

If you are working on the LangChain Python package, the canonical local workflow is:

```bash
npm run langchain-python:install-dev
npm run lint:langchain-python
npm run typecheck:langchain-python
npm run test:langchain-python
```

If you are working on the Python SDK, the canonical local workflow is:

```bash
cd sdk-python
python -m pip install -e ".[dev]"
ruff check src/ tests/ scripts/
mypy --strict src/
pytest --cov=agent_did_sdk --cov-fail-under=85 -q
python scripts/conformance_rfc001.py
```

If you are working on the CrewAI Python integration, the canonical local workflow is:

```bash
cd integrations/crewai
python -m pip install -e .[dev]
python -m ruff check src/ tests/ examples/
python -m mypy src/
python -m build
python -m pytest tests/ -q
```

Repository-level shortcuts also exist:

```bash
npm run python:test
npm run python:conformance
```

These `npm` commands are convenience wrappers only; the Python SDK remains Python-native in local development and CI.

If you are working on the smart contract security track, run:

```bash
npm run audit:contracts
```

This command generates Slither and Mythril reports under `contracts/reports/security` and requires a running Docker daemon.

By default the audit gate is strict: any unmatched finding at severity `Low` or higher fails the command. You can raise the threshold with `AUDIT_FAIL_ON_SEVERITY=medium|high|critical` for exploratory runs.

## Key Documentation

- Main specification: [docs/RFC-001-Agent-DID-Specification.md](docs/RFC-001-Agent-DID-Specification.md)
- Compliance checklist: [docs/RFC-001-Compliance-Checklist.md](docs/RFC-001-Compliance-Checklist.md)
- Implementation backlog: [docs/RFC-001-Implementation-Backlog.md](docs/RFC-001-Implementation-Backlog.md)
- TS ↔ Python parity matrix: [docs/F2-01-TS-Python-Parity-Matrix.md](docs/F2-01-TS-Python-Parity-Matrix.md)
- SDK release checklist: [docs/SDK-Release-Checklist.md](docs/SDK-Release-Checklist.md)
- LangChain Python technical plan: [docs/F1-03-LangChain-Python-Technical-Plan.md](docs/F1-03-LangChain-Python-Technical-Plan.md)
- Resolver HA runbook: [docs/RFC-001-Resolver-HA-Runbook.md](docs/RFC-001-Resolver-HA-Runbook.md)
- Complete SDK course (7 modules, Spanish): [docs/Complete-Agent-DID-SDK-Course-ES.md](docs/Complete-Agent-DID-SDK-Course-ES.md)
- Complete SDK course (7 modules, English): [docs/Complete-Agent-DID-SDK-Course-EN.md](docs/Complete-Agent-DID-SDK-Course-EN.md)
- 2-hour practical course: [docs/RFC-001-2h-Practical-Course.md](docs/RFC-001-2h-Practical-Course.md)
- Training manual: [docs/RFC-001-Training-Manual.md](docs/RFC-001-Training-Manual.md)
- Strategic assessment & roadmap (Spanish): [docs/Strategic-Assessment-Agent-DID-ES.md](docs/Strategic-Assessment-Agent-DID-ES.md)
- Strategic assessment & roadmap (English): [docs/Strategic-Assessment-Agent-DID-EN.md](docs/Strategic-Assessment-Agent-DID-EN.md)
- Contribution guide: [CONTRIBUTING.md](CONTRIBUTING.md)

## Roadmap

RFC-001 is implemented and fully conformant. The project follows a 3-phase roadmap:

### Phase 1 — Consolidation & Visibility (current)

| # | Item | Status |
|---|---|---|
| F1-01 | Publish SDK to npm (`@agent-did/sdk`) | Done |
| F1-02 | Translate all docs to English | Done (course + strategic assessment + README) |
| F1-03 | LangChain integration for Agent-DID identity | Done |
| F1-04 | Submit RFC-001 to DIF | Open |
| F1-05 | Automated smart contract audit (Slither/Mythril) | Done |
| F1-06 | CI/CD pipeline with GitHub Actions | Done |

The repository now includes a GitHub Actions workflow at `.github/workflows/ci.yml` that installs the root, SDK, and contract workspaces and runs `npm run conformance:rfc001` on pushes, pull requests, and manual dispatches.

LangChain JS validation runs in the dedicated workflow at `.github/workflows/ci-langchain-js.yml`, which builds `sdk/` and tests `integrations/langchain` separately from the core TypeScript/conformance pipeline.

Current CI split in GitHub Actions:

- `CI — TypeScript SDK & RFC-001 Conformance`: Node/TypeScript pipeline for the root workspace, `sdk/`, `contracts/`, and RFC-001 conformance/smoke coverage.
- `CI — LangChain JS Integration`: dedicated Node validation for `integrations/langchain/` against the local `sdk/`.
- `CI — Python SDK & RFC-001 Conformance`: Python-native quality gates for `sdk-python/`, including conformance and Python smoke coverage on the primary runtime.
- `CI — LangChain Python Integration`: dedicated validation for `integrations/langchain-python/`.
- `CI - Semantic Kernel Integration`: dedicated validation for `integrations/semantic-kernel/`.
- `Contract Audit`: Slither/Mythril security audit pipeline for `contracts/`.

Python quality gates run in the dedicated workflow at `.github/workflows/ci-python.yml`, exposed in Actions as `CI — Python SDK & RFC-001 Conformance`, which executes the Python SDK matrix, linting, strict type-checking, coverage, build, conformance, and Python smoke tests.

Smart contract audit automation is available through `npm run audit:contracts` and the dedicated GitHub Actions workflow at `.github/workflows/contract-audit.yml`, which runs Slither and Mythril and uploads the resulting reports as CI artifacts.

The audit runner preserves the raw JSON reports, classifies only exact known-noise matches in the generated summary, and applies a severity-aware gate to unmatched findings.

Initial triage of the current contract findings is documented in [docs/F1-05-Contract-Audit-Triage.md](docs/F1-05-Contract-Audit-Triage.md). Formal external audit remains a later milestone under F3-04.

The LangChain integration is available in [integrations/langchain/README.md](integrations/langchain/README.md).

### Phase 2 — Ecosystem Expansion (3-6 months)

| # | Item | Status |
|---|---|---|
| F2-01 | Python SDK with feature parity | Done |
| F2-02 | Google A2A proof-of-concept | Open |
| F2-03 | Production resolver (IPFS/Arweave + HTTP) | Open |
| F2-04 | Microsoft Agent Framework integration | Done |
| F2-05 | CrewAI integration | Open |
| F2-06 | Public testnet deployment | Open |
| F2-07 | Formal whitepaper publication | Open |
| F2-08 | Azure AI Agent Service integration | Open |

The next Python-focused consolidation track is semantic parity: canonical `documentRef` generation, shared cross-language fixtures, and keeping the separate Python CI aligned with the TypeScript quality bar.

The next Python integration track is hardening and release maturation of LangChain Python, with execution steps documented in [docs/F1-03-LangChain-Python-Implementation-Checklist.md](docs/F1-03-LangChain-Python-Implementation-Checklist.md).

### Phase 3 — Maturity & Standardization (6-12 months)

| # | Item | Status |
|---|---|---|
| F3-01 | Propose `did:agent` to W3C DID WG | Planned |
| F3-02 | Conformance certification service | Planned |
| F3-03 | ZKP for capability verification | Planned |
| F3-04 | Formal contract audit for mainnet | Planned |
| F3-05 | Enterprise partnerships | Planned |
| F3-06 | Account Abstraction (ERC-4337) for agent wallets | Planned |

See [CONTRIBUTING.md](CONTRIBUTING.md) for details on how to pick up roadmap items.

## License

[MIT](LICENSE)
