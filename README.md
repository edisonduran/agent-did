# Agent-DID: The Identity Layer for AI Agents

[![License: Apache-2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Node.js](https://img.shields.io/badge/node-%3E%3D18-brightgreen)](https://nodejs.org)
[![Works with LangChain](https://img.shields.io/badge/works%20with-LangChain-blue)](integrations/langchain/)
[![Works with CrewAI](https://img.shields.io/badge/works%20with-CrewAI-orange)](integrations/crewai/)
[![Works with Semantic Kernel](https://img.shields.io/badge/works%20with-Semantic%20Kernel-purple)](integrations/semantic-kernel/)
[![Works with Microsoft Agent Framework](https://img.shields.io/badge/works%20with-MS%20Agent%20Framework-lightblue)](integrations/microsoft-agent-framework/)
[![CI — TypeScript SDK](https://github.com/edisonduran/Agent-citizen-identification/actions/workflows/ci.yml/badge.svg)](https://github.com/edisonduran/Agent-citizen-identification/actions/workflows/ci.yml)
[![CI — Python SDK](https://github.com/edisonduran/Agent-citizen-identification/actions/workflows/ci-python.yml/badge.svg)](https://github.com/edisonduran/Agent-citizen-identification/actions/workflows/ci-python.yml)
[![CI — LangChain JS](https://github.com/edisonduran/Agent-citizen-identification/actions/workflows/ci-langchain-js.yml/badge.svg)](https://github.com/edisonduran/Agent-citizen-identification/actions/workflows/ci-langchain-js.yml)
[![CI — LangChain Python](https://github.com/edisonduran/Agent-citizen-identification/actions/workflows/ci-langchain-python.yml/badge.svg)](https://github.com/edisonduran/Agent-citizen-identification/actions/workflows/ci-langchain-python.yml)
[![CI — CrewAI](https://github.com/edisonduran/Agent-citizen-identification/actions/workflows/ci-crewai.yml/badge.svg)](https://github.com/edisonduran/Agent-citizen-identification/actions/workflows/ci-crewai.yml)
[![CI — Semantic Kernel](https://github.com/edisonduran/Agent-citizen-identification/actions/workflows/ci-semantic-kernel.yml/badge.svg)](https://github.com/edisonduran/Agent-citizen-identification/actions/workflows/ci-semantic-kernel.yml)
[![CI — Microsoft Agent Framework](https://github.com/edisonduran/Agent-citizen-identification/actions/workflows/ci-microsoft-agent-framework.yml/badge.svg)](https://github.com/edisonduran/Agent-citizen-identification/actions/workflows/ci-microsoft-agent-framework.yml)
[![Contract Audit](https://github.com/edisonduran/Agent-citizen-identification/actions/workflows/contract-audit.yml/badge.svg)](https://github.com/edisonduran/Agent-citizen-identification/actions/workflows/contract-audit.yml)

> **Give your AI agents a verifiable identity — in the framework you already use, with or without blockchain.**

**Agent-DID** is an open standard and reference implementation that answers the question the AI industry has systematically avoided: *when an autonomous agent acts — signs a request, delegates a task, modifies data — how does the system on the other side know who that agent really is?*

OAuth delegates this to a centralized provider. MCP ignores it by design. Agent-DID solves it at the cryptographic level, with zero lock-in and native integration in every major AI orchestration framework.

Built on W3C DID and Verifiable Credentials, Agent-DID provides:

- **A language-agnostic specification** ([RFC-001](docs/RFC-001-Agent-DID-Specification.md)) — 11/11 MUST conformant
- **Production-ready SDKs** for TypeScript and Python
- **Native integrations** for LangChain (JS + Python), CrewAI, Semantic Kernel, and Microsoft Agent Framework
- **Flexible trust anchoring** — on-chain (EVM) for immutability, or web-based (`did:wba`) for zero-friction adoption

---

## Why Agent-DID

| Problem | What Agent-DID provides |
|---|---|
| MCP and A2A don't define agent identity | Cryptographic DID anchored to the agent's model, prompt, and capabilities |
| Blockchain is required friction for most developers | `did:wba` method: identity without gas fees or wallets |
| Identity is a separate concern from the AI framework | Native wrappers that inject identity into LangChain, CrewAI, SK, and MAF |
| Agent actions are unauditable | Ed25519-signed HTTP requests — every action traceable to a verifiable DID |
| Rogue agents can't be stopped globally | On-chain revocation propagates instantly across all resolvers |

---

## Design Philosophy

### The Core Problem

AI is no longer just a tool humans use — it is becoming an actor that makes decisions, negotiates, executes code, signs operations, and delegates tasks to other agents. This transition raises a question the industry has systematically avoided:

> **How does a system know who the agent talking to it really is?**

Not who created it. Not which platform it runs on. But *which specific agent*, at this moment, with this behavior, executing these actions.

OAuth delegates this to a centralized provider. MCP ignores it by design. Agent-DID solves it at the cryptographic level, without platform lock-in.

### Five Principles

**1. Identity is a first-class citizen of the AI stack**
Identity is not a credential bolted on at the end. It is the foundation on which trust between autonomous systems is built. Without cryptographically verifiable identity there is no real audit trail, no algorithmic accountability, no revocation system that works when something goes wrong.

**2. Flexible by design, not by accident**
Not every system needs blockchain. Not every system can avoid it. Agent-DID rejects the imposition of a single trust-anchoring mechanism:
- High-frequency financial agents need EVM immutability and on-chain cryptographic traceability.
- Rapid-prototyping platforms need zero friction — no gas fees, no wallets.
- Regulated environments need verifiable credentials compatible with compliance frameworks.

The same standard — the same SDK — must work in all three cases.

**3. Meet the developer where they are**
A standard that requires learning a new paradigm before writing the first useful line of code has a structural adoption problem. Agent-DID integrates into the frameworks developers already use — LangChain, CrewAI, Semantic Kernel, Microsoft Agent Framework — and gives them verifiable identity without abandoning their workflow.

**4. Open standards over proprietary lock-in**
Agent-DID extends W3C DID Core and the Verifiable Credentials data model. It does not define a new identity format — it extends the standard the industry is already converging on, adding AI-specific metadata: model hash, system prompt hash, declared capabilities, evolution lifecycle. An identity ecosystem for AI agents only has value if it is interoperable. A proprietary standard is not a standard: it is a dependency.

**5. Verifiability without accidental complexity**
Identity cryptography is complex. AI agent developers should not have to be. Agent-DID closes that gap with framework abstractions that inject identity into the agent's execution chain without extra developer code, and with Ed25519 as the default — the fastest, most compact, and most secure cryptographic primitive for high-frequency signing environments.

### What Agent-DID Is Not

- **Not an orchestration framework.** It does not replace LangChain or CrewAI. It integrates with them.
- **Not a payment system.** ERC-4337 compatibility exists for agent wallets, but payment management is out of scope.
- **Not a blockchain mandate.** The EVM registry is an option, not a requirement. `did:wba` and `did:web` are equally valid.
- **Not a centralized platform.** There is no Agent-DID server to connect to. The protocol is the product.

---

Documentation governance for live project status and canonical sources of truth is defined in [docs/Documentation-Governance.md](docs/Documentation-Governance.md).

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
- CrewAI: functional Python integration with callbacks, guardrails, structured outputs and runtime smoke coverage in [integrations/crewai/README.md](integrations/crewai/README.md), roadmap item F2-05
- Microsoft Agent Framework: functional Python integration with native `Agent`/`tool(...)` wiring, `WorkflowBuilder` helpers, advanced orchestration coverage and sanitized observability in [integrations/microsoft-agent-framework/README.md](integrations/microsoft-agent-framework/README.md), roadmap item F2-09
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

- **Conceptual philosophy & vision**: [docs/PHILOSOPHY.md](docs/PHILOSOPHY.md)
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
- `CI — Microsoft Agent Framework Integration`: dedicated validation for `integrations/microsoft-agent-framework/`.
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
| F2-04 | Semantic Kernel integration | Done |
| F2-05 | CrewAI integration | Done |
| F2-06 | Public testnet deployment | Open |
| F2-07 | Formal whitepaper publication | Open |
| F2-08 | Azure AI Agent Service integration | Open |
| F2-09 | Microsoft Agent Framework integration | Done |

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

[Apache-2.0](LICENSE) — includes an explicit patent grant (Section 3) protecting all users and contributors.
