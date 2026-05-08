# Agent-DID: The Identity Layer for AI Agents

[![License: Apache-2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Node.js](https://img.shields.io/badge/node-%3E%3D18-brightgreen)](https://nodejs.org)
[![Works with LangChain](https://img.shields.io/badge/works%20with-LangChain-blue)](integrations/langchain/)
[![Works with CrewAI](https://img.shields.io/badge/works%20with-CrewAI-orange)](integrations/crewai/)
[![Works with Semantic Kernel](https://img.shields.io/badge/works%20with-Semantic%20Kernel-purple)](integrations/semantic-kernel/)
[![Works with Microsoft Agent Framework](https://img.shields.io/badge/works%20with-MS%20Agent%20Framework-lightblue)](integrations/microsoft-agent-framework/)
[![Works with Google A2A](https://img.shields.io/badge/works%20with-Google%20A2A-green)](integrations/a2a/)
[![CI — TypeScript SDK](https://github.com/edisonduran/agent-did/actions/workflows/ci.yml/badge.svg)](https://github.com/edisonduran/agent-did/actions/workflows/ci.yml)
[![CI — Python SDK](https://github.com/edisonduran/agent-did/actions/workflows/ci-python.yml/badge.svg)](https://github.com/edisonduran/agent-did/actions/workflows/ci-python.yml)
[![CI — LangChain JS](https://github.com/edisonduran/agent-did/actions/workflows/ci-langchain-js.yml/badge.svg)](https://github.com/edisonduran/agent-did/actions/workflows/ci-langchain-js.yml)
[![CI — LangChain Python](https://github.com/edisonduran/agent-did/actions/workflows/ci-langchain-python.yml/badge.svg)](https://github.com/edisonduran/agent-did/actions/workflows/ci-langchain-python.yml)
[![CI — CrewAI](https://github.com/edisonduran/agent-did/actions/workflows/ci-crewai.yml/badge.svg)](https://github.com/edisonduran/agent-did/actions/workflows/ci-crewai.yml)
[![CI — Semantic Kernel](https://github.com/edisonduran/agent-did/actions/workflows/ci-semantic-kernel.yml/badge.svg)](https://github.com/edisonduran/agent-did/actions/workflows/ci-semantic-kernel.yml)
[![CI — Microsoft Agent Framework](https://github.com/edisonduran/agent-did/actions/workflows/ci-microsoft-agent-framework.yml/badge.svg)](https://github.com/edisonduran/agent-did/actions/workflows/ci-microsoft-agent-framework.yml)
[![CI — Google A2A](https://github.com/edisonduran/agent-did/actions/workflows/ci-a2a.yml/badge.svg)](https://github.com/edisonduran/agent-did/actions/workflows/ci-a2a.yml)
[![Contract Audit](https://github.com/edisonduran/agent-did/actions/workflows/contract-audit.yml/badge.svg)](https://github.com/edisonduran/agent-did/actions/workflows/contract-audit.yml)
[![Public Review](https://img.shields.io/badge/status-public_review_v1-orange)](docs/RFC-001-Agent-DID-Specification.md)
[![Contributions Welcome](https://img.shields.io/badge/contributions-welcome-brightgreen.svg)](CONTRIBUTING.md)
[![Feedback Wanted](https://img.shields.io/badge/feedback-wanted-lightgrey)](https://github.com/edisonduran/agent-did/discussions)

> **Give your AI agents a verifiable identity — with `did:webvh` as the core deployment path.**

**Agent-DID** is an open standard and reference implementation for an application pattern on top of `did:webvh` for AI agent identity, composition, and runtime authentication. It addresses a question the AI industry still lacks a clear answer for: *when an autonomous agent acts — signs a request, delegates a task, modifies data — how does the system on the other side know who that agent really is?*

OAuth delegates this to a centralized provider. MCP leaves it out of scope by design. Agent-DID addresses it at the cryptographic layer, without introducing platform lock-in, by extending W3C DID/VC with agent-specific metadata, an A2A composition contract, and a runtime profile based on HTTP Message Signatures.

> **Interactive demo:** [Agent-DID in Action](https://edisonduran.github.io/agent-did-in-action/) shows real browser-side signed handoffs, live tamper detection, and the published `@agentdid/sdk` working across multiple use cases.

> **For contributors (Public Review):**
> - Start here: [QUICKSTART.md](QUICKSTART.md)
> - Contribution workflow: [CONTRIBUTING.md](CONTRIBUTING.md)
> - Security reporting: [SECURITY.md](SECURITY.md)
> - Docs navigation: [docs/INDEX.md](docs/INDEX.md)
> - RFC under Public Review: [docs/RFC-001-Agent-DID-Specification.md](docs/RFC-001-Agent-DID-Specification.md)
> - Compatibility expectations: [docs/DEPRECATION-POLICY.md](docs/DEPRECATION-POLICY.md)

Built on W3C DID and Verifiable Credentials, Agent-DID provides:

- **A language-agnostic specification** ([RFC-001](docs/RFC-001-Agent-DID-Specification.md)) — 11/11 MUST conformant
- **TypeScript and Python SDKs** backed by dedicated CI, interoperability fixtures, and conformance checks
- **Native integrations** for LangChain (JS + Python), CrewAI, Semantic Kernel, and Microsoft Agent Framework
- **A web-native deployment model** — `did:webvh` for canonical agent/controller identity, verifiable history, and recursive controller validation

---

## Why Agent-DID

| Problem | What Agent-DID adds |
|---|---|
| MCP, A2A, and agent frameworks do not provide portable, verifiable agent identity | A DID-based identity layer that binds controller, model and prompt fingerprints, and declared capabilities |
| Requiring blockchain for every deployment slows adoption | A `did:webvh` core path that keeps the model web-native and avoids on-chain operational overhead for 1.0 |
| Existing frameworks orchestrate behavior, not trust | Native integrations that add identity to LangChain, CrewAI, Semantic Kernel, and Microsoft Agent Framework without replacing them |
| Agent actions are hard to attribute and verify | Ed25519 signing for payloads and HTTP requests, enabling verifiable actions and audit trails |
| Revocation is inconsistent across environments | Compatible resolvers can propagate and enforce revocation state for compromised agents |

---

## Design Philosophy

### The Core Problem

AI is no longer just a tool humans use — it is becoming an actor that makes decisions, negotiates, executes code, signs operations, and delegates tasks to other agents. This transition raises a question the industry still lacks a clear answer for:

> **How does a system know who the agent talking to it really is?**

Not who created it. Not which platform it runs on. But *which specific agent*, at this moment, with this behavior, executing these actions.

OAuth delegates this to a centralized provider. MCP leaves it out of scope by design. Agent-DID addresses it at the cryptographic layer, without platform lock-in.

### Five Principles

**1. Identity is a first-class citizen of the AI stack**
Identity is not a credential bolted on at the end. It is the foundation on which trust between autonomous systems is built. Without cryptographically verifiable identity there is no real audit trail, no algorithmic accountability, no revocation system that works when something goes wrong.

**2. Method-aligned by design, flexible by deployment profile**
Agent-DID now chooses a default instead of asking every adopter to re-litigate the DID-method question. The canonical pattern is `did:webvh`: web-native, domain-bound, and compatible with verifiable history plus recursive controller validation.

Flexibility still matters, but it now lives in the **deployment profile**, not in treating every DID method as equally primary:
- Most deployments should stay web-native and publish agent/controller identity through `did:webvh`.
- Storage and delivery can still vary across HTTP, mirrored content stores, and resolver topologies.
- EVM/on-chain anchoring is deferred outside the 1.0 path and should only be revisited if a concrete need appears later.

The same standard — and the same SDK surface over time — is designed to support those profiles without losing one canonical story.

**3. Meet the developer where they are**
A standard that requires learning a new paradigm before writing the first useful line of code has a structural adoption problem. Agent-DID integrates into the frameworks developers already use — LangChain, CrewAI, Semantic Kernel, Microsoft Agent Framework — and gives them verifiable identity without abandoning their workflow.

**4. Open standards over proprietary lock-in**
Agent-DID extends W3C DID Core and the Verifiable Credentials data model. It does not define a new DID method or proprietary identity format — it extends existing identity standards with AI-specific metadata: model hash, system prompt hash, declared capabilities, evolution lifecycle. An identity ecosystem for AI agents only has value if it is interoperable. A proprietary identity format creates dependency where interoperability is needed.

**5. Verifiability without accidental complexity**
Identity cryptography is complex. AI agent developers should not have to be. Agent-DID closes that gap with framework abstractions that inject identity into the agent's execution chain without extra developer code, and with Ed25519 as the default — a fast, compact, and widely trusted cryptographic primitive for high-frequency signing environments.

### What Agent-DID Is Not

- **Not an orchestration framework.** It does not replace LangChain or CrewAI. It integrates with them.
- **Not a payment system.** ERC-4337 compatibility exists for agent wallets, but payment management is out of scope.
- **Not a blockchain mandate.** The recommended default pattern is `did:webvh`; EVM/on-chain work is deferred outside core 1.0, and other DID methods are compatibility profiles rather than co-equal defaults.
- **Not a centralized platform.** There is no Agent-DID server to connect to. The protocol and SDKs are the primary interface.

---

Documentation governance for live project status and canonical sources of truth is defined in [docs/Documentation-Governance.md](docs/Documentation-Governance.md).

## Current Status

The project is past the specification-only phase: it includes a functional implementation and a validation pipeline.

- **RFC-001** is in **Public Review v1** as `0.3-pivot-pattern-on-webvh`: [docs/RFC-001-Agent-DID-Specification.md](docs/RFC-001-Agent-DID-Specification.md)
- **Compliance checklist**: [docs/RFC-001-Compliance-Checklist.md](docs/RFC-001-Compliance-Checklist.md)
- **Current result**: MUST `11/11 PASS` and SHOULD `5/5 PASS`
- **Published SDKs**: `@agentdid/sdk` `0.2.0` on npm and `agent-did-sdk` `0.1.0` on PyPI
- **Start here**: [QUICKSTART.md](QUICKSTART.md), [SECURITY.md](SECURITY.md), [docs/INDEX.md](docs/INDEX.md), [docs/DEPRECATION-POLICY.md](docs/DEPRECATION-POLICY.md)

## Build In Public

Agent-DID is an open, pre-1.0 project being built in public.

- The core RFC lifecycle is implemented and covered by conformance checks.
- The TypeScript SDK is published as `@agentdid/sdk` and the Python SDK is published as `agent-did-sdk`.
- The `did:webvh` runtime path, validation drills, and framework integrations are functional, while release planning is being aligned around `did:webvh` as the canonical deployment story.
- Community feedback is explicitly welcome before the project reaches full production hardening.
- Public-review compatibility expectations are documented in [docs/DEPRECATION-POLICY.md](docs/DEPRECATION-POLICY.md).
- Security reporting instructions are documented in [SECURITY.md](SECURITY.md).

If you want to help shape the next stage, the highest-leverage open areas today are:

- **v1.0 scope freeze**: API freeze, migration guides, compatibility matrix, and release-critical CI cleanup
- **F2-03** production resolver hardening beyond the shipped source-adapter baseline
- **F2-07** formal whitepaper publication
- **F2-08** Azure AI Agent Service integration

See [CONTRIBUTING.md](CONTRIBUTING.md) for contribution workflow, [docs/INDEX.md](docs/INDEX.md) for documentation navigation, and [docs/RFC-001-Implementation-Backlog.md](docs/RFC-001-Implementation-Backlog.md) for the technical execution history.

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
- External `did:webvh` smoke with repo-managed public defaults: `npm run smoke:webvh-external` / `npm run python:smoke:webvh-external`
- JSON-RPC resolution smoke: `npm run smoke:rpc`
- Revocation policy smoke: `npm run smoke:policy`

## Integrations

- LangChain JS 1.x: implemented in [integrations/langchain/README.md](integrations/langchain/README.md)
- LangChain Python: functional MVP implemented in [integrations/langchain-python/README.md](integrations/langchain-python/README.md), with dedicated tests, opt-in key rotation, and hardened HTTP signing defaults
- Semantic Kernel: functional Python integration with tools, session-context helpers, middleware-style identity injection and sanitized observability in [integrations/semantic-kernel/README.md](integrations/semantic-kernel/README.md), roadmap item F2-04
- CrewAI: functional Python integration with callbacks, guardrails, structured outputs and runtime smoke coverage in [integrations/crewai/README.md](integrations/crewai/README.md), roadmap item F2-05
- Microsoft Agent Framework: functional Python integration with native `Agent`/`tool(...)` wiring, `WorkflowBuilder` helpers, advanced orchestration coverage and sanitized observability in [integrations/microsoft-agent-framework/README.md](integrations/microsoft-agent-framework/README.md), roadmap item F2-09
- Google A2A: functional Python proof-of-concept with DID-enriched AgentCards, JSON-RPC request signing, mutual DID-based authentication and sanitized observability in [integrations/a2a/README.md](integrations/a2a/README.md), roadmap item F2-02
- Azure AI Agent Service: planned roadmap item F2-08

Integrated `did:wba` demos are now available in both LangChain packages:

- LangChain JS: [integrations/langchain/examples/agentDidLangChain.didWbaDemo.example.js](integrations/langchain/examples/agentDidLangChain.didWbaDemo.example.js)
- LangChain Python: [integrations/langchain-python/examples/agent_did_langchain_did_wba_demo.py](integrations/langchain-python/examples/agent_did_langchain_did_wba_demo.py)

When these LangChain integrations change, the repository also expects the paired governance artifacts to stay current in [docs/F1-03-LangChain-TS-Python-Integration-Parity-Matrix.md](docs/F1-03-LangChain-TS-Python-Integration-Parity-Matrix.md) and [docs/F1-03-LangChain-Integration-Parity-Review-Checklist.md](docs/F1-03-LangChain-Integration-Parity-Review-Checklist.md).

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
npm run smoke:langchain-didwba
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
- LangChain `did:wba` demo walkthrough: [docs/F1-03-LangChain-didwba-Demo-Walkthrough.md](docs/F1-03-LangChain-didwba-Demo-Walkthrough.md)
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
| F1-01 | Publish TypeScript SDK to npm (`@agentdid/sdk`) | Done |
| F1-02 | Translate README and key docs to English | Done (README + course + strategic assessment) |
| F1-03 | LangChain integration for Agent-DID identity | Done |
| F1-04 | Prepare optional DIF / `did:webvh` companion-note material | Post-1.0 / optional |
| F1-05 | Automated smart contract audit (Slither/Mythril) | Done |
| F1-06 | CI/CD pipeline with GitHub Actions | Done |

The repository now includes a GitHub Actions workflow at `.github/workflows/ci.yml` that installs the root, SDK, and contract workspaces and runs `npm run conformance:rfc001` on pushes, pull requests, and manual dispatches.

LangChain JS validation runs in the dedicated workflow at `.github/workflows/ci-langchain-js.yml`, which builds `sdk/` and tests `integrations/langchain` separately from the core TypeScript/conformance pipeline.

Current CI split in GitHub Actions:

- `CI — TypeScript SDK & RFC-001 Conformance`: Node/TypeScript pipeline for the root workspace, `sdk/`, `contracts/`, and RFC-001 conformance/smoke coverage.
- `CI — LangChain JS Integration`: dedicated Node validation for `integrations/langchain/` against the local `sdk/`.
- `CI — Python SDK & RFC-001 Conformance`: Python-native quality gates for `sdk-python/`, including conformance and Python smoke coverage on the primary runtime.
- `CI — LangChain Python Integration`: dedicated validation for `integrations/langchain-python/`.
- `CI — LangChain did:wba Demo Smoke`: cross-package smoke that executes the shipped JavaScript and Python integrated demos together.
- `CI — CrewAI Integration`: dedicated validation for `integrations/crewai/`.
- `CI — Semantic Kernel Integration`: dedicated validation for `integrations/semantic-kernel/`.
- `CI — Microsoft Agent Framework Integration`: dedicated validation for `integrations/microsoft-agent-framework/`.
- `CI — Google A2A Integration`: dedicated validation for `integrations/a2a/` with DID-enriched AgentCards, JSON-RPC signing, and mutual authentication tests.
- `CI — Integration Governance`: validates the required parity/checklist artifacts that must stay aligned with supported integrations.
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
| F2-02 | Google A2A proof-of-concept | Done |
| F2-03 | Production resolver hardening beyond shipped source adapters | Post-core hardening |
| F2-04 | Semantic Kernel integration | Done |
| F2-05 | CrewAI integration | Done |
| F2-06 | EVM/on-chain profile evaluation | Deferred — revisit only if a concrete need appears |
| F2-07 | Formal whitepaper publication | Open |
| F2-08 | Azure AI Agent Service integration | Open |
| F2-09 | Microsoft Agent Framework integration | Done |

Python semantic parity is achieved: canonical `documentRef` generation, shared cross-language fixtures, and per-stack CI are all operational.

The universal resolver core is already shipped in both SDKs: cache/failover, HTTP/IPFS gateway resolution, JSON-RPC resolution, direct `did:wba` web resolution, and runtime smoke coverage are all implemented today. The remaining F2-03 scope is post-baseline hardening for operator-managed persistent backends and any additional transport targets such as Arweave.

The next Python integration track is hardening and release maturation of LangChain Python, with execution steps documented in [docs/F1-03-LangChain-Python-Implementation-Checklist.md](docs/F1-03-LangChain-Python-Implementation-Checklist.md).

### Phase 3 — Maturity & Standardization (6-12 months)

| # | Item | Status |
|---|---|---|
| F3-01 | Explore Agent-DID as a DIF / `did:webvh` companion note | Planned post-1.0 |
| F3-02 | Conformance certification service | Planned |
| F3-03 | ZKP for capability verification | Planned |
| F3-04 | Formal contract audit for mainnet | Planned |
| F3-05 | Enterprise partnerships | Planned |
| F3-06 | Account Abstraction (ERC-4337) for agent wallets | Planned |

Release 1.0 now follows the post-ADR-001 path in [docs/RELEASE-1.0-CRITERIA.md](docs/RELEASE-1.0-CRITERIA.md): core `did:webvh` stability first; EVM/on-chain work is deferred outside the core tag, and standards outreach is not a release blocker.

See [CONTRIBUTING.md](CONTRIBUTING.md) for details on how to pick up roadmap items.

## Community

### Spec co-authors

- **RFC-001 A2A Identity Composition Contract** ([`docs/RFC-001-A2A-Identity-Composition-Contract.md`](docs/RFC-001-A2A-Identity-Composition-Contract.md)) — co-drafted with [@aeoess](https://github.com/aeoess) (Tymofii Pidlisnyi, [Agent Passport System / APS](https://github.com/aeoess/agent-passport-system), IETF `draft-pidlisnyi-aps-00`). All five normative sections (§4.3, §4.4, §5, §6.3, §6.4) are APS-confirmed via direct pushes (`3fc38384`, `da473ee3`) and verified upstream-thread approval (`0e6a5d4c`). Landed on `main` via [PR #35](https://github.com/edisonduran/agent-did/pull/35) (`63bff720`).

### Contributors

Thanks to everyone who has contributed code, reviews, or design input:

- [@Ashish-KumarGupta](https://github.com/Ashish-KumarGupta) — `sdk-python/examples/`: `http_sign_verify_example.py` ([PR #32](https://github.com/edisonduran/agent-did/pull/32)) and `did_wba_http_sign_verify.py` ([PR #37](https://github.com/edisonduran/agent-did/pull/37))
- [@haroldmalikfrimpong-ops](https://github.com/haroldmalikfrimpong-ops) — design partner and reviewer for the `add_verified_handoff` Microsoft Agent Framework helper (originating thread [`microsoft/agent-framework#4842`](https://github.com/microsoft/agent-framework/issues/4842), [PR #31 review](https://github.com/edisonduran/agent-did/pull/31))
- [@mdqamarhussain](https://github.com/mdqamarhussain) — README contributor navigation block ([PR #25](https://github.com/edisonduran/agent-did/pull/25))

### Cross-ecosystem

- [Agent Passport System (APS)](https://github.com/aeoess/agent-passport-system) — Agent-DID is represented in the [`agent-governance-vocabulary` crosswalk](https://github.com/aeoess/agent-governance-vocabulary/blob/main/crosswalk/agent-did.yaml) (merged via [PR #66](https://github.com/aeoess/agent-governance-vocabulary/pull/66), commit `69393c3`).

## License

[Apache-2.0](LICENSE) — includes an explicit patent grant (Section 3) protecting all users and contributors.
