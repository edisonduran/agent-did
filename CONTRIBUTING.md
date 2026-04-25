# Contributing to Agent-DID

Thank you for considering contributing to Agent-DID! We are building the foundational identity layer for the AI economy, and every contribution matters.

> **Project status:** Agent-DID is an open, pre-1.0 project being built in public. The TypeScript SDK is published (`@agentdid/sdk`), the Python SDK is implemented with dedicated CI in `sdk-python/`, RFC-001 is fully conformant (11/11 MUST + 5/5 SHOULD), and the EVM smart contract is functional. See the [Roadmap](#roadmap--where-to-contribute) below for what's next.

---

## How Can I Contribute?

### 1. Review the Specification

The [RFC-001 Specification](docs/RFC-001-Agent-DID-Specification.md) is the cornerstone of the project. We welcome reviews focused on:

- Edge cases in key rotation, revocation delegation, or document evolution.
- Alignment with W3C DID Core 1.0 and related standards.
- Security considerations for production deployments.

Open an Issue tagged `[RFC]` to start a discussion.

### Public Review v1 - Open RFC Areas

During the current Public Review window, maintainers are explicitly seeking feedback on the following areas:

- The semantics and granularity of `agentMetadata.capabilities`, including whether the field should stay purely declarative or grow a stronger authorization profile.
- How `coreModelHash` and `systemPromptHash` should represent fine-tuned models, prompt templates, composite agents, and runtime composition without losing interoperability.
- Document evolution and revision semantics, including where to draw the line between update, key rotation, evolution, and delegated runtime identity.
- DID method guidance beyond the current EVM, `did:wba`, and `did:web` emphasis, including portability expectations for additional DID methods.
- Anti-replay guidance for streaming, callbacks, and multi-hop agent delegation, especially nonce-cache behavior and verifier responsibilities beyond the current SDK defaults.
- Resolver trust, persistence, and availability expectations for production deployments beyond the current in-memory and drill-oriented baseline.
- Verifiable Credential profile expectations for `complianceCertifications`, including issuer trust and interoperability constraints.

The following surfaces are treated as comparatively stable unless a correctness or security issue requires change:

- W3C DID / VC foundations and the core DID document structure.
- Ed25519 as the default signing algorithm.
- Minimal on-chain anchoring plus off-chain document reference and revocation state.
- The lifecycle primitives: create, update, rotate, revoke, resolve, verify.

### 2. Contribute Code (Pull Requests)

1. Fork the repository.
2. Create a branch from `master` (`git checkout -b feature/your-feature`).
3. Write code + tests. Ensure the relevant stack-native test workflow passes in the affected package.
4. Run conformance: `npm run conformance:rfc001` from the project root.
5. If you touch the LangChain integration, also run `npm run test:langchain` from the project root.
6. If you touch `sdk-python/`, also run the canonical Python workflow in `sdk-python/README.md`.
7. If you touch the Solidity contract or audit automation, also run `npm run audit:contracts` with Docker running.
8. If your change affects delivered status, roadmap closure, CI coverage, maturity claims, or integration scope, update all impacted live documents in the same PR.
9. Use the documentation checklist in this file when a PR changes project status, roadmap items, integration maturity, or training content.
10. Commit with a descriptive message following [Conventional Commits](https://www.conventionalcommits.org/) (e.g., `feat(sdk): add batch DID resolution`).
11. Open a Pull Request against `master`.

### 3. Improve Documentation

Docs are available in English and Spanish under `docs/`. Improvements to the specification, training materials, or runbooks are always welcome. Tag your issue or PR with `[Docs]`.

Documentation governance is defined in [docs/Documentation-Governance.md](docs/Documentation-Governance.md). Use that document as the canonical policy for live docs, sources of truth, conflict resolution, and historical labeling.

Documentation update checklist for status-changing work:

- Update the root `README.md` when project-wide status, roadmap completion, CI coverage, or available integrations change.
- Update the affected package or integration README when public capabilities, examples, runtime coverage, or installation guidance change.
- Update feature-level governance docs such as implementation checklists, review checklists, parity matrices, and maturity assessments when a roadmap item materially advances.
- Update training materials and manuals when they make claims about what is currently implemented or available.
- Update strategic assessments when shipped work changes the project positioning, main gaps, or open adoption barriers.
- Explicitly label any document as historical if the team decides not to keep it current.

### 4. Help With Current Open Tracks

If you want to contribute quickly, these are the most valuable open areas right now:

- **F1-04** Submit RFC-001 to DIF and prepare supporting review material.
- **F2-03** Build a production resolver backend beyond the current in-memory default.
- **F2-06** Deploy and document a public testnet environment.
- **F2-07** Turn the theoretical paper into a formal whitepaper package.
- **F2-08** Add Azure AI Agent Service integration with the same governance discipline used by the shipped integrations.

If you want to take ownership of one of these, open an issue titled `Proposal: F#-## - <description>` with scope, validation plan, and affected docs.

## Public Review Triage Target

During the two weeks immediately following a Public Review announcement, maintainers aim to acknowledge new issues and discussions within 48 hours.

This is a best-effort target for community responsiveness, not a contractual SLA.

---

## Roadmap — Where to Contribute

The project follows a 3-phase roadmap. Items marked with **🔓 Open** are actively seeking contributors.

### Phase 1 — Consolidation & Visibility (current)

| # | Item | Type | Status |
|---|---|---|---|
| F1-01 | Publish SDK to npm as `@agentdid/sdk` | Technical | ✅ Done |
| F1-02 | Translate README and key docs to English | Documentation | ✅ Done |
| F1-03 | **LangChain integration** — inject Agent-DID identity into agent chains | Integration | ✅ Done |
| F1-04 | **Submit RFC-001 to DIF** (Decentralized Identity Foundation) | Standards | 🔓 Open |
| F1-05 | **Automated smart contract audit** (Slither/Mythril) | Security | ✅ Done |
| F1-06 | **CI/CD pipeline** with GitHub Actions (build + test + conformance per PR) | DevOps | ✅ Done |

GitHub Actions now installs the repository workspaces and runs the RFC-001 conformance suite from `.github/workflows/ci.yml` on pushes, pull requests, and manual dispatches.

The same workflow also installs and tests the LangChain integration package in `integrations/langchain`.

Smart contract static audit automation is available through `.github/workflows/contract-audit.yml`, which runs Slither and Mythril via Docker and publishes the generated reports as workflow artifacts.

Current audit triage notes are available in [docs/F1-05-Contract-Audit-Triage.md](docs/F1-05-Contract-Audit-Triage.md). Formal third-party review is still tracked separately under F3-04.

The implemented LangChain package lives in [integrations/langchain/README.md](integrations/langchain/README.md).

### Phase 2 — Ecosystem Expansion (3-6 months)

| # | Item | Type | Status |
|---|---|---|---|
| F2-01 | **Python SDK** with feature parity | Technical | ✅ Done |
| F2-02 | **Google A2A proof-of-concept** — Agent-DID as identity layer for A2A | Integration | ✅ Done |
| F2-03 | **Production resolver** with persistent backend (IPFS/Arweave + HTTP) | Technical | 🔓 Open |
| F2-04 | **Semantic Kernel integration** | Integration | ✅ Done |
| F2-05 | **CrewAI integration** | Integration | ✅ Done |
| F2-06 | **Public testnet deployment** with documentation | Infrastructure | 🔓 Open |
| F2-07 | Publish theoretical paper as formal whitepaper | Marketing | 🔓 Open |
| F2-08 | **Azure AI Agent Service integration** | Integration | 🔓 Open |
| F2-09 | **Microsoft Agent Framework integration** | Integration | ✅ Done |

### Phase 3 — Maturity & Standardization (6-12 months)

| # | Item | Type | Status |
|---|---|---|---|
| F3-01 | Propose `did:agent` method to W3C DID WG | Standards | Planned |
| F3-02 | Conformance certification as a service | Business | Planned |
| F3-03 | ZKP for capability verification | Technical | Planned |
| F3-04 | Formal contract audit for mainnet deployment | Security | Planned |
| F3-05 | Enterprise agent platform partnerships | Business | Planned |
| F3-06 | Account Abstraction (ERC-4337) for agent wallets | Technical | Planned |

> **Want to take on an item?** Open an Issue titled `Proposal: F#-## — <description>` and we'll discuss scope and approach.

---

## Development Setup

```bash
# Clone and install
git clone https://github.com/edisonduran/agent-did.git
cd agent-did
npm install
npm --prefix sdk install
npm --prefix contracts install
npm --prefix integrations/langchain install
python -m pip install -e "./sdk-python[dev]"

# Run SDK tests
cd sdk && npm test

# Run LangChain integration tests
cd .. && npm run test:langchain

# Run contract audit automation
npm run audit:contracts

# Run full conformance
npm run conformance:rfc001

# Run Python SDK checks
cd sdk-python
python -m ruff check src/ tests/ scripts/
python -m mypy --strict src/
python -m pytest tests/ -q
```

### Requirements

- Node.js 18+
- npm
- Python 3.10+

---

## Issue Labels

When opening an issue, use one of these tags in the title:

| Tag | Use for |
|---|---|
| `[RFC]` | Specification discussions, normative changes |
| `[SDK-TS]` | TypeScript SDK bugs, features, improvements |
| `[SDK-PY]` | Python SDK bugs, features, parity, and maintenance |
| `[Contract]` | Smart contract changes, audit findings |
| `[Integration]` | Framework integrations (LangChain, CrewAI, A2A) |
| `[DevOps]` | CI/CD, testing infrastructure |
| `[Security]` | Security hardening, disclosure follow-up, audit-driven changes |
| `[Docs]` | Documentation improvements |
| `[Idea]` | New features, use cases, or research proposals |

---

## Code of Conduct

See [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) for community expectations and enforcement.

If you witness behavior that violates the Code of Conduct, report it privately to [agent.ai.did@gmail.com](mailto:agent.ai.did@gmail.com) with the subject prefix `[CODE OF CONDUCT]`.

If you need to report a security vulnerability instead, use the private workflow in [SECURITY.md](SECURITY.md) rather than opening a public issue.

---

## License

By contributing, you agree that your contributions will be licensed under the [Apache-2.0 License](LICENSE).

Thank you for helping us build the future of verifiable AI identity!
