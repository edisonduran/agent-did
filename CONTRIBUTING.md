# Contributing to Agent-DID

Thank you for considering contributing to Agent-DID! We are building the foundational identity layer for the AI economy, and every contribution matters.

> **Project status:** The TypeScript SDK is published (`@agent-did/sdk`), RFC-001 is fully conformant (11/11 MUST + 5/5 SHOULD), and the EVM smart contract is functional. See the [Roadmap](#roadmap--where-to-contribute) below for what's next.

---

## How Can I Contribute?

### 1. Review the Specification

The [RFC-001 Specification](docs/RFC-001-Agent-DID-Specification.md) is the cornerstone of the project. We welcome reviews focused on:

- Edge cases in key rotation, revocation delegation, or document evolution.
- Alignment with W3C DID Core 1.0 and related standards.
- Security considerations for production deployments.

Open an Issue tagged `[RFC]` to start a discussion.

### 2. Contribute Code (Pull Requests)

1. Fork the repository.
2. Create a branch from `master` (`git checkout -b feature/your-feature`).
3. Write code + tests. Ensure `npm test` passes in the relevant package.
4. Run conformance: `npm run conformance:rfc001` from the project root.
5. Commit with a descriptive message following [Conventional Commits](https://www.conventionalcommits.org/) (e.g., `feat(sdk): add batch DID resolution`).
6. Open a Pull Request against `master`.

### 3. Improve Documentation

Docs are available in English and Spanish under `docs/`. Improvements to the specification, training materials, or runbooks are always welcome. Tag your issue or PR with `[Docs]`.

---

## Roadmap — Where to Contribute

The project follows a 3-phase roadmap. Items marked with **🔓 Open** are actively seeking contributors.

### Phase 1 — Consolidation & Visibility (current)

| # | Item | Type | Status |
|---|---|---|---|
| F1-01 | Publish SDK to npm as `@agent-did/sdk` | Technical | ✅ Done |
| F1-02 | Translate all docs to English | Documentation | ✅ Done |
| F1-03 | **LangChain plugin** — inject Agent-DID identity into agent chains | Integration | 🔓 Open |
| F1-04 | **Submit RFC-001 to DIF** (Decentralized Identity Foundation) | Standards | 🔓 Open |
| F1-05 | **Automated smart contract audit** (Slither/Mythril) | Security | 🔓 Open |
| F1-06 | **CI/CD pipeline** with GitHub Actions (build + test + conformance per PR) | DevOps | ✅ Done |

GitHub Actions now installs the repository workspaces and runs the RFC-001 conformance suite from `.github/workflows/ci.yml` on pushes, pull requests, and manual dispatches.

### Phase 2 — Ecosystem Expansion (3-6 months)

| # | Item | Type | Status |
|---|---|---|---|
| F2-01 | **Python SDK** with feature parity | Technical | 🔓 Open |
| F2-02 | **Google A2A proof-of-concept** — Agent-DID as identity layer for A2A | Integration | 🔓 Open |
| F2-03 | **Production resolver** with persistent backend (IPFS/Arweave + HTTP) | Technical | 🔓 Open |
| F2-04 | **Microsoft Agent Framework (Semantic Kernel) plugin** | Integration | 🔓 Open |
| F2-05 | **CrewAI plugin** | Integration | 🔓 Open |
| F2-06 | **Public testnet deployment** with documentation | Infrastructure | 🔓 Open |
| F2-07 | Publish theoretical paper as formal whitepaper | Marketing | 🔓 Open |
| F2-08 | **Azure AI Agent Service integration** | Integration | 🔓 Open |

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
git clone https://github.com/edisonduran/Agent-citizen-identification.git
cd Agent-citizen-identification
npm install
npm --prefix sdk install
npm --prefix contracts install

# Run SDK tests
cd sdk && npm test

# Run full conformance
cd .. && npm run conformance:rfc001
```

### Requirements

- Node.js 18+
- npm

---

## Issue Labels

When opening an issue, use one of these tags in the title:

| Tag | Use for |
|---|---|
| `[RFC]` | Specification discussions, normative changes |
| `[SDK-TS]` | TypeScript SDK bugs, features, improvements |
| `[SDK-PY]` | Python SDK development (F2-01) |
| `[Contract]` | Smart contract changes, audit findings |
| `[Integration]` | Framework plugins (LangChain, CrewAI, A2A) |
| `[DevOps]` | CI/CD, testing infrastructure |
| `[Docs]` | Documentation improvements |
| `[Idea]` | New features, use cases, or research proposals |

---

## Code of Conduct

- Be welcoming and inclusive.
- Respect differing viewpoints and experiences.
- Focus on what is best for the community and the standard.

Report unacceptable behavior to the project maintainers.

---

## License

By contributing, you agree that your contributions will be licensed under the [MIT License](LICENSE).

Thank you for helping us build the future of verifiable AI identity!
