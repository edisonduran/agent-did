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

## Running Locally

### Requirements

- Node.js 18+
- npm

### Installation

```bash
npm install
npm --prefix sdk install
npm --prefix contracts install
```

### Recommended Quick Verification

```bash
npm run conformance:rfc001
```

This command runs SDK build/tests and operational smokes (policy, HA, RPC, E2E).

## Key Documentation

- Main specification: [docs/RFC-001-Agent-DID-Specification.md](docs/RFC-001-Agent-DID-Specification.md)
- Compliance checklist: [docs/RFC-001-Compliance-Checklist.md](docs/RFC-001-Compliance-Checklist.md)
- Implementation backlog: [docs/RFC-001-Implementation-Backlog.md](docs/RFC-001-Implementation-Backlog.md)
- Resolver HA runbook: [docs/RFC-001-Resolver-HA-Runbook.md](docs/RFC-001-Resolver-HA-Runbook.md)
- Complete SDK course (7 modules, Spanish): [docs/Curso-Completo-Agent-DID-SDK-ES.md](docs/Curso-Completo-Agent-DID-SDK-ES.md)
- Complete SDK course (7 modules, English): [docs/Curso-Completo-Agent-DID-SDK-EN.md](docs/Curso-Completo-Agent-DID-SDK-EN.md)
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
| F1-01 | Publish SDK to npm (`@agent-did/sdk`) | Open |
| F1-02 | Translate all docs to English | Partial |
| F1-03 | LangChain plugin for Agent-DID identity | Open |
| F1-04 | Submit RFC-001 to DIF | Open |
| F1-05 | Automated smart contract audit (Slither/Mythril) | Open |
| F1-06 | CI/CD pipeline with GitHub Actions | Open |

### Phase 2 — Ecosystem Expansion (3-6 months)

| # | Item | Status |
|---|---|---|
| F2-01 | Python SDK with feature parity | Open |
| F2-02 | Google A2A proof-of-concept | Open |
| F2-03 | Production resolver (IPFS/Arweave + HTTP) | Open |
| F2-04 | Microsoft Agent Framework (Semantic Kernel) plugin | Open |
| F2-05 | CrewAI plugin | Open |
| F2-06 | Public testnet deployment | Open |
| F2-07 | Formal whitepaper publication | Open |
| F2-08 | Azure AI Agent Service integration | Open |

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
