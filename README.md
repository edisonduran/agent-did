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
- Resolver HA runbook: [docs/RFC-001-Resolver-HA-Runbook.md](docs/RFC-001-Resolver-HA-Runbook.md)
- Contribution guide: [CONTRIBUTING.md](CONTRIBUTING.md)

## Roadmap

RFC-001 is implemented and conformant. Next iterations may focus on:

- New RFCs (advanced delegation, A2H approvals)
- External integrations and shared fixture adoption across implementations
- Operational/CI hardening for multi-region production environments

## License

[MIT](LICENSE)
