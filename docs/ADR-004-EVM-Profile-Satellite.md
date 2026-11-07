# ADR-004: Move the EVM profile to a satellite repository

- **Status:** Accepted (2026-11-07)
- **Deciders:** Maintainer
- **Applies from:** `1.0.0-rc.5`

## Context

Since ADR-001 the EVM/on-chain profile is deferred outside core `1.0`: `did:webvh` is the canonical method and the core SDKs do not depend on any chain. Until `1.0.0-rc.4` the profile still lived in this repository:

- `contracts/`: the Hardhat workspace with `AgentRegistry.sol`, deployment scripts, tests and the Slither/Mythril audit automation;
- `evm/`: the TypeScript adapter, published as `@agentdid/evm`;
- `sdk-python/src/agent_did_sdk/evm/`: the Python adapter, shipped inside `agent-did-sdk` behind the `[evm]` extra.

That kept EVM concerns in the core release: the core CI installed the contract workspace, RFC-001 conformance ran two smokes against a local Hardhat node (`smoke:e2e`, the evidence of MUST-09, and `smoke:policy`), the version check covered nine packages instead of eight, and a release of the core implied a release of the profile. An external evaluation of `1.0.0-rc.4` flagged the mix.

## Decision

Move the EVM profile, with its git history, to the separate repository `edisonduran/agent-did-evm` before the `1.0.0-rc.5` cut:

| Moved | To | Published as |
|---|---|---|
| `contracts/`, `scripts/contract-audit.js`, `.github/workflows/contract-audit.yml`, `docs/F1-05-Contract-Audit-Triage.md` | `contracts/`, `scripts/`, `.github/`, `docs/` | not published |
| `evm/` | `evm/` | npm `@agentdid/evm` |
| `agent_did_sdk.evm`, its tests, example and smokes | `python/` (package `agent_did_evm`) | PyPI `agent-did-evm` |
| `docs/RFC-001-EVM-Profile.md` | `docs/` | |

In this repository:

- `smoke:e2e` and `smoke:policy` (and their Python equivalents) are rewritten on `did:webvh`. The end-to-end smoke creates an agent, signs, verifies, revokes with a controller-signed deactivation entry and checks that the signature fails, in the revoking client and in a fresh verifier that only has the published logs. The policy smoke checks that a third party's key cannot revoke, rotate or update a DID, that a registry record alone does not revoke it, and that nothing changes it after deactivation. RFC-001 conformance keeps running both, with no Hardhat node.
- `agent-did-sdk` drops the `[evm]` extra and `web3`. `import agent_did_sdk.evm` stops working; the same classes are in `agent_did_evm`.
- `docs/RFC-001-EVM-Profile.md` becomes a pointer to the satellite.
- The release train and the version check cover the eight core packages.

## Consequences

- The core release, CI and conformance no longer depend on Hardhat, `ethers` or `web3`.
- Breaking for Python users of `agent_did_sdk.evm`: they install `agent-did-evm` and change the import (migration guide `sdk-python/MIGRATION-1.0-rc.4-to-rc.5.md`). `@agentdid/evm` keeps its name; later versions are released from the satellite.
- The satellite has its own CI (Hardhat tests, the EVM smokes, the Python adapter, the audit) and its own releases. It depends on the published core packages, never the other way round.
- Security reports for the profile follow this repository's `SECURITY.md`.
- MUST-09 and SHOULD-04 of the compliance checklist now rest on the `did:webvh` smokes; the contract-level revocation policy stays covered in the satellite.
