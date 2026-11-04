# @agentdid/sdk Migration Guide: 1.0.0-rc.3 -> 1.0.0-rc.4

Breaking changes between `1.0.0-rc.3` and `1.0.0-rc.4`. There are no wire-format changes for the canonical `did:webvh` profile.

## 1. The controller is an Ed25519 `AgentSigner`

```ts
// rc.3
const identity = new AgentIdentity({ signer: new ethers.Wallet(key) });

// rc.4
import { AgentIdentity, LocalKeySigner } from '@agentdid/sdk';
const identity = new AgentIdentity({ controllerSigner: new LocalKeySigner(ed25519PrivateKeyHex) });
```

- `controllerSigner` is any `AgentSigner` (KMS/HSM-backed in production). Its public key identifies the creator as `did:key:z6Mk…` (`didKeyFromPublicKey`).
- An EVM key is not an Ed25519 key: generate a new controller key instead of reusing `CREATOR_PRIVATE_KEY` from an EVM wallet.
- `AgentDidClient.createAgent(controllerAddress, ...)` is now `createAgent(controllerSigner, ...)`.
- The implicit local bootstrap controller is keyed by the creator's `did:key`, so a new controller key means a new bootstrap controller DID.

## 2. Legacy `did:agent` profile

- `controller` is the creator's `did:key` (was `did:ethr:<address>`).
- The identifier is `did:agent:<network>:<sha256 hex>` (was `0x` + Keccak-256).
- `verificationMethod[].blockchainAccountId` is no longer generated. The optional field stays in the type for documents that carry a real account.

Documents created by rc.3 remain valid and resolvable; only newly created ones change.

## 3. EVM adapter moved to `@agentdid/evm`

```bash
npm install @agentdid/evm
```

```ts
// rc.3
import { EvmAgentRegistry, EthersAgentRegistryContractClient } from '@agentdid/sdk';
// rc.4
import { EvmAgentRegistry, EthersAgentRegistryContractClient } from '@agentdid/evm';
```

`@agentdid/sdk` no longer depends on `ethers`. Install `ethers` yourself if your code uses it.
