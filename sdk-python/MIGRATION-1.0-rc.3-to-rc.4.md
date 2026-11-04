# agent-did-sdk Migration Guide: 1.0.0rc3 -> 1.0.0rc4

Breaking changes between `1.0.0rc3` and `1.0.0rc4`. There are no wire-format changes for the canonical `did:webvh` profile.

## 1. The controller is an Ed25519 `AgentSigner`

```python
# rc3
identity = AgentIdentity(AgentIdentityConfig(signer_address="0x..."))

# rc4
from agent_did_sdk import AgentIdentity, AgentIdentityConfig, LocalKeySigner
identity = AgentIdentity(AgentIdentityConfig(controller_signer=LocalKeySigner(ed25519_private_key_hex)))
```

- `controller_signer` is any `AgentSigner` (KMS/HSM-backed in production). Its public key identifies the creator as `did:key:z6Mk…` (`did_key_from_public_key`).
- `AgentDidClient.create_agent(signer_address, ...)` is now `create_agent(controller_signer, ...)`.
- The implicit local bootstrap controller is keyed by the creator's `did:key`.

## 2. Legacy `did:agent` profile

- `controller` is the creator's `did:key` (was `did:ethr:<address>`).
- The identifier is `did:agent:<network>:<sha256 hex>` (was Keccak-256 hex).
- `blockchainAccountId` is no longer generated.

## 3. EVM adapter moved to `agent_did_sdk.evm`

```bash
pip install "agent-did-sdk[evm]"
```

```python
# rc3
from agent_did_sdk import EvmAgentRegistry, Web3AgentRegistryContractClient
from agent_did_sdk.registry.evm_types import EvmAgentRegistryAdapterConfig
# rc4
from agent_did_sdk.evm import EvmAgentRegistry, EvmAgentRegistryAdapterConfig, Web3AgentRegistryContractClient
```

`web3` and `eth_utils` are no longer core dependencies.
