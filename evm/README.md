# @agentdid/evm

Optional EVM registry adapter for [Agent-DID](https://github.com/edisonduran/agent-did). The core `@agentdid/sdk` does not depend on it (or on `ethers`); the EVM profile stays deferred outside core 1.0 (see `docs/RFC-001-EVM-Profile.md`).

```bash
npm install @agentdid/evm @agentdid/sdk ethers
```

```ts
import { AgentDidClient } from '@agentdid/sdk';
import { EvmAgentRegistry, EthersAgentRegistryContractClient } from '@agentdid/evm';

const registry = new EvmAgentRegistry({
  contractClient: new EthersAgentRegistryContractClient(contract), // an ethers v6 Contract
  awaitTransactionConfirmation: true
});
const client = new AgentDidClient({ registry });
```

The adapter is duck-typed over the contract, so it does not import `ethers` itself. See `examples/evm-registry-wiring.ts`.
