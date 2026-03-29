import { AgentRegistryRecord } from './types';

export interface EvmTxResponse {
  wait?: () => Promise<unknown>;
}

export interface EvmAgentRegistryContract {
  registerAgent(did: string, controller: string, documentRef?: string): Promise<EvmTxResponse | void>;
  registerAgentWithDocument?(did: string, controller: string, documentRef: string): Promise<EvmTxResponse | void>;
  setDocumentRef(did: string, documentRef: string): Promise<EvmTxResponse | void>;
  revokeAgent(did: string): Promise<EvmTxResponse | void>;
  getAgentRecord(did: string): Promise<AgentRegistryRecord | null>;
  isRevoked?(did: string): Promise<boolean>;
}

export interface EvmAgentRegistryAdapterConfig {
  contractClient: EvmAgentRegistryContract;
  awaitTransactionConfirmation?: boolean;
}
