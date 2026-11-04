import { AgentRegistryRecord } from '@agentdid/sdk';

export interface EvmTxResponse {
  wait?: () => Promise<unknown>;
}

/** Registrar-signed authorization for one registration (see `attestation.ts`). */
export interface RegistrationAttestation {
  /** Address that becomes the record owner. */
  owner: string;
  /** Unix seconds after which the attestation is no longer accepted. */
  deadline: number | bigint;
  /** 65-byte EIP-712 signature by the contract's current registrar. */
  signature: string;
}

export interface RegistrationAttestationRequest {
  did: string;
  controller: string;
  documentRef?: string;
}

/** Obtains an attestation for a registration, typically by calling the registrar service. */
export type RegistrationAttestationProvider = (
  request: RegistrationAttestationRequest
) => Promise<RegistrationAttestation>;

export interface EvmAgentRegistryContract {
  registerAgentAttested(
    did: string,
    controller: string,
    documentRef: string,
    attestation: RegistrationAttestation
  ): Promise<EvmTxResponse | void>;
  setDocumentRef(did: string, documentRef: string): Promise<EvmTxResponse | void>;
  revokeAgent(did: string): Promise<EvmTxResponse | void>;
  getAgentRecord(did: string): Promise<AgentRegistryRecord | null>;
  isRevoked?(did: string): Promise<boolean>;
}

export interface EvmAgentRegistryAdapterConfig {
  contractClient: EvmAgentRegistryContract;
  awaitTransactionConfirmation?: boolean;
  /**
   * Required to call `register`: the contract only accepts registrations that carry a signature
   * from its registrar. Read and revoke operations work without it.
   */
  attestationProvider?: RegistrationAttestationProvider;
}
