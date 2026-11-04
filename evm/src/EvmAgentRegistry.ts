import { AgentRegistry, AgentRegistryRecord } from '@agentdid/sdk';
import {
  EvmAgentRegistryAdapterConfig,
  EvmAgentRegistryContract,
  EvmTxResponse,
  RegistrationAttestationProvider
} from './evm-types';

export class EvmAgentRegistry implements AgentRegistry {
  private readonly contractClient: EvmAgentRegistryContract;
  private readonly awaitTransactionConfirmation: boolean;
  private readonly attestationProvider: RegistrationAttestationProvider | undefined;

  constructor(config: EvmAgentRegistryAdapterConfig) {
    this.contractClient = config.contractClient;
    this.awaitTransactionConfirmation = config.awaitTransactionConfirmation ?? true;
    this.attestationProvider = config.attestationProvider;
  }

  public async register(did: string, controller: string, documentRef?: string): Promise<void> {
    if (!this.attestationProvider) {
      throw new Error(
        'EvmAgentRegistry.register requires an attestationProvider: the contract only accepts registrar-attested registrations'
      );
    }

    const attestation = await this.attestationProvider({ did, controller, documentRef });
    const tx = await this.contractClient.registerAgentAttested(did, controller, documentRef ?? '', attestation);
    await this.waitForConfirmationIfNeeded(tx);
  }

  public async setDocumentReference(did: string, documentRef: string): Promise<void> {
    const tx = await this.contractClient.setDocumentRef(did, documentRef);
    await this.waitForConfirmationIfNeeded(tx);
  }

  public async revoke(did: string): Promise<void> {
    const tx = await this.contractClient.revokeAgent(did);
    await this.waitForConfirmationIfNeeded(tx);
  }

  public async getRecord(did: string): Promise<AgentRegistryRecord | null> {
    return this.contractClient.getAgentRecord(did);
  }

  public async isRevoked(did: string): Promise<boolean> {
    if (this.contractClient.isRevoked) {
      return this.contractClient.isRevoked(did);
    }

    const record = await this.getRecord(did);
    return Boolean(record?.revokedAt);
  }

  private async waitForConfirmationIfNeeded(tx: EvmTxResponse | void): Promise<void> {
    if (!this.awaitTransactionConfirmation) {
      return;
    }

    if (tx?.wait) {
      await tx.wait();
    }
  }
}
