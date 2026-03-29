import { AgentRegistry, AgentRegistryRecord } from './types';
import { EvmAgentRegistryAdapterConfig, EvmAgentRegistryContract, EvmTxResponse } from './evm-types';

export class EvmAgentRegistry implements AgentRegistry {
  private readonly contractClient: EvmAgentRegistryContract;
  private readonly awaitTransactionConfirmation: boolean;

  constructor(config: EvmAgentRegistryAdapterConfig) {
    this.contractClient = config.contractClient;
    this.awaitTransactionConfirmation = config.awaitTransactionConfirmation ?? true;
  }

  public async register(did: string, controller: string, documentRef?: string): Promise<void> {
    if (documentRef && this.contractClient.registerAgentWithDocument) {
      const tx = await this.contractClient.registerAgentWithDocument(did, controller, documentRef);
      await this.waitForConfirmationIfNeeded(tx);
      return;
    }

    const tx = await this.contractClient.registerAgent(did, controller);
    await this.waitForConfirmationIfNeeded(tx);

    if (documentRef) {
      const refTx = await this.contractClient.setDocumentRef(did, documentRef);
      await this.waitForConfirmationIfNeeded(refTx);
    }
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
