import { AgentRegistryRecord } from '@agentdid/sdk';
import { EvmAgentRegistryContract, EvmTxResponse, RegistrationAttestation } from './evm-types';
import { normalizeTimestampToIso } from '@agentdid/sdk';

function safeStr(v: unknown): string {
  if (v === null || v === undefined) return '';
  if (typeof v === 'string') return v;
  if (typeof v === 'number' || typeof v === 'bigint') return v.toString();
  return '';
}

interface EthersLikeContract {
  registerAgentAttested?: (
    did: string,
    controller: string,
    documentRef: string,
    attestation: RegistrationAttestation
  ) => Promise<EvmTxResponse | void>;
  setDocumentRef?: (did: string, documentRef: string) => Promise<EvmTxResponse | void>;
  revokeAgent?: (did: string) => Promise<EvmTxResponse | void>;
  getAgentRecord?: (did: string) => Promise<AgentRegistryRecord | null>;
  isRevoked?: (did: string) => Promise<boolean>;
}

export class EthersAgentRegistryContractClient implements EvmAgentRegistryContract {
  private readonly contract: EthersLikeContract;

  constructor(contract: EthersLikeContract) {
    this.contract = contract;
  }

  public async registerAgentAttested(
    did: string,
    controller: string,
    documentRef: string,
    attestation: RegistrationAttestation
  ): Promise<EvmTxResponse | void> {
    if (!this.contract.registerAgentAttested) {
      throw new Error('Contract method not available: registerAgentAttested(did, controller, documentRef, attestation)');
    }

    return this.contract.registerAgentAttested(did, controller, documentRef, attestation);
  }

  public async setDocumentRef(did: string, documentRef: string): Promise<EvmTxResponse | void> {
    if (!this.contract.setDocumentRef) {
      throw new Error('Contract method not available: setDocumentRef(did, documentRef)');
    }

    return this.contract.setDocumentRef(did, documentRef);
  }

  public async revokeAgent(did: string): Promise<EvmTxResponse | void> {
    if (!this.contract.revokeAgent) {
      throw new Error('Contract method not available: revokeAgent(did)');
    }

    return this.contract.revokeAgent(did);
  }

  public async getAgentRecord(did: string): Promise<AgentRegistryRecord | null> {
    if (!this.contract.getAgentRecord) {
      throw new Error('Contract method not available: getAgentRecord(did)');
    }

    const rawRecord = await this.contract.getAgentRecord(did);

    if (!rawRecord) {
      return null;
    }

    if (Array.isArray(rawRecord)) {
      const [recordDid, controller, createdAt, revokedAt, documentRef] = rawRecord;
      return {
        did: safeStr(recordDid),
        controller: safeStr(controller),
        createdAt: normalizeTimestampToIso(safeStr(createdAt)) || safeStr(createdAt),
        revokedAt: normalizeTimestampToIso(safeStr(revokedAt)),
        documentRef: safeStr(documentRef) || undefined
      };
    }

    const record = rawRecord as unknown as Record<string, unknown>;
    if (
      record &&
      typeof record === 'object' &&
      typeof record.did === 'string' &&
      typeof record.controller === 'string'
    ) {
      return {
        did: record.did,
        controller: record.controller,
        createdAt: normalizeTimestampToIso(safeStr(record.createdAt))
          || safeStr(record.createdAt),
        revokedAt: normalizeTimestampToIso(safeStr(record.revokedAt)),
        documentRef: record.documentRef ? safeStr(record.documentRef) : undefined
      };
    }

    throw new Error(`Invalid contract response format for getAgentRecord`);
  }

  public async isRevoked(did: string): Promise<boolean> {
    if (!this.contract.isRevoked) {
      const record = await this.getAgentRecord(did);
      return Boolean(record?.revokedAt);
    }

    return this.contract.isRevoked(did);
  }
}
