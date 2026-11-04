/**
 * EIP-712 definitions for the registrar attestation that `AgentRegistry.registerAgentAttested`
 * requires. The registrar signs these with its own wallet (for example ethers
 * `signer.signTypedData(domain, REGISTRATION_ATTESTATION_TYPES, message)`) after verifying,
 * off-chain, that `owner` controls the DID. This module has no ethers dependency.
 */
import { RegistrationAttestationRequest } from './evm-types';

export const REGISTRATION_ATTESTATION_TYPES: { Registration: Array<{ name: string; type: string }> } = {
  Registration: [
    { name: 'did', type: 'string' },
    { name: 'controller', type: 'string' },
    { name: 'documentRef', type: 'string' },
    { name: 'owner', type: 'address' },
    { name: 'deadline', type: 'uint256' }
  ]
};

export interface RegistrationAttestationDomain {
  name: 'AgentRegistry';
  version: '1';
  chainId: number | bigint;
  verifyingContract: string;
}

export function registrationAttestationDomain(
  chainId: number | bigint,
  verifyingContract: string
): RegistrationAttestationDomain {
  return { name: 'AgentRegistry', version: '1', chainId, verifyingContract };
}

/** The typed-data message the registrar signs. */
export function registrationAttestationMessage(
  request: RegistrationAttestationRequest,
  owner: string,
  deadline: number | bigint
): { did: string; controller: string; documentRef: string; owner: string; deadline: number | bigint } {
  return {
    did: request.did,
    controller: request.controller,
    documentRef: request.documentRef ?? '',
    owner,
    deadline
  };
}
