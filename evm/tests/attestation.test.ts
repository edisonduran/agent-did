import { ethers } from 'ethers';
import {
  REGISTRATION_ATTESTATION_TYPES,
  registrationAttestationDomain,
  registrationAttestationMessage
} from '../src';

describe('registration attestation typed data', () => {
  it('matches the REGISTRATION_TYPEHASH string in AgentRegistry.sol', () => {
    const encoded = ethers.TypedDataEncoder
      .from(REGISTRATION_ATTESTATION_TYPES)
      .encodeType('Registration');

    expect(encoded).toBe(
      'Registration(string did,string controller,string documentRef,address owner,uint256 deadline)'
    );
  });

  it('builds the domain and message the contract verifies', async () => {
    const registrar = ethers.Wallet.createRandom();
    const domain = registrationAttestationDomain(31337, '0x0000000000000000000000000000000000000abc');
    const message = registrationAttestationMessage(
      { did: 'did:agent:polygon:0x1', controller: 'did:ethr:0xabc' },
      '0x0000000000000000000000000000000000000001',
      1700000000
    );

    expect(domain).toEqual({
      name: 'AgentRegistry',
      version: '1',
      chainId: 31337,
      verifyingContract: '0x0000000000000000000000000000000000000abc'
    });
    expect(message.documentRef).toBe('');

    const signature = await registrar.signTypedData(
      domain,
      REGISTRATION_ATTESTATION_TYPES,
      message
    );
    const digest = ethers.TypedDataEncoder.hash(
      domain,
      REGISTRATION_ATTESTATION_TYPES,
      message
    );
    expect(ethers.recoverAddress(digest, signature)).toBe(registrar.address);
  });
});
