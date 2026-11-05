import { EvmAgentRegistry } from '../src/EvmAgentRegistry';
import { EvmAgentRegistryContract } from '../src/evm-types';

describe('EvmAgentRegistry Adapter', () => {
  const attestation = { owner: '0x0000000000000000000000000000000000000001', deadline: 1700000000, signature: '0xsig' };

  it('should register with the provided attestation and await tx confirmation by default', async () => {
    const wait = jest.fn().mockResolvedValue(undefined);
    const registerAgentAttested = jest.fn().mockResolvedValue({ wait });
    const attestationProvider = jest.fn().mockResolvedValue(attestation);

    const contractClient: EvmAgentRegistryContract = {
      registerAgentAttested,
      setDocumentRef: jest.fn().mockResolvedValue({ wait }),
      revokeAgent: jest.fn().mockResolvedValue(undefined),
      getAgentRecord: jest.fn().mockResolvedValue(null)
    };

    const registry = new EvmAgentRegistry({ contractClient, attestationProvider });
    await registry.register('did:agent:polygon:0x1', 'did:ethr:0xabc', 'hash://sha256/test');

    expect(attestationProvider).toHaveBeenCalledWith({
      did: 'did:agent:polygon:0x1',
      controller: 'did:ethr:0xabc',
      documentRef: 'hash://sha256/test'
    });
    expect(registerAgentAttested).toHaveBeenCalledWith(
      'did:agent:polygon:0x1', 'did:ethr:0xabc', 'hash://sha256/test', attestation
    );
    expect(wait).toHaveBeenCalled();
  });

  it('should register without documentRef using an empty string', async () => {
    const registerAgentAttested = jest.fn().mockResolvedValue(undefined);
    const registry = new EvmAgentRegistry({
      contractClient: {
        registerAgentAttested,
        setDocumentRef: jest.fn(),
        revokeAgent: jest.fn(),
        getAgentRecord: jest.fn().mockResolvedValue(null)
      },
      attestationProvider: async () => attestation
    });

    await registry.register('did:agent:polygon:0x3', 'did:ethr:0xabc');

    expect(registerAgentAttested).toHaveBeenCalledWith('did:agent:polygon:0x3', 'did:ethr:0xabc', '', attestation);
  });

  it('should refuse to register without an attestationProvider and not touch the contract', async () => {
    const registerAgentAttested = jest.fn();
    const registry = new EvmAgentRegistry({
      contractClient: {
        registerAgentAttested,
        setDocumentRef: jest.fn(),
        revokeAgent: jest.fn(),
        getAgentRecord: jest.fn().mockResolvedValue(null)
      }
    });

    await expect(registry.register('did:agent:polygon:0x4', 'did:ethr:0xabc')).rejects.toThrow('attestationProvider');
    expect(registerAgentAttested).not.toHaveBeenCalled();
  });

  it('should resolve revocation state from getAgentRecord when isRevoked is not provided', async () => {
    const contractClient: EvmAgentRegistryContract = {
      registerAgentAttested: jest.fn().mockResolvedValue(undefined),
      setDocumentRef: jest.fn().mockResolvedValue(undefined),
      revokeAgent: jest.fn().mockResolvedValue(undefined),
      getAgentRecord: jest.fn().mockResolvedValue({
        did: 'did:agent:polygon:0x2',
        controller: 'did:ethr:0xdef',
        createdAt: new Date().toISOString(),
        revokedAt: new Date().toISOString()
      })
    };

    const registry = new EvmAgentRegistry({ contractClient });
    const isRevoked = await registry.isRevoked('did:agent:polygon:0x2');

    expect(isRevoked).toBe(true);
  });

  it('should call setDocumentReference explicitly', async () => {
    const setDocumentRef = jest.fn().mockResolvedValue(undefined);
    const contractClient: EvmAgentRegistryContract = {
      registerAgentAttested: jest.fn().mockResolvedValue(undefined),
      setDocumentRef,
      revokeAgent: jest.fn().mockResolvedValue(undefined),
      getAgentRecord: jest.fn().mockResolvedValue(null)
    };

    const registry = new EvmAgentRegistry({ contractClient });
    await registry.setDocumentReference('did:agent:polygon:0x9', 'hash://sha256/abc');

    expect(setDocumentRef).toHaveBeenCalledWith('did:agent:polygon:0x9', 'hash://sha256/abc');
  });
});
