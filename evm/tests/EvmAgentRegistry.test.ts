import { EvmAgentRegistry } from '../src/EvmAgentRegistry';
import { EvmAgentRegistryContract } from '../src/evm-types';

describe('EvmAgentRegistry Adapter', () => {
  it('should call registerAgent and await tx confirmation by default', async () => {
    const wait = jest.fn().mockResolvedValue(undefined);
    const registerAgent = jest.fn().mockResolvedValue({ wait });
    const setDocumentRef = jest.fn().mockResolvedValue({ wait });

    const contractClient: EvmAgentRegistryContract = {
      registerAgent,
      setDocumentRef,
      revokeAgent: jest.fn().mockResolvedValue(undefined),
      getAgentRecord: jest.fn().mockResolvedValue(null)
    };

    const registry = new EvmAgentRegistry({ contractClient });
    await registry.register('did:agent:polygon:0x1', 'did:ethr:0xabc', 'hash://sha256/test');

    expect(registerAgent).toHaveBeenCalledWith('did:agent:polygon:0x1', 'did:ethr:0xabc');
    expect(setDocumentRef).toHaveBeenCalledWith('did:agent:polygon:0x1', 'hash://sha256/test');
    expect(wait).toHaveBeenCalled();
  });

  it('should resolve revocation state from getAgentRecord when isRevoked is not provided', async () => {
    const contractClient: EvmAgentRegistryContract = {
      registerAgent: jest.fn().mockResolvedValue(undefined),
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
      registerAgent: jest.fn().mockResolvedValue(undefined),
      setDocumentRef,
      revokeAgent: jest.fn().mockResolvedValue(undefined),
      getAgentRecord: jest.fn().mockResolvedValue(null)
    };

    const registry = new EvmAgentRegistry({ contractClient });
    await registry.setDocumentReference('did:agent:polygon:0x9', 'hash://sha256/abc');

    expect(setDocumentRef).toHaveBeenCalledWith('did:agent:polygon:0x9', 'hash://sha256/abc');
  });
});
