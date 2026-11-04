import { EthersAgentRegistryContractClient } from '../src/EthersAgentRegistryContractClient';

describe('Security Edge Cases', () => {
  describe('EthersAgentRegistryContractClient type safety', () => {
    it('should throw on invalid registry record shape', async () => {
      const mockContract = {
        getAgentRecord: jest.fn().mockResolvedValue({
          did: 123, // wrong type — should be string
          controller: 'did:ethr:0x123',
          documentRef: 'hash://sha256/test',
          active: true,
          createdAt: BigInt(1000),
          updatedAt: BigInt(2000),
        }),
      } as any;

      const client = new EthersAgentRegistryContractClient(mockContract);
      await expect(client.getAgentRecord('did:agent:polygon:0xtest')).rejects.toThrow('Invalid contract response format');
    });
  });
});
