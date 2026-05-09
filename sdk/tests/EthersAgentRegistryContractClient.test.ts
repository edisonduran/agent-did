import { EthersAgentRegistryContractClient } from '../src/registry/EthersAgentRegistryContractClient';

describe('EthersAgentRegistryContractClient', () => {
  it('should delegate write methods to the contract when available', async () => {
    const registerAgent = jest.fn().mockResolvedValue({ hash: '0x1' });
    const registerAgentWithDocument = jest.fn().mockResolvedValue({ hash: '0x2' });
    const setDocumentRef = jest.fn().mockResolvedValue({ hash: '0x3' });
    const revokeAgent = jest.fn().mockResolvedValue({ hash: '0x4' });

    const client = new EthersAgentRegistryContractClient({
      registerAgent,
      registerAgentWithDocument,
      setDocumentRef,
      revokeAgent,
    });

    await expect(client.registerAgent('did:agent:test:1', 'did:webvh:controller')).resolves.toEqual({ hash: '0x1' });
    await expect(
      client.registerAgentWithDocument('did:agent:test:1', 'did:webvh:controller', 'hash://sha256/doc')
    ).resolves.toEqual({ hash: '0x2' });
    await expect(client.setDocumentRef('did:agent:test:1', 'hash://sha256/next')).resolves.toEqual({ hash: '0x3' });
    await expect(client.revokeAgent('did:agent:test:1')).resolves.toEqual({ hash: '0x4' });

    expect(registerAgent).toHaveBeenCalledWith('did:agent:test:1', 'did:webvh:controller');
    expect(registerAgentWithDocument).toHaveBeenCalledWith(
      'did:agent:test:1',
      'did:webvh:controller',
      'hash://sha256/doc'
    );
    expect(setDocumentRef).toHaveBeenCalledWith('did:agent:test:1', 'hash://sha256/next');
    expect(revokeAgent).toHaveBeenCalledWith('did:agent:test:1');
  });

  it('should throw when a required write method is unavailable', async () => {
    const client = new EthersAgentRegistryContractClient({});

    await expect(client.registerAgent('did:agent:test:1', 'did:webvh:controller'))
      .rejects.toThrow('Contract method not available: registerAgent(did, controller)');
    await expect(client.registerAgentWithDocument('did:agent:test:1', 'did:webvh:controller', 'hash://sha256/doc'))
      .rejects.toThrow('Contract method not available: registerAgentWithDocument(did, controller, documentRef)');
    await expect(client.setDocumentRef('did:agent:test:1', 'hash://sha256/doc'))
      .rejects.toThrow('Contract method not available: setDocumentRef(did, documentRef)');
    await expect(client.revokeAgent('did:agent:test:1'))
      .rejects.toThrow('Contract method not available: revokeAgent(did)');
  });

  it('should parse tuple-like contract response into AgentRegistryRecord', async () => {
    const contract = {
      registerAgent: jest.fn(),
      setDocumentRef: jest.fn(),
      revokeAgent: jest.fn(),
      getAgentRecord: jest.fn().mockResolvedValue([
        'did:agent:polygon:0xabc',
        'did:ethr:0xcontroller',
        '1740566400',
        '',
        'hash://sha256/document-ref'
      ]),
      isRevoked: jest.fn().mockResolvedValue(false)
    };

    const client = new EthersAgentRegistryContractClient(contract);
    const record = await client.getAgentRecord('did:agent:polygon:0xabc');

    expect(record?.did).toEqual('did:agent:polygon:0xabc');
    expect(record?.controller).toEqual('did:ethr:0xcontroller');
    expect(record?.revokedAt).toBeUndefined();
    expect(record?.documentRef).toEqual('hash://sha256/document-ref');
    expect(record?.createdAt.endsWith('Z')).toBe(true);
    expect(Number.isNaN(Date.parse(record!.createdAt))).toBe(false);
  });

  it('should parse object-like contract responses and normalize stringable values', async () => {
    const contract = {
      getAgentRecord: jest.fn().mockResolvedValue({
        did: 'did:webvh:agent.example',
        controller: 'did:webvh:controller.example',
        createdAt: 1740566400,
        revokedAt: 1740567400n,
        documentRef: 12345,
      }),
    };

    const client = new EthersAgentRegistryContractClient(contract);
    const record = await client.getAgentRecord('did:webvh:agent.example');

    expect(record).toEqual({
      did: 'did:webvh:agent.example',
      controller: 'did:webvh:controller.example',
      createdAt: '2025-02-26T10:40:00.000Z',
      revokedAt: '2025-02-26T10:56:40.000Z',
      documentRef: '12345',
    });
  });

  it('should return null when the registry has no record', async () => {
    const client = new EthersAgentRegistryContractClient({
      getAgentRecord: jest.fn().mockResolvedValue(null),
    });

    await expect(client.getAgentRecord('did:webvh:missing.example')).resolves.toBeNull();
  });

  it('should throw when the contract response shape is invalid', async () => {
    const client = new EthersAgentRegistryContractClient({
      getAgentRecord: jest.fn().mockResolvedValue({ did: 123, controller: 'did:webvh:controller.example' }),
    });

    await expect(client.getAgentRecord('did:webvh:bad.example'))
      .rejects.toThrow('Invalid contract response format for getAgentRecord');
  });

  it('should fall back to revokedAt when isRevoked is not implemented', async () => {
    const client = new EthersAgentRegistryContractClient({
      getAgentRecord: jest.fn().mockResolvedValue({
        did: 'did:webvh:agent.example',
        controller: 'did:webvh:controller.example',
        createdAt: 1740566400,
        revokedAt: 1740567400,
      }),
    });

    await expect(client.isRevoked('did:webvh:agent.example')).resolves.toBe(true);
  });

  it('should use the contract isRevoked method when available', async () => {
    const isRevoked = jest.fn().mockResolvedValue(false);
    const getAgentRecord = jest.fn();
    const client = new EthersAgentRegistryContractClient({ isRevoked, getAgentRecord });

    await expect(client.isRevoked('did:webvh:agent.example')).resolves.toBe(false);
    expect(isRevoked).toHaveBeenCalledWith('did:webvh:agent.example');
    expect(getAgentRecord).not.toHaveBeenCalled();
  });
});
