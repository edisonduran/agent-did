import { JsonRpcDIDDocumentSource } from '../src/resolver/JsonRpcDIDDocumentSource';

describe('JsonRpcDIDDocumentSource', () => {
  const sampleDocument = {
    '@context': ['https://www.w3.org/ns/did/v1', 'https://agent-did.org/v1'],
    id: 'did:agent:polygon:0xrpc',
    controller: 'did:ethr:0xcontroller',
    created: '2026-01-01T00:00:00.000Z',
    updated: '2026-01-01T00:00:00.000Z',
    agentMetadata: {
      name: 'RpcResolverBot',
      version: '1.0.0',
      coreModelHash: 'hash://sha256/model',
      systemPromptHash: 'hash://sha256/prompt'
    },
    verificationMethod: [
      {
        id: 'did:agent:polygon:0xrpc#key-1',
        type: 'Ed25519VerificationKey2020',
        controller: 'did:ethr:0xcontroller',
        publicKeyMultibase: 'zabc'
      }
    ],
    authentication: ['did:agent:polygon:0xrpc#key-1']
  };

  it('should resolve document from json-rpc endpoint', async () => {
    const transport = jest.fn().mockResolvedValue({
      ok: true,
      status: 200,
      json: async () => ({ jsonrpc: '2.0', id: 1, result: sampleDocument })
    });

    const source = new JsonRpcDIDDocumentSource({
      endpoint: 'https://rpc-a.example',
      transport
    });

    const result = await source.getByReference('hash://sha256/ref');
    expect(result?.id).toEqual(sampleDocument.id);
    expect(transport).toHaveBeenCalledTimes(1);
  });

  it('should fail over across json-rpc endpoints until success', async () => {
    const transport = jest
      .fn()
      .mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => ({ jsonrpc: '2.0', id: 1, error: { code: -32000, message: 'backend down' } })
      })
      .mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => ({ jsonrpc: '2.0', id: 2, result: sampleDocument })
      });

    const source = new JsonRpcDIDDocumentSource({
      endpoints: ['https://rpc-a.example', 'https://rpc-b.example'],
      transport
    });

    const result = await source.getByReference('hash://sha256/ref');
    expect(result?.id).toEqual(sampleDocument.id);
    expect(transport).toHaveBeenCalledTimes(2);
  });

  it('should return null when all endpoints report not found', async () => {
    const transport = jest
      .fn()
      .mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => ({ jsonrpc: '2.0', id: 1, error: { code: -32004, message: 'not found' } })
      })
      .mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => ({ jsonrpc: '2.0', id: 2, error: { code: 404, message: 'not found' } })
      });

    const source = new JsonRpcDIDDocumentSource({
      endpoints: ['https://rpc-a.example', 'https://rpc-b.example'],
      transport
    });

    const result = await source.getByReference('hash://sha256/missing');
    expect(result).toBeNull();
  });

  it('should throw when all endpoints fail unexpectedly', async () => {
    const transport = jest
      .fn()
      .mockResolvedValueOnce({
        ok: false,
        status: 502,
        json: async () => ({})
      })
      .mockRejectedValueOnce(new Error('timeout'));

    const source = new JsonRpcDIDDocumentSource({
      endpoints: ['https://rpc-a.example', 'https://rpc-b.example'],
      transport
    });

    await expect(source.getByReference('hash://sha256/failure')).rejects.toThrow(
      'Failed to resolve DID document via JSON-RPC endpoints'
    );
  });

  it('treats an endpoint blocked by policy as an error, not as a missing document', async () => {
    const transport = jest.fn();
    const onlyBlocked = new JsonRpcDIDDocumentSource({ endpoints: ['file:///etc/passwd', 'http://10.0.0.5/rpc'], transport });

    await expect(onlyBlocked.getByReference('hash://sha256/abc')).rejects.toThrow(
      'Failed to resolve DID document via JSON-RPC endpoints'
    );
    expect(transport).not.toHaveBeenCalled();
  });

  it('treats a blocked endpoint next to one answering not found as an error', async () => {
    const transport = jest.fn().mockResolvedValue({
      ok: true,
      status: 200,
      json: async () => ({ jsonrpc: '2.0', id: 1, error: { code: 404, message: 'not found' } })
    });
    const source = new JsonRpcDIDDocumentSource({ endpoints: ['http://10.0.0.5/rpc', 'https://rpc-a.example'], transport });

    await expect(source.getByReference('hash://sha256/abc')).rejects.toThrow('http://10.0.0.5/rpc: blocked by SSRF policy');
  });
});
