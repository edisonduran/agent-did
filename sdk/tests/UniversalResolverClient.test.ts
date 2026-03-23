import { UniversalResolverClient } from '../src/resolver/UniversalResolverClient';
import { DIDDocumentSource } from '../src/resolver/types';
import { AgentRegistry } from '../src/registry/types';
import { InMemoryDIDResolver } from '../src/resolver/InMemoryDIDResolver';
import { AgentIdentity } from '../src/core/AgentIdentity';

describe('UniversalResolverClient', () => {
  const sampleDocument = {
    '@context': ['https://www.w3.org/ns/did/v1', 'https://agent-did.org/v1'],
    id: 'did:agent:polygon:0xabc',
    controller: 'did:ethr:0xcontroller',
    created: '2026-01-01T00:00:00Z',
    updated: '2026-01-01T00:00:00Z',
    agentMetadata: {
      name: 'UniversalResolverBot',
      version: '1.0.0',
      coreModelHash: 'hash://sha256/model',
      systemPromptHash: 'hash://sha256/prompt'
    },
    verificationMethod: [
      {
        id: 'did:agent:polygon:0xabc#key-1',
        type: 'Ed25519VerificationKey2020',
        controller: 'did:ethr:0xcontroller',
        publicKeyMultibase: 'zabc'
      }
    ],
    authentication: ['did:agent:polygon:0xabc#key-1']
  };

  const createWbaDocument = (did: string) => ({
    ...sampleDocument,
    id: did,
    verificationMethod: [
      {
        ...sampleDocument.verificationMethod[0],
        id: `${did}#key-1`
      }
    ],
    authentication: [`${did}#key-1`]
  });

  it('should resolve via registry + source and use cache on repeated calls', async () => {
    const registry: AgentRegistry = {
      register: jest.fn(),
      setDocumentReference: jest.fn(),
      revoke: jest.fn(),
      getRecord: jest.fn().mockResolvedValue({
        did: sampleDocument.id,
        controller: sampleDocument.controller,
        createdAt: '1740566400',
        documentRef: 'hash://sha256/doc-ref'
      }),
      isRevoked: jest.fn().mockResolvedValue(false)
    };

    const source: DIDDocumentSource = {
      getByReference: jest.fn().mockResolvedValue(sampleDocument)
    };

    const resolver = new UniversalResolverClient({
      registry,
      documentSource: source,
      cacheTtlMs: 60_000
    });

    const first = await resolver.resolve(sampleDocument.id);
    const second = await resolver.resolve(sampleDocument.id);

    expect(first.id).toEqual(sampleDocument.id);
    expect(second.id).toEqual(sampleDocument.id);
    expect(registry.getRecord).toHaveBeenCalledTimes(1);
    expect(source.getByReference).toHaveBeenCalledTimes(1);

    const stats = resolver.getCacheStats();
    expect(stats.hits).toBe(1);
    expect(stats.misses).toBe(1);
  });

  it('should fallback when registry has no documentRef', async () => {
    const fallbackResolver = new InMemoryDIDResolver();
    fallbackResolver.registerDocument(sampleDocument);

    const registry: AgentRegistry = {
      register: jest.fn(),
      setDocumentReference: jest.fn(),
      revoke: jest.fn(),
      getRecord: jest.fn().mockResolvedValue({
        did: sampleDocument.id,
        controller: sampleDocument.controller,
        createdAt: '1740566400'
      }),
      isRevoked: jest.fn().mockResolvedValue(false)
    };

    const source: DIDDocumentSource = {
      getByReference: jest.fn().mockResolvedValue(null)
    };

    const resolver = new UniversalResolverClient({
      registry,
      documentSource: source,
      fallbackResolver
    });

    const resolved = await resolver.resolve(sampleDocument.id);
    expect(resolved.id).toEqual(sampleDocument.id);
  });

  it('should throw when no source document and no fallback are available', async () => {
    const registry: AgentRegistry = {
      register: jest.fn(),
      setDocumentReference: jest.fn(),
      revoke: jest.fn(),
      getRecord: jest.fn().mockResolvedValue({
        did: sampleDocument.id,
        controller: sampleDocument.controller,
        createdAt: '1740566400',
        documentRef: 'hash://sha256/missing-ref'
      }),
      isRevoked: jest.fn().mockResolvedValue(false)
    };

    const source: DIDDocumentSource = {
      getByReference: jest.fn().mockResolvedValue(null)
    };

    const resolver = new UniversalResolverClient({
      registry,
      documentSource: source
    });

    await expect(resolver.resolve(sampleDocument.id)).rejects.toThrow('Document not found');
  });

  it('should resolve did:wba using .well-known without registry lookup', async () => {
    const did = 'did:wba:agents.example';
    const wbaDocument = createWbaDocument(did);

    const registry: AgentRegistry = {
      register: jest.fn(),
      setDocumentReference: jest.fn(),
      revoke: jest.fn(),
      getRecord: jest.fn(),
      isRevoked: jest.fn().mockResolvedValue(false)
    };

    const source: DIDDocumentSource = {
      getByReference: jest.fn().mockResolvedValue(sampleDocument)
    };

    const wbaDocumentSource: DIDDocumentSource = {
      getByReference: jest.fn().mockResolvedValue(wbaDocument)
    };

    const resolver = new UniversalResolverClient({
      registry,
      documentSource: source,
      wbaDocumentSource
    });

    const resolved = await resolver.resolve(did);

    expect(resolved.id).toEqual(did);
    expect(registry.getRecord).not.toHaveBeenCalled();
    expect(source.getByReference).not.toHaveBeenCalled();
    expect(wbaDocumentSource.getByReference).toHaveBeenCalledWith('https://agents.example/.well-known/did.json');
  });

  it('should resolve did:wba path segments to nested did.json URL', async () => {
    const did = 'did:wba:agents.example%3A8443:profiles:alice';
    const wbaDocument = createWbaDocument(did);
    const wbaDocumentSource: DIDDocumentSource = {
      getByReference: jest.fn().mockResolvedValue(wbaDocument)
    };

    const registry: AgentRegistry = {
      register: jest.fn(),
      setDocumentReference: jest.fn(),
      revoke: jest.fn(),
      getRecord: jest.fn(),
      isRevoked: jest.fn().mockResolvedValue(false)
    };

    const resolver = new UniversalResolverClient({
      registry,
      documentSource: {
        getByReference: jest.fn().mockResolvedValue(null)
      },
      wbaDocumentSource
    });

    const resolved = await resolver.resolve(did);

    expect(resolved.id).toEqual(did);
    expect(resolver.getCacheStats().misses).toBe(1);
    expect(registry.getRecord).not.toHaveBeenCalled();
    expect(wbaDocumentSource.getByReference).toHaveBeenCalledWith('https://agents.example:8443/profiles/alice/did.json');
  });

  it('should allow AgentIdentity to use production resolver profile', async () => {
    const fallbackResolver = new InMemoryDIDResolver();
    fallbackResolver.registerDocument(sampleDocument);

    const registry: AgentRegistry = {
      register: jest.fn(),
      setDocumentReference: jest.fn(),
      revoke: jest.fn(),
      getRecord: jest.fn().mockResolvedValue({
        did: sampleDocument.id,
        controller: sampleDocument.controller,
        createdAt: '1740566400'
      }),
      isRevoked: jest.fn().mockResolvedValue(false)
    };

    const source: DIDDocumentSource = {
      getByReference: jest.fn().mockResolvedValue(null)
    };

    AgentIdentity.setResolver(fallbackResolver);
    AgentIdentity.useProductionResolver({
      registry,
      documentSource: source,
      cacheTtlMs: 10_000
    });

    const resolved = await AgentIdentity.resolve(sampleDocument.id);
    expect(resolved.id).toEqual(sampleDocument.id);
  });

  it('should resolve non-local DID using HTTP production resolver bootstrap', async () => {
    const registry: AgentRegistry = {
      register: jest.fn(),
      setDocumentReference: jest.fn(),
      revoke: jest.fn(),
      getRecord: jest.fn().mockResolvedValue({
        did: sampleDocument.id,
        controller: sampleDocument.controller,
        createdAt: '1740566400',
        documentRef: 'hash://sha256/http-ref'
      }),
      isRevoked: jest.fn().mockResolvedValue(false)
    };

    const fetchFn = jest.fn().mockResolvedValue({
      ok: true,
      status: 200,
      json: async () => sampleDocument
    });

    AgentIdentity.useProductionResolverFromHttp({
      registry,
      cacheTtlMs: 10_000,
      referenceToUrl: (ref) => `https://resolver.example/doc/${encodeURIComponent(ref)}`,
      fetchFn
    });

    const resolved = await AgentIdentity.resolve(sampleDocument.id);
    expect(resolved.id).toEqual(sampleDocument.id);
    expect(fetchFn).toHaveBeenCalledTimes(1);
  });

  it('should resolve did:wba using HTTP production resolver bootstrap fetch configuration', async () => {
    const did = 'did:wba:agents.example:profiles:weather-bot';
    const wbaDocument = createWbaDocument(did);

    const fetchFn = jest.fn().mockImplementation(async (url: string) => ({
      ok: url === 'https://agents.example/profiles/weather-bot/did.json',
      status: url === 'https://agents.example/profiles/weather-bot/did.json' ? 200 : 404,
      json: async () => (url === 'https://agents.example/profiles/weather-bot/did.json' ? wbaDocument : {})
    }));

    AgentIdentity.useProductionResolverFromHttp({
      registry: {
        register: jest.fn(),
        setDocumentReference: jest.fn(),
        revoke: jest.fn(),
        getRecord: jest.fn(),
        isRevoked: jest.fn().mockResolvedValue(false)
      },
      fetchFn
    });

    const resolved = await AgentIdentity.resolve(did);

    expect(resolved.id).toEqual(did);
    expect(fetchFn).toHaveBeenCalledWith('https://agents.example/profiles/weather-bot/did.json');
  });

  it('should emit resolver events and support HTTP endpoint failover', async () => {
    const events: string[] = [];

    const registry: AgentRegistry = {
      register: jest.fn(),
      setDocumentReference: jest.fn(),
      revoke: jest.fn(),
      getRecord: jest.fn().mockResolvedValue({
        did: sampleDocument.id,
        controller: sampleDocument.controller,
        createdAt: '1740566400',
        documentRef: 'hash://sha256/http-failover-ref'
      }),
      isRevoked: jest.fn().mockResolvedValue(false)
    };

    const fetchFn = jest
      .fn()
      .mockResolvedValueOnce({ ok: false, status: 503, json: async () => ({}) })
      .mockResolvedValueOnce({ ok: true, status: 200, json: async () => sampleDocument });

    AgentIdentity.useProductionResolverFromHttp({
      registry,
      cacheTtlMs: 10_000,
      referenceToUrls: (ref) => [
        `https://resolver-a.example/doc/${encodeURIComponent(ref)}`,
        `https://resolver-b.example/doc/${encodeURIComponent(ref)}`
      ],
      fetchFn,
      onResolutionEvent: (event) => {
        events.push(event.stage);
      }
    });

    const resolved = await AgentIdentity.resolve(sampleDocument.id);
    expect(resolved.id).toEqual(sampleDocument.id);
    expect(fetchFn).toHaveBeenCalledTimes(2);
    expect(events).toContain('cache-miss');
    expect(events).toContain('registry-lookup');
    expect(events).toContain('source-fetch');
    expect(events).toContain('source-fetched');
    expect(events).toContain('resolved');
  });

  it('should resolve non-local DID from ipfs documentRef using gateway failover', async () => {
    const registry: AgentRegistry = {
      register: jest.fn(),
      setDocumentReference: jest.fn(),
      revoke: jest.fn(),
      getRecord: jest.fn().mockResolvedValue({
        did: sampleDocument.id,
        controller: sampleDocument.controller,
        createdAt: '1740566400',
        documentRef: 'ipfs://bafybeigdyrztcid/example.json'
      }),
      isRevoked: jest.fn().mockResolvedValue(false)
    };

    const fetchFn = jest
      .fn()
      .mockResolvedValueOnce({ ok: false, status: 503, json: async () => ({}) })
      .mockResolvedValueOnce({ ok: true, status: 200, json: async () => sampleDocument });

    AgentIdentity.useProductionResolverFromHttp({
      registry,
      cacheTtlMs: 10_000,
      ipfsGateways: ['https://gateway-a.example/ipfs', 'https://gateway-b.example/ipfs'],
      fetchFn
    });

    const resolved = await AgentIdentity.resolve(sampleDocument.id);
    expect(resolved.id).toEqual(sampleDocument.id);
    expect(fetchFn).toHaveBeenNthCalledWith(1, 'https://gateway-a.example/ipfs/bafybeigdyrztcid/example.json');
    expect(fetchFn).toHaveBeenNthCalledWith(2, 'https://gateway-b.example/ipfs/bafybeigdyrztcid/example.json');
  });

  it('should resolve non-local DID using JSON-RPC bootstrap with endpoint failover', async () => {
    const registry: AgentRegistry = {
      register: jest.fn(),
      setDocumentReference: jest.fn(),
      revoke: jest.fn(),
      getRecord: jest.fn().mockResolvedValue({
        did: sampleDocument.id,
        controller: sampleDocument.controller,
        createdAt: '1740566400',
        documentRef: 'hash://sha256/rpc-ref'
      }),
      isRevoked: jest.fn().mockResolvedValue(false)
    };

    const transport = jest
      .fn()
      .mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => ({ jsonrpc: '2.0', id: 1, error: { code: -32000, message: 'temporary failure' } })
      })
      .mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => ({ jsonrpc: '2.0', id: 2, result: sampleDocument })
      });

    AgentIdentity.useProductionResolverFromJsonRpc({
      registry,
      cacheTtlMs: 10_000,
      endpoints: ['https://rpc-a.example', 'https://rpc-b.example'],
      transport
    });

    const resolved = await AgentIdentity.resolve(sampleDocument.id);
    expect(resolved.id).toEqual(sampleDocument.id);
    expect(transport).toHaveBeenCalledTimes(2);
  });
});
