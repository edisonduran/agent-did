import { UniversalResolverClient } from '../src/resolver/UniversalResolverClient';
import { DIDDocumentSource } from '../src/resolver/types';
import { AgentRegistry } from '../src/registry/types';
import { InMemoryDIDResolver } from '../src/resolver/InMemoryDIDResolver';
import { AgentIdentity } from '../src/core/AgentIdentity';
import { generateCanonicalDocumentHash } from '../src/crypto/hash';
import { DocumentIntegrityError, ResolverResolutionEvent } from '../src/resolver/types';
import { LocalKeySigner } from '../src/core/signer';
import { deactivateDidWebvhLog } from '../src/webvh/adapter';
import { createAgentWebvhLog, tamperLastState, TEST_CONTROLLER_KEY, textResponse } from './helpers/webvhAgentLog';

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
  const sampleDocumentRef = generateCanonicalDocumentHash(sampleDocument);

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
        documentRef: sampleDocumentRef
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
        documentRef: sampleDocumentRef
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
        documentRef: sampleDocumentRef
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
      unverifiedDocumentRefSchemes: ['ipfs'],
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
        documentRef: sampleDocumentRef
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

  describe('documentRef integrity', () => {
    const buildRegistry = (documentRef: string): AgentRegistry => ({
      register: jest.fn(),
      setDocumentReference: jest.fn(),
      revoke: jest.fn(),
      getRecord: jest.fn().mockResolvedValue({
        did: sampleDocument.id,
        controller: sampleDocument.controller,
        createdAt: '1740566400',
        documentRef
      }),
      isRevoked: jest.fn().mockResolvedValue(false)
    });

    const tamperedDocument = {
      ...sampleDocument,
      verificationMethod: [{ ...sampleDocument.verificationMethod[0], publicKeyMultibase: 'zattacker' }]
    };

    it('rejects a fetched document that does not hash to the registry documentRef', async () => {
      const resolver = new UniversalResolverClient({
        registry: buildRegistry(sampleDocumentRef),
        documentSource: { getByReference: jest.fn().mockResolvedValue(tamperedDocument) }
      });

      await expect(resolver.resolve(sampleDocument.id)).rejects.toThrow(DocumentIntegrityError);
      await expect(resolver.resolve(sampleDocument.id)).rejects.toThrow('Document integrity check failed');
    });

    it('never falls back to another source on an integrity failure', async () => {
      const fallbackResolver = new InMemoryDIDResolver();
      fallbackResolver.registerDocument(sampleDocument);
      const fallbackResolve = jest.spyOn(fallbackResolver, 'resolve');
      const events: ResolverResolutionEvent[] = [];

      const resolver = new UniversalResolverClient({
        registry: buildRegistry(sampleDocumentRef),
        documentSource: { getByReference: jest.fn().mockResolvedValue(tamperedDocument) },
        fallbackResolver,
        onResolutionEvent: (event) => events.push(event)
      });

      await expect(resolver.resolve(sampleDocument.id)).rejects.toThrow(DocumentIntegrityError);
      expect(fallbackResolve).not.toHaveBeenCalled();
      expect(events.map((event) => event.stage)).not.toContain('fallback');
      expect(events.at(-1)).toMatchObject({ stage: 'error' });
      expect(resolver.getCacheStats().size).toBe(0);
    });

    it('rejects a fetched document whose id differs from the requested DID without falling back', async () => {
      const fallbackResolver = new InMemoryDIDResolver();
      fallbackResolver.registerDocument(sampleDocument);
      const otherDocument = { ...sampleDocument, id: 'did:agent:polygon:0xother' };

      const resolver = new UniversalResolverClient({
        registry: buildRegistry(generateCanonicalDocumentHash(otherDocument)),
        documentSource: { getByReference: jest.fn().mockResolvedValue(otherDocument) },
        fallbackResolver
      });

      await expect(resolver.resolve(sampleDocument.id)).rejects.toThrow(DocumentIntegrityError);
    });

    it('rejects unverifiable documentRef schemes unless explicitly allowed', async () => {
      const resolver = new UniversalResolverClient({
        registry: buildRegistry('ipfs://bafybeigdyrztcid/example.json'),
        documentSource: { getByReference: jest.fn().mockResolvedValue(sampleDocument) }
      });

      await expect(resolver.resolve(sampleDocument.id)).rejects.toThrow('Unsupported documentRef scheme');
    });

    it('accepts allowed unverifiable schemes and reports them as unverified', async () => {
      const events: ResolverResolutionEvent[] = [];
      const resolver = new UniversalResolverClient({
        registry: buildRegistry('ipfs://bafybeigdyrztcid/example.json'),
        documentSource: { getByReference: jest.fn().mockResolvedValue(sampleDocument) },
        unverifiedDocumentRefSchemes: ['IPFS'],
        onResolutionEvent: (event) => events.push(event)
      });

      await expect(resolver.resolve(sampleDocument.id)).resolves.toMatchObject({ id: sampleDocument.id });
      expect(events.some((event) => event.message?.startsWith('integrity=unverified scheme=ipfs'))).toBe(true);
    });

    it('still falls back when the source is unavailable', async () => {
      const fallbackResolver = new InMemoryDIDResolver();
      fallbackResolver.registerDocument(sampleDocument);

      const resolver = new UniversalResolverClient({
        registry: buildRegistry(sampleDocumentRef),
        documentSource: { getByReference: jest.fn().mockRejectedValue(new Error('503 Service Unavailable')) },
        fallbackResolver
      });

      await expect(resolver.resolve(sampleDocument.id)).resolves.toMatchObject({ id: sampleDocument.id });
    });

    it('resolves documents stored through registerDocument under their canonical reference', async () => {
      const store = new Map<string, unknown>();
      const resolver = new UniversalResolverClient({
        registry: buildRegistry(sampleDocumentRef),
        documentSource: {
          getByReference: jest.fn(async (ref: string) => (store.get(ref) as typeof sampleDocument) ?? null),
          storeByReference: jest.fn(async (ref: string, document) => {
            store.set(ref, document);
          })
        },
        cacheTtlMs: 0
      });

      resolver.registerDocument(sampleDocument);
      await Promise.resolve();
      expect([...store.keys()]).toEqual([sampleDocumentRef]);
      await expect(resolver.resolve(sampleDocument.id)).resolves.toMatchObject({ id: sampleDocument.id });
    });
  });

  describe('did:webvh', () => {
    const registry = (): AgentRegistry => ({
      register: jest.fn(),
      setDocumentReference: jest.fn(),
      revoke: jest.fn(),
      getRecord: jest.fn(),
      isRevoked: jest.fn().mockResolvedValue(false)
    });
    const logSource = (log: string | null) => ({
      getByReference: jest.fn(),
      getDidLogByReference: jest.fn().mockResolvedValue(log)
    });

    it('should fetch .well-known/did.jsonl, verify it and return the signed state', async () => {
      const created = await createAgentWebvhLog('agents.example');
      const webvhDocumentSource = logSource(created.log);
      const documentSource = { getByReference: jest.fn() };
      const reg = registry();
      const resolver = new UniversalResolverClient({ registry: reg, documentSource, webvhDocumentSource });

      const resolved = await resolver.resolve(created.did);

      expect(resolved).toEqual(created.state);
      expect(reg.getRecord).not.toHaveBeenCalled();
      expect(documentSource.getByReference).not.toHaveBeenCalled();
      expect(webvhDocumentSource.getByReference).not.toHaveBeenCalled();
      expect(webvhDocumentSource.getDidLogByReference).toHaveBeenCalledWith('https://agents.example/.well-known/did.jsonl');
    });

    it('should map a port and path segments to the nested did.jsonl URL', async () => {
      const created = await createAgentWebvhLog('agents.example:8443', ['profiles', 'alice']);
      const webvhDocumentSource = logSource(created.log);
      const resolver = new UniversalResolverClient({
        registry: registry(),
        documentSource: { getByReference: jest.fn() },
        webvhDocumentSource
      });

      await expect(resolver.resolve(created.did)).resolves.toMatchObject({ id: created.did });
      expect(webvhDocumentSource.getDidLogByReference).toHaveBeenCalledWith(
        'https://agents.example:8443/profiles/alice/did.jsonl'
      );
    });

    it('should never fall back when the log fails verification', async () => {
      const created = await createAgentWebvhLog('agents.example');
      const tampered = tamperLastState(created.log, (state) => {
        state.controller = 'did:webvh:QmAttacker:attacker.example';
      });
      const fallbackResolver = new InMemoryDIDResolver();
      fallbackResolver.registerDocument(created.state as any);
      const fallbackSpy = jest.spyOn(fallbackResolver, 'resolve');
      const resolver = new UniversalResolverClient({
        registry: registry(),
        documentSource: { getByReference: jest.fn() },
        webvhDocumentSource: logSource(tampered),
        fallbackResolver
      });

      await expect(resolver.resolve(created.did)).rejects.toBeInstanceOf(DocumentIntegrityError);
      expect(fallbackSpy).not.toHaveBeenCalled();
    });

    it('should reject a valid log that belongs to another DID', async () => {
      const other = await createAgentWebvhLog('agents.example');
      const created = await createAgentWebvhLog('agents.example', ['agents', 'bot']);
      const resolver = new UniversalResolverClient({
        registry: registry(),
        documentSource: { getByReference: jest.fn() },
        webvhDocumentSource: logSource(other.log)
      });

      await expect(resolver.resolve(created.did)).rejects.toBeInstanceOf(DocumentIntegrityError);
    });

    it('should refuse a deactivated DID without falling back', async () => {
      const created = await createAgentWebvhLog('agents.example');
      const deactivated = await deactivateDidWebvhLog({ log: created.log, signer: new LocalKeySigner(TEST_CONTROLLER_KEY) });
      const fallbackResolver = new InMemoryDIDResolver();
      fallbackResolver.registerDocument(created.state as any);
      const resolver = new UniversalResolverClient({
        registry: registry(),
        documentSource: { getByReference: jest.fn() },
        webvhDocumentSource: logSource(deactivated.log),
        fallbackResolver
      });

      await expect(resolver.resolve(created.did)).rejects.toThrow(/deactivated/u);
    });

    it('should fall back only when the log is unavailable', async () => {
      const created = await createAgentWebvhLog('agents.example');
      const fallbackResolver = new InMemoryDIDResolver();
      fallbackResolver.registerDocument(created.state as any);
      const resolver = new UniversalResolverClient({
        registry: registry(),
        documentSource: { getByReference: jest.fn() },
        webvhDocumentSource: logSource(null),
        fallbackResolver
      });

      await expect(resolver.resolve(created.did)).resolves.toMatchObject({ id: created.did });
    });

    it.each([
      ['IPv4 host', 'did:webvh:QmUy89VrfryQ254CeHZzQfmcKqByPoKNGqYykP3SeXuegQ:127.0.0.1'],
      ['percent-encoded IPv4 host', 'did:webvh:QmUy89VrfryQ254CeHZzQfmcKqByPoKNGqYykP3SeXuegQ:127%2E0%2E0%2E1'],
      ['path traversal', 'did:webvh:QmUy89VrfryQ254CeHZzQfmcKqByPoKNGqYykP3SeXuegQ:example.com:..:admin'],
      ['encoded traversal', 'did:webvh:QmUy89VrfryQ254CeHZzQfmcKqByPoKNGqYykP3SeXuegQ:example.com:%2E%2E:admin'],
      ['fragment', 'did:webvh:QmUy89VrfryQ254CeHZzQfmcKqByPoKNGqYykP3SeXuegQ:example.com#x']
    ])('should reject a DID with %s before any fetch', async (_label, did) => {
      const webvhDocumentSource = logSource(null);
      const resolver = new UniversalResolverClient({
        registry: registry(),
        documentSource: { getByReference: jest.fn() },
        webvhDocumentSource,
        fallbackResolver: new InMemoryDIDResolver()
      });

      await expect(resolver.resolve(did)).rejects.toThrow(/Invalid did:webvh DID/u);
      expect(webvhDocumentSource.getDidLogByReference).not.toHaveBeenCalled();
    });

    it('should refuse a webvh source that cannot return the raw log', async () => {
      const created = await createAgentWebvhLog('agents.example');
      const resolver = new UniversalResolverClient({
        registry: registry(),
        documentSource: { getByReference: jest.fn() },
        webvhDocumentSource: { getByReference: jest.fn().mockResolvedValue(created.state) }
      });

      await expect(resolver.resolve(created.did)).rejects.toThrow(/getDidLogByReference/u);
    });

    it('should resolve through the HTTP production profile', async () => {
      const created = await createAgentWebvhLog('agents.example', ['profiles', 'weather-bot']);
      const logUrl = 'https://agents.example/profiles/weather-bot/did.jsonl';
      const fetchFn = jest.fn(async (url: string) => (url === logUrl ? textResponse(created.log) : textResponse('', 404)));

      AgentIdentity.useProductionResolverFromHttp({ registry: registry(), fetchFn });

      await expect(AgentIdentity.resolve(created.did)).resolves.toMatchObject({ id: created.did });
      expect(fetchFn).toHaveBeenCalledWith(logUrl);
    });
  });

  describe('cache bound', () => {
    const emptyRegistry = (): AgentRegistry => ({
      register: jest.fn(),
      setDocumentReference: jest.fn(),
      revoke: jest.fn(),
      getRecord: jest.fn().mockResolvedValue(null),
      isRevoked: jest.fn().mockResolvedValue(false)
    });
    const documentFor = (did: string) => ({ ...createWbaDocument(did), id: did });
    const isCached = async (resolver: UniversalResolverClient, did: string): Promise<boolean> => {
      const before = resolver.getCacheStats().hits;
      await resolver.resolve(did).catch(() => undefined);
      return resolver.getCacheStats().hits > before;
    };

    afterEach(() => {
      jest.restoreAllMocks();
    });

    it('rejects a maxCacheEntries that is not a positive integer', () => {
      const config = { registry: emptyRegistry(), documentSource: { getByReference: jest.fn() } };
      expect(() => new UniversalResolverClient({ ...config, maxCacheEntries: 0 })).toThrow(TypeError);
      expect(() => new UniversalResolverClient({ ...config, maxCacheEntries: 2.5 })).toThrow(TypeError);
    });

    it('keeps at most maxCacheEntries documents, evicting the least recently used', async () => {
      const resolver = new UniversalResolverClient({
        registry: emptyRegistry(),
        documentSource: { getByReference: jest.fn() },
        maxCacheEntries: 2
      });

      resolver.registerDocument(documentFor('did:example:a'));
      resolver.registerDocument(documentFor('did:example:b'));
      await resolver.resolve('did:example:a'); // a becomes the most recently used
      resolver.registerDocument(documentFor('did:example:c'));

      expect(resolver.getCacheStats().size).toBe(2);
      expect(await isCached(resolver, 'did:example:a')).toBe(true);
      expect(await isCached(resolver, 'did:example:c')).toBe(true);
      expect(await isCached(resolver, 'did:example:b')).toBe(false);
    });

    it('drops expired documents before evicting live ones', async () => {
      const now = jest.spyOn(Date, 'now').mockReturnValue(0);
      const resolver = new UniversalResolverClient({
        registry: emptyRegistry(),
        documentSource: { getByReference: jest.fn() },
        cacheTtlMs: 2000,
        maxCacheEntries: 2
      });

      resolver.registerDocument(documentFor('did:example:a')); // expires at 2000
      now.mockReturnValue(500);
      resolver.registerDocument(documentFor('did:example:b')); // expires at 2500
      now.mockReturnValue(1000);
      await resolver.resolve('did:example:a'); // a is now the most recently used, b the least
      now.mockReturnValue(2100);
      resolver.registerDocument(documentFor('did:example:c'));

      expect(resolver.getCacheStats().size).toBe(2);
      expect(await isCached(resolver, 'did:example:b')).toBe(true);
      expect(await isCached(resolver, 'did:example:c')).toBe(true);
    });
  });
});
