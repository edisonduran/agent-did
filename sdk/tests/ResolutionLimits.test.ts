import { LocalKeySigner } from '../src/core/signer';
import { AgentDidClient, AgentIdentity, InMemoryAgentRegistry, UniversalResolverClient } from '../src';
import { ResolutionLimits } from '../src/resolver/types';
import { deriveDidWebvhLogUrl } from '../src/webvh/adapter';

// Parity: sdk-python/tests/test_resolution_limits.py
const realNow = Date.now.bind(Date);
let clockOffsetMs = 0;
beforeEach(() => {
  clockOffsetMs = 0;
  jest.spyOn(Date, 'now').mockImplementation(() => realNow() + clockOffsetMs);
});
afterEach(() => {
  jest.restoreAllMocks();
});

async function ownerWithAgent() {
  const owner = new AgentDidClient();
  const identity = new AgentIdentity({ controllerSigner: LocalKeySigner.generate()[0], client: owner });
  const { document } = await identity.create({ name: 'LimitsBot', coreModel: 'test', systemPrompt: 'test' });
  return { owner, did: document.id };
}

function resolverWith(getDidLogByReference: (url: string) => Promise<string | null>, limits?: ResolutionLimits) {
  return new UniversalResolverClient({
    registry: new InMemoryAgentRegistry(),
    documentSource: { getByReference: async () => null },
    webvhDocumentSource: { getByReference: async () => null, getDidLogByReference },
    resolutionLimits: limits
  });
}

describe('resolution limits of the universal resolver', () => {
  it('answers a recent failure again without fetching, until it expires', async () => {
    const source = jest.fn().mockRejectedValue(new Error('connect ETIMEDOUT'));
    const resolver = resolverWith(source, { negativeCacheTtlMs: 5_000 });
    const did = 'did:webvh:QmScid:host.example.com:agents:a';

    await expect(resolver.resolve(did)).rejects.toThrow(/could not be fetched/u);
    await expect(resolver.resolve(did)).rejects.toThrow(/could not be fetched/u);
    await expect(resolver.resolveDidWebvhLog(did)).rejects.toThrow(/could not be fetched/u);
    expect(source).toHaveBeenCalledTimes(1);

    clockOffsetMs += 5_001;
    await expect(resolver.resolve(did)).rejects.toThrow(/could not be fetched/u);
    expect(source).toHaveBeenCalledTimes(2);
  });

  it('does not remember failures when the negative cache is off', async () => {
    const source = jest.fn().mockRejectedValue(new Error('connect ETIMEDOUT'));
    const resolver = resolverWith(source, { negativeCacheTtlMs: 0 });
    const did = 'did:webvh:QmScid:host.example.com:agents:a';

    await expect(resolver.resolve(did)).rejects.toThrow();
    await expect(resolver.resolve(did)).rejects.toThrow();
    expect(source).toHaveBeenCalledTimes(2);
  });

  it('shares one fetch between concurrent resolutions of the same DID', async () => {
    const { owner, did } = await ownerWithAgent();
    const source = jest.fn(async (url: string) => (url === deriveDidWebvhLogUrl(did) ? owner.exportDidWebvhHistory(did) : null));
    const resolver = resolverWith(source);

    const documents = await Promise.all([resolver.resolve(did), resolver.resolve(did), resolver.resolveDidWebvhLog(did)]);

    expect(source).toHaveBeenCalledTimes(1);
    expect(documents[0]).toEqual(documents[1]);
    documents[0].verificationMethod.length = 0; // each caller gets its own copy
    expect(documents[1].verificationMethod.length).toBeGreaterThan(0);
  });

  it('runs at most maxConcurrentFetches fetches at once', async () => {
    let active = 0;
    let peak = 0;
    const source = async () => {
      active += 1;
      peak = Math.max(peak, active);
      await new Promise((resolve) => setTimeout(resolve, 20));
      active -= 1;
      throw new Error('not here');
    };
    const resolver = resolverWith(source, { maxConcurrentFetches: 2 });

    await Promise.allSettled(
      ['a', 'b', 'c', 'd', 'e'].map((name) => resolver.resolve(`did:webvh:QmScid:host.example.com:agents:${name}`))
    );

    expect(peak).toBe(2);
  });

  it('fetches only DIDs on allowed hosts, before any request and with no fallback', async () => {
    const source = jest.fn().mockResolvedValue(null);
    const resolver = resolverWith(source, { allowedHosts: ['trusted.example.com', '*.partner.example'] });

    await expect(resolver.resolve('did:webvh:QmScid:evil.example:agents:a')).rejects.toThrow(/not in allowedHosts/u);
    await expect(resolver.resolve('did:webvh:QmScid:partner.example:agents:a')).rejects.toThrow(/not in allowedHosts/u);
    await expect(resolver.resolve('did:wba:evil.example:agents:a')).rejects.toThrow(/not in allowedHosts/u);
    expect(source).not.toHaveBeenCalled();

    await expect(resolver.resolve('did:webvh:QmScid:trusted.example.com:agents:a')).rejects.toThrow(/not found/u);
    await expect(resolver.resolve('did:webvh:QmScid:agents.partner.example:a')).rejects.toThrow(/not found/u);
    expect(source).toHaveBeenCalledTimes(2);
  });

  it('rejects invalid limits', () => {
    expect(() => resolverWith(jest.fn(), { negativeCacheTtlMs: -1 })).toThrow(TypeError);
    expect(() => resolverWith(jest.fn(), { maxConcurrentFetches: 0 })).toThrow(TypeError);
    expect(() => resolverWith(jest.fn(), { allowedHosts: [''] })).toThrow(TypeError);
  });
});
