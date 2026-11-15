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

  it('fetches again after evict or remove, even within the negative cache TTL', async () => {
    const source = jest.fn().mockRejectedValue(new Error('connect ETIMEDOUT'));
    const resolver = resolverWith(source, { negativeCacheTtlMs: 5_000 });
    const did = 'did:webvh:QmScid:host.example.com:agents:a';

    await expect(resolver.resolve(did)).rejects.toThrow(/could not be fetched/u);
    resolver.evict(did);
    await expect(resolver.resolve(did)).rejects.toThrow(/could not be fetched/u);
    resolver.remove(did);
    await expect(resolver.resolve(did)).rejects.toThrow(/could not be fetched/u);
    expect(source).toHaveBeenCalledTimes(3);
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
    expect(() => resolverWith(jest.fn(), { maxConcurrentFetchesPerHost: 0 })).toThrow(TypeError);
    expect(() => resolverWith(jest.fn(), { maxQueuedFetches: -1 })).toThrow(TypeError);
    expect(() => resolverWith(jest.fn(), { fetchDeadlineMs: 0 })).toThrow(TypeError);
  });
});

describe('fetch queue of the universal resolver', () => {
  /** A source whose fetches hang until `releaseAll` is called; tracks the peak of active fetches per host. */
  function hangingSource() {
    const pending: Array<() => void> = [];
    const active = new Map<string, number>();
    const peak = new Map<string, number>();
    const fetch = jest.fn(async (url: string): Promise<string | null> => {
      const host = new URL(url).hostname;
      active.set(host, (active.get(host) ?? 0) + 1);
      peak.set(host, Math.max(peak.get(host) ?? 0, active.get(host) ?? 0));
      await new Promise<void>((resolve) => pending.push(resolve));
      active.set(host, (active.get(host) ?? 1) - 1);
      throw new Error('connect ETIMEDOUT');
    });
    const releaseAll = async () => {
      while (pending.length > 0) {
        pending.splice(0).forEach((resolve) => resolve());
        await new Promise((resolve) => setImmediate(resolve));
      }
    };
    return { fetch, peak, releaseAll };
  }
  const flush = () => new Promise((resolve) => setImmediate(resolve));
  const settle = (promise: Promise<unknown>) => promise.then(() => undefined, (error: Error) => error);

  it('runs at most maxConcurrentFetchesPerHost fetches for one host', async () => {
    const source = hangingSource();
    const resolver = resolverWith(source.fetch, { maxConcurrentFetchesPerHost: 2 });
    const all = Promise.allSettled(
      ['a', 'b', 'c', 'd', 'e'].map((name) => resolver.resolve(`did:webvh:QmScid:slow.example:agents:${name}`))
    );
    await flush();
    expect(source.fetch).toHaveBeenCalledTimes(2);
    await source.releaseAll();
    await all;
    expect(source.peak.get('slow.example')).toBe(2);
    expect(source.fetch).toHaveBeenCalledTimes(5);
  });

  it('does not let a busy host hold up fetches for another host', async () => {
    const source = hangingSource();
    const routed = async (url: string) => (url.includes('slow.example') ? source.fetch(url) : null);
    const resolver = resolverWith(routed, { maxConcurrentFetches: 3, maxConcurrentFetchesPerHost: 2 });
    const slow = Promise.allSettled(
      ['a', 'b', 'c'].map((name) => resolver.resolve(`did:webvh:QmScid:slow.example:agents:${name}`))
    );
    await flush();
    // slow.example holds 2 slots and has one waiter; the third slot goes to another host at once.
    await expect(resolver.resolve('did:webvh:QmScid:fast.example:agents:x')).rejects.toThrow(/not found/u);
    await source.releaseAll();
    await slow;
  });

  it('refuses at once when maxQueuedFetches fetches are waiting, without remembering the refusal', async () => {
    const source = hangingSource();
    const resolver = resolverWith(source.fetch, { maxConcurrentFetches: 1, maxQueuedFetches: 1 });
    const first = settle(resolver.resolve('did:webvh:QmScid:one.example:agents:a'));
    const second = settle(resolver.resolve('did:webvh:QmScid:two.example:agents:b'));
    await flush();

    const startedAt = realNow();
    await expect(resolver.resolve('did:webvh:QmScid:three.example:agents:c')).rejects.toThrow(
      /too many DID fetches are waiting/u
    );
    expect(realNow() - startedAt).toBeLessThan(1_000);
    expect(source.fetch).toHaveBeenCalledTimes(1);

    await source.releaseAll();
    await first;
    await second;
    // The refusal was about load, not about the DID: the next resolution fetches.
    const third = settle(resolver.resolve('did:webvh:QmScid:three.example:agents:c'));
    await flush();
    await source.releaseAll();
    expect(String(await third)).toMatch(/could not be fetched/u);
    expect(source.fetch).toHaveBeenCalledTimes(3);
  });

  it('counts the time spent waiting toward fetchDeadlineMs', async () => {
    const source = hangingSource();
    const resolver = resolverWith(source.fetch, { maxConcurrentFetches: 1, fetchDeadlineMs: 100 });
    const first = settle(resolver.resolve('did:webvh:QmScid:one.example:agents:a'));
    const startedAt = realNow();
    await expect(resolver.resolve('did:webvh:QmScid:two.example:agents:b')).rejects.toThrow(
      /no fetch slot freed up within 100 ms/u
    );
    expect(realNow() - startedAt).toBeLessThan(1_000);
    expect(String(await first)).toMatch(/did not finish within 100 ms/u);
    await source.releaseAll();
  });

  it('fails a fetch that outlives fetchDeadlineMs, remembers it, and keeps the slot until the fetch settles', async () => {
    const source = hangingSource();
    const resolver = resolverWith(source.fetch, { maxConcurrentFetches: 1, maxQueuedFetches: 0, fetchDeadlineMs: 50 });
    const did = 'did:webvh:QmScid:slow.example:agents:a';
    await expect(resolver.resolve(did)).rejects.toThrow(/did not finish within 50 ms/u);
    await expect(resolver.resolve(did)).rejects.toThrow(/did not finish within 50 ms/u); // negative cache
    // The hung fetch still holds the only slot, and nothing may wait.
    await expect(resolver.resolve('did:webvh:QmScid:other.example:agents:b')).rejects.toThrow(/too many DID fetches/u);
    expect(source.fetch).toHaveBeenCalledTimes(1);
    await source.releaseAll();
    await flush();
    await expect(resolver.resolve('did:webvh:QmScid:other.example:agents:b')).rejects.toThrow(/did not finish/u);
    await source.releaseAll();
  });

  it('keeps a legitimate resolution fast while many fetches to one unresponsive host are pending', async () => {
    const source = hangingSource();
    const routed = async (url: string) => (url.includes('attacker.example') ? source.fetch(url) : null);
    const resolver = resolverWith(routed);
    const attack = Array.from({ length: 160 }, (_, i) =>
      settle(resolver.resolve(`did:webvh:QmScid:attacker.example:agents:n${i}`))
    );
    await flush();

    const startedAt = realNow();
    await expect(resolver.resolve('did:webvh:QmScid:partner.example:agents:a')).rejects.toThrow(/not found/u);
    expect(realNow() - startedAt).toBeLessThan(1_000);
    expect(source.fetch).toHaveBeenCalledTimes(4); // DEFAULT_MAX_CONCURRENT_FETCHES_PER_HOST

    // 4 fetches run and 64 wait (DEFAULT_MAX_QUEUED_FETCHES); the other 92 were refused at once.
    const refused = (await Promise.all(attack.slice(68))) as Error[];
    expect(refused).toHaveLength(92);
    refused.forEach((error) => expect(error.message).toMatch(/too many DID fetches are waiting/u));
    await source.releaseAll();
    await Promise.all(attack);
  });
});
