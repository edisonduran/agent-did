import { AgentIdentity } from '../src/core/AgentIdentity';
import { InMemoryNonceStore, NonceStore } from '../src/core/nonce-store';
import { LocalKeySigner } from '../src/core/signer';

// The example is a plain CommonJS file, copied by users into their services.
// eslint-disable-next-line @typescript-eslint/no-require-imports
const { createRedisNonceStore } = require('../examples/redis-nonce-store') as {
  createRedisNonceStore: (client: FakeRedis, options?: { prefix?: string }) => NonceStore;
};

/** The part of Redis the example uses: `SET key value NX EXAT t`, atomic, key gone from second `t` on. */
class FakeRedis {
  private readonly entries = new Map<string, number>();
  public failing = false;

  constructor(private readonly now: () => number) {}

  async set(key: string, _value: string, options: { NX: true; EXAT: number }): Promise<string | null> {
    if (this.failing) {
      throw new Error('ECONNREFUSED');
    }
    const expiresAt = this.entries.get(key);
    if (expiresAt !== undefined && this.now() < expiresAt) {
      return null; // NX: the key exists
    }
    this.entries.set(key, options.EXAT);
    return 'OK';
  }
}

describe('Redis NonceStore reference (sdk/examples/redis-nonce-store.js)', () => {
  let clock = 1_000;
  const redis = new FakeRedis(() => clock);

  beforeEach(() => {
    clock = 1_000;
    redis.failing = false;
  });

  const contract: Array<[string, () => NonceStore]> = [
    ['InMemoryNonceStore', () => new InMemoryNonceStore({ now: () => clock })],
    ['Redis reference', () => createRedisNonceStore(new FakeRedis(() => clock))]
  ];

  describe.each(contract)('NonceStore contract: %s', (_name, make) => {
    it('accepts a key once and refuses its replay', async () => {
      const store = make();
      await expect(store.checkAndStore('k1', 1_060)).resolves.toBe(true);
      await expect(store.checkAndStore('k1', 1_060)).resolves.toBe(false);
      await expect(store.checkAndStore('k2', 1_060)).resolves.toBe(true);
    });

    it('is atomic: of concurrent submissions of one key exactly one wins', async () => {
      const store = make();
      const results = await Promise.all(Array.from({ length: 50 }, () => store.checkAndStore('same', 1_060)));
      expect(results.filter(Boolean)).toHaveLength(1);
    });

    it('keeps the key through the second `expiresAt` inclusive, because the verifier accepts now <= expires', async () => {
      const store = make();
      await expect(store.checkAndStore('edge', 1_030)).resolves.toBe(true);
      clock = 1_030;
      await expect(store.checkAndStore('edge', 1_030)).resolves.toBe(false);
    });
  });

  it('shares state between verifier instances that share Redis', async () => {
    const instanceA = createRedisNonceStore(redis);
    const instanceB = createRedisNonceStore(redis);
    await expect(instanceA.checkAndStore('shared', 1_060)).resolves.toBe(true);
    await expect(instanceB.checkAndStore('shared', 1_060)).resolves.toBe(false);
  });

  it('forgets the key after `expiresAt`, when the verifier already refuses the request as expired', async () => {
    const store = createRedisNonceStore(redis);
    await expect(store.checkAndStore('gone', 1_030)).resolves.toBe(true);
    clock = 1_031;
    await expect(store.checkAndStore('gone', 1_030)).resolves.toBe(true);
  });

  it('uses the prefix for its keys', async () => {
    const seen: string[] = [];
    const client = { set: async (key: string) => { seen.push(key); return 'OK'; } };
    await createRedisNonceStore(client as unknown as FakeRedis, { prefix: 'svc:' }).checkAndStore('abc', 5);
    expect(seen).toEqual(['svc:abc']);
  });

  it('fails closed: a Redis error rejects instead of accepting the request', async () => {
    const store = createRedisNonceStore(redis);
    redis.failing = true;
    await expect(store.checkAndStore('x', 1_060)).rejects.toThrow('ECONNREFUSED');
  });

  it('rejects a replayed signed request across two instances sharing Redis, and a Redis outage refuses the request', async () => {
    const [signer] = LocalKeySigner.generate();
    const identity = new AgentIdentity({ controllerSigner: signer });
    const { document, agentPrivateKey } = await identity.create({ name: 'RedisBot', coreModel: 'test', systemPrompt: 'test' });
    const request = { method: 'POST', url: 'https://api.example.com/v1/data', body: '{"redis":true}' };
    const headers = await identity.signHttpRequest({ ...request, agentPrivateKey, agentDid: document.id, verificationMethodId: `${document.id}#key-1`, expiresInSeconds: 120 });

    // Real time here: the verifier uses the system clock, so Redis uses it too.
    const realRedis = new FakeRedis(() => Math.floor(Date.now() / 1000));
    const instanceA = createRedisNonceStore(realRedis);
    const instanceB = createRedisNonceStore(realRedis);

    await expect(AgentIdentity.verifyHttpRequestSignature({ ...request, headers, nonceStore: instanceA })).resolves.toBe(true);
    await expect(AgentIdentity.verifyHttpRequestSignature({ ...request, headers, nonceStore: instanceB })).resolves.toBe(false);

    const fresh = await identity.signHttpRequest({ ...request, agentPrivateKey, agentDid: document.id, verificationMethodId: `${document.id}#key-1` });
    realRedis.failing = true;
    await expect(
      AgentIdentity.verifyHttpRequestSignature({ ...request, headers: fresh, nonceStore: instanceA })
    ).rejects.toThrow('ECONNREFUSED');
  });
});
