import { InMemoryNonceStore } from '../src/core/nonce-store';

describe('InMemoryNonceStore', () => {
  it('accepts a key once until it expires', async () => {
    let now = 1_000;
    const store = new InMemoryNonceStore({ now: () => now });

    await expect(store.checkAndStore('k', 1_010)).resolves.toBe(true);
    await expect(store.checkAndStore('k', 1_010)).resolves.toBe(false);
    now = 1_011;
    await expect(store.checkAndStore('k', 1_020)).resolves.toBe(true);
  });

  it('purges expired entries and fails closed when full of live ones', async () => {
    let now = 1_000;
    const store = new InMemoryNonceStore({ maxEntries: 2, now: () => now });

    await expect(store.checkAndStore('a', 1_005)).resolves.toBe(true);
    await expect(store.checkAndStore('b', 1_100)).resolves.toBe(true);
    await expect(store.checkAndStore('c', 1_100)).resolves.toBe(false);
    now = 1_006;
    await expect(store.checkAndStore('c', 1_100)).resolves.toBe(true);
    expect(store.size).toBe(2);
  });
});


describe('InMemoryNonceStore scopes', () => {
  it('bounds the live entries of one keyid, so one signer cannot lock the others out', async () => {
    const store = new InMemoryNonceStore({ maxEntries: 100, maxEntriesPerScope: 2, now: () => 1_000 });

    await expect(store.checkAndStore('did:a#key-1 n1', 1_100)).resolves.toBe(true);
    await expect(store.checkAndStore('did:a#key-1 n2', 1_100)).resolves.toBe(true);
    await expect(store.checkAndStore('did:a#key-1 n3', 1_100)).resolves.toBe(false);
    await expect(store.checkAndStore('did:b#key-1 n1', 1_100)).resolves.toBe(true);
  });

  it('frees a scope when its entries expire', async () => {
    let now = 1_000;
    const store = new InMemoryNonceStore({ maxEntriesPerScope: 1, now: () => now });

    await expect(store.checkAndStore('did:a#key-1 n1', 1_005)).resolves.toBe(true);
    await expect(store.checkAndStore('did:a#key-1 n2', 1_100)).resolves.toBe(false);
    now = 1_006;
    await expect(store.checkAndStore('did:a#key-1 n2', 1_100)).resolves.toBe(true);
  });
});
