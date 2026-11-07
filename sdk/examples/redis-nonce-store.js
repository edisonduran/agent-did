/**
 * Reference `NonceStore` backed by Redis, for several verifier instances (replicas, serverless
 * functions, Kubernetes) that serve the same agents. Copy it into your service; it is not part of
 * the SDK package, so the SDK has no Redis dependency.
 *
 *   const { createClient } = require('redis');
 *   const { createRedisNonceStore } = require('./redis-nonce-store');
 *
 *   const redis = createClient({ url: process.env.REDIS_URL });
 *   await redis.connect();
 *   const nonceStore = createRedisNonceStore(redis);
 *
 *   const ok = await client.verifyHttpRequestSignature({ method, url, body, headers, nonceStore });
 *
 * Contract (see `NonceStore` in `@agentdid/sdk`):
 * - `checkAndStore(key, expiresAt)` is ATOMIC: one `SET key value NX EXAT ...`, never a GET then a SET.
 * - It resolves `true` for a key not seen before and `false` for a replay.
 * - It keeps the key through the second `expiresAt` INCLUSIVE, because the verifier accepts a
 *   request while `now <= expires`. Redis `EXAT t` removes the key at the start of second `t`, so
 *   the expiry is `expiresAt + 1`. With `EXAT expiresAt` a request replayed in the last second of
 *   its life would be accepted.
 * - It FAILS CLOSED: a Redis error rejects the promise, `verifyHttpRequestSignature` rejects with it,
 *   and the request must be refused (answer 5xx/401, never "accept because the store is down").
 *
 * The tests in `sdk/tests/RedisNonceStoreExample.test.ts` run this file against a fake Redis that
 * has the same `SET NX EXAT` semantics.
 *
 * @param {{ set(key: string, value: string, options: { NX: true, EXAT: number }): Promise<string | null> }} client
 *        node-redis v4+ client (or anything with the same `set` signature).
 * @param {{ prefix?: string }} [options]
 * @returns {{ checkAndStore(key: string, expiresAt: number): Promise<boolean> }}
 */
function createRedisNonceStore(client, options = {}) {
  const prefix = options.prefix ?? 'agent-did:nonce:';
  return {
    async checkAndStore(key, expiresAt) {
      const reply = await client.set(`${prefix}${key}`, '1', { NX: true, EXAT: expiresAt + 1 });
      return reply === 'OK';
    }
  };
}

module.exports = { createRedisNonceStore };
