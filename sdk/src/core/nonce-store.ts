/**
 * Replay protection for verified HTTP message signatures.
 *
 * `AgentIdentity.verifyHttpRequestSignature` records each accepted signature's
 * `nonce` (scoped to its `keyid`) until the signature's `expires` time and
 * rejects a second request carrying the same pair. Use a shared store (for
 * example Redis `SET key 1 NX EXAT expiresAt`) when several verifier instances
 * serve the same agents.
 *
 * Python parity: `agent_did_sdk.core.nonce_store`.
 */
export interface NonceStore {
  /**
   * Records `key` until `expiresAt` (Unix seconds). Resolves `true` when the key
   * was not recorded yet, `false` when it was (a replay). Must be atomic.
   */
  checkAndStore(key: string, expiresAt: number): Promise<boolean>;
}

export interface InMemoryNonceStoreOptions {
  /**
   * Upper bound on live entries. When the store is full after purging expired
   * entries, new nonces are refused (fail closed) instead of evicting live ones,
   * which would reopen a replay window. Default: 100 000.
   */
  maxEntries?: number;
  /** Clock in Unix seconds; injectable for tests. */
  now?: () => number;
}

/** Process-local `NonceStore`. Suitable for a single verifier instance. */
export class InMemoryNonceStore implements NonceStore {
  private readonly entries = new Map<string, number>();
  private readonly maxEntries: number;
  private readonly now: () => number;

  constructor(options: InMemoryNonceStoreOptions = {}) {
    this.maxEntries = options.maxEntries ?? 100_000;
    this.now = options.now ?? (() => Math.floor(Date.now() / 1000));
  }

  public async checkAndStore(key: string, expiresAt: number): Promise<boolean> {
    const now = this.now();
    const existing = this.entries.get(key);
    if (existing !== undefined && existing >= now) {
      return false;
    }
    if (this.entries.size >= this.maxEntries) {
      this.purge(now);
      if (this.entries.size >= this.maxEntries) {
        return false;
      }
    }
    this.entries.set(key, expiresAt);
    return true;
  }

  /** Number of live entries (expired ones may linger until the next purge). */
  public get size(): number {
    return this.entries.size;
  }

  private purge(now: number): void {
    for (const [key, expiresAt] of this.entries) {
      if (expiresAt < now) {
        this.entries.delete(key);
      }
    }
  }
}
