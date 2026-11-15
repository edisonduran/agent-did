import { AgentDIDDocument, DidDocument } from '../core/types';
import { generateCanonicalDocumentHash } from '../crypto/hash';
import { agentDidDocumentProblem, didDocumentProblem } from '../core/document-guard';
import { HttpDIDDocumentSource } from './HttpDIDDocumentSource';
import { WebvhDIDDocumentSource } from './WebvhDIDDocumentSource';
import {
  compareDidWebvhLogs,
  deriveDidWebvhLogUrl,
  deriveDidWebvhWitnessUrl,
  didWebvhLastEntrySigners,
  didWebvhLogRequiresWitnesses,
  resolveDidWebvhLog
} from '../webvh/adapter';
import {
  DEFAULT_FETCH_DEADLINE_MS,
  DEFAULT_MAX_CONCURRENT_FETCHES,
  DEFAULT_MAX_CONCURRENT_FETCHES_PER_HOST,
  DEFAULT_MAX_QUEUED_FETCHES,
  DEFAULT_NEGATIVE_CACHE_TTL_MS,
  DEFAULT_RESOLVER_MAX_CACHE_ENTRIES,
  DocumentIntegrityError,
  DidWebvhResolution,
  DIDResolver,
  ResolverResolutionEvent,
  ResolverCacheStats,
  UniversalResolverConfig
} from './types';

const SHA256_DOCUMENT_REF_PREFIX = 'hash://sha256/';

/**
 * A resolution refused because the resolver is busy (the fetch queue is full, or no slot freed up before the
 * deadline). It says nothing about the DID, so it is not remembered in the negative cache.
 */
class FetchCapacityError extends Error {}

interface FetchWaiter {
  host: string;
  start: () => void;
}

// did:wba host grammar (parity: sdk-python/src/agent_did_sdk/resolver/universal.py). After percent-decoding, the
// domain segment must be a DNS name with an optional port: ASCII letters, digits and hyphens in dot-separated labels.
// IP literals are rejected (did:web, which did:wba builds on, excludes them), and so is a numeric last label, which a
// URL parser would read as an IPv4 address.
const DID_WBA_LABEL = /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$/;
const DID_WBA_NUMERIC_LABEL = /^(?:0x[0-9a-f]*|[0-9]+)$/i;
const DID_WBA_PORT = /^[1-9][0-9]{0,4}$/;

/** Splits a decoded did:wba domain into a lowercase host and a port (undefined for the default), or null if invalid. */
function parseDidWbaDomain(domain: string): { host: string; port?: number } | null {
  const separator = domain.indexOf(':');
  const host = separator === -1 ? domain : domain.slice(0, separator);
  let port: number | undefined;
  if (separator !== -1) {
    const portText = domain.slice(separator + 1);
    if (!DID_WBA_PORT.test(portText) || Number(portText) > 65535) {
      return null;
    }
    port = Number(portText);
  }
  const labels = host.split('.');
  if (host.length > 253 || !labels.every((label) => DID_WBA_LABEL.test(label))) {
    return null;
  }
  if (DID_WBA_NUMERIC_LABEL.test(labels[labels.length - 1])) {
    return null;
  }
  return { host: host.toLowerCase(), port: port === 443 ? undefined : port };
}

/** Percent-encodes everything but the RFC 3986 unreserved characters. */
function encodeDidWbaPathSegment(segment: string): string {
  return encodeURIComponent(segment).replace(/[!'()*]/g, (c) => `%${c.charCodeAt(0).toString(16).toUpperCase()}`);
}

function decodeDidWbaSegment(segment: string, segmentType: 'domain' | 'path'): string {
  try {
    return decodeURIComponent(segment);
  } catch {
    throw new Error(`Invalid did:wba ${segmentType} segment: ${segment}`);
  }
}

/**
 * The HTTPS URL of a did:wba DID's `did.json`. The URL is built from validated parts and parsed again, so the host,
 * port and path that are fetched are exactly the ones derived from the DID.
 */
function deriveDidWbaDocumentUrl(did: string): string {
  const suffix = did.startsWith('did:wba:') ? did.slice('did:wba:'.length) : '';
  if (!suffix) {
    throw new Error(`Invalid did:wba DID: ${did}`);
  }

  const [domainSegment, ...pathSegments] = suffix.split(':');
  const domain = decodeDidWbaSegment(domainSegment, 'domain');
  if (!domain) {
    throw new Error(`Invalid did:wba DID: missing domain in ${did}`);
  }
  const parsedDomain = parseDidWbaDomain(domain);
  if (!parsedDomain) {
    throw new Error(`Invalid did:wba domain segment: ${domainSegment}`);
  }
  const { host, port } = parsedDomain;

  const decodedSegments = pathSegments
    .filter((segment) => segment.length > 0)
    .map((segment) => decodeDidWbaSegment(segment, 'path'));
  if (decodedSegments.some((segment) => segment === '.' || segment === '..')) {
    throw new Error(`Invalid did:wba DID: dot path segment in ${did}`);
  }
  const pathname = decodedSegments.length === 0
    ? '/.well-known/did.json'
    : `/${decodedSegments.map(encodeDidWbaPathSegment).join('/')}/did.json`;

  const authority = port === undefined ? host : `${host}:${port}`;
  const url = `https://${authority}${pathname}`;

  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    throw new Error(`Invalid did:wba DID: ${did}`);
  }
  if (
    parsed.protocol !== 'https:' ||
    parsed.hostname !== host ||
    parsed.port !== (port === undefined ? '' : String(port)) ||
    parsed.username !== '' ||
    parsed.password !== '' ||
    parsed.pathname !== pathname ||
    parsed.search !== '' ||
    parsed.hash !== '' ||
    parsed.href !== url
  ) {
    throw new Error(`Invalid did:wba DID: ${did}`);
  }
  return url;
}

interface CachedDocument {
  /** An Agent-DID document, or (did:webvh only) any DID Core document: `resolve` checks the agent profile. */
  document: DidDocument;
  expiresAt: number;
  /** Set when the document came from a verified did:webvh log fetched by this resolver. */
  webvh?: DidWebvhResolution;
  /** The did:webvh log ends in a deactivation entry: `resolve` rejects, `resolveDidWebvhLog` returns the log. */
  deactivated?: boolean;
}

/** `host` is listed, or a subdomain of a `*.`-prefixed entry. */
function hostAllowed(host: string, allowedHosts: readonly string[]): boolean {
  const normalized = host.toLowerCase();
  return allowedHosts.some((entry) =>
    entry.startsWith('*.') ? normalized.endsWith(entry.slice(1)) && normalized.length > entry.length - 1 : normalized === entry
  );
}

export class UniversalResolverClient implements DIDResolver {
  private readonly registry;
  private readonly documentSource;
  private readonly wbaDocumentSource;
  private readonly webvhDocumentSource;
  private readonly fallbackResolver;
  private readonly cacheTtlMs: number;
  private readonly maxCacheEntries: number;
  private readonly onResolutionEvent;
  private readonly unverifiedDocumentRefSchemes: ReadonlySet<string>;
  private readonly cache = new Map<string, CachedDocument>();
  private readonly negativeCacheTtlMs: number;
  private readonly maxConcurrentFetches: number;
  private readonly maxConcurrentFetchesPerHost: number;
  private readonly maxQueuedFetches: number;
  private readonly fetchDeadlineMs: number;
  private readonly allowedHosts: readonly string[] | undefined;
  /** Recent did:webvh / did:wba failures, answered again without fetching until they expire. */
  private readonly negativeCache = new Map<string, { error: unknown; expiresAt: number }>();
  /** Fetches in progress, shared by concurrent resolutions of the same DID. */
  private readonly inFlight = new Map<string, Promise<unknown>>();
  private activeFetches = 0;
  private readonly activeFetchesByHost = new Map<string, number>();
  /** Fetches waiting for a slot, oldest first. */
  private readonly fetchQueue: FetchWaiter[] = [];
  private hits = 0;
  private misses = 0;

  constructor(private readonly config: UniversalResolverConfig) {
    this.registry = config.registry;
    this.documentSource = config.documentSource;
    this.wbaDocumentSource = config.wbaDocumentSource ?? new HttpDIDDocumentSource();
    this.webvhDocumentSource = config.webvhDocumentSource ?? new WebvhDIDDocumentSource();
    this.fallbackResolver = config.fallbackResolver;
    this.cacheTtlMs = config.cacheTtlMs ?? 60_000;
    this.maxCacheEntries = config.maxCacheEntries ?? DEFAULT_RESOLVER_MAX_CACHE_ENTRIES;
    if (!Number.isSafeInteger(this.maxCacheEntries) || this.maxCacheEntries <= 0) {
      throw new TypeError('maxCacheEntries must be a positive integer');
    }
    const limits = config.resolutionLimits ?? {};
    this.negativeCacheTtlMs = limits.negativeCacheTtlMs ?? DEFAULT_NEGATIVE_CACHE_TTL_MS;
    if (!Number.isSafeInteger(this.negativeCacheTtlMs) || this.negativeCacheTtlMs < 0) {
      throw new TypeError('negativeCacheTtlMs must be a non-negative integer');
    }
    this.maxConcurrentFetches = limits.maxConcurrentFetches ?? DEFAULT_MAX_CONCURRENT_FETCHES;
    if (!Number.isSafeInteger(this.maxConcurrentFetches) || this.maxConcurrentFetches <= 0) {
      throw new TypeError('maxConcurrentFetches must be a positive integer');
    }
    this.maxConcurrentFetchesPerHost = limits.maxConcurrentFetchesPerHost ?? DEFAULT_MAX_CONCURRENT_FETCHES_PER_HOST;
    if (!Number.isSafeInteger(this.maxConcurrentFetchesPerHost) || this.maxConcurrentFetchesPerHost <= 0) {
      throw new TypeError('maxConcurrentFetchesPerHost must be a positive integer');
    }
    this.maxQueuedFetches = limits.maxQueuedFetches ?? DEFAULT_MAX_QUEUED_FETCHES;
    if (!Number.isSafeInteger(this.maxQueuedFetches) || this.maxQueuedFetches < 0) {
      throw new TypeError('maxQueuedFetches must be a non-negative integer');
    }
    this.fetchDeadlineMs = limits.fetchDeadlineMs ?? DEFAULT_FETCH_DEADLINE_MS;
    if (!Number.isSafeInteger(this.fetchDeadlineMs) || this.fetchDeadlineMs <= 0) {
      throw new TypeError('fetchDeadlineMs must be a positive integer');
    }
    if (limits.allowedHosts !== undefined) {
      if (!Array.isArray(limits.allowedHosts) || limits.allowedHosts.some((host) => typeof host !== 'string' || !host.trim())) {
        throw new TypeError('allowedHosts must be a list of host names');
      }
      this.allowedHosts = limits.allowedHosts.map((host) => host.trim().toLowerCase());
    }
    this.onResolutionEvent = config.onResolutionEvent;
    this.unverifiedDocumentRefSchemes = new Set(
      (config.unverifiedDocumentRefSchemes ?? []).map((scheme) => scheme.toLowerCase())
    );
  }

  public registerDocument(document: AgentDIDDocument): void {
    const did = document.id;
    this.cachePut(did, document, Date.now() + this.cacheTtlMs);

    if (this.documentSource.storeByReference) {
      const documentRef = this.computeDocumentReference(document);
      this.documentSource.storeByReference(documentRef, this.clone(document)).catch((error: unknown) => {
        // The cache is already updated, so resolution here keeps working, but the document did not
        // reach the remote store: tell the operator instead of swallowing it.
        const message = error instanceof Error ? error.message : String(error);
        try {
          this.emitEvent({ did, stage: 'error', durationMs: 0, message: `storeByReference failed: ${message}` });
        } catch {
          // An event handler that throws must not become an unhandled rejection.
        }
      });
    }
  }

  public async resolve(did: string): Promise<AgentDIDDocument> {
    if (this.isDidWebvh(did)) {
      return this.agentDocument(did, await this.resolveDocument(did));
    }
    const startedAt = Date.now();
    const now = Date.now();
    const cached = this.cacheHit(did, startedAt, now);
    if (cached !== undefined) {
      // Only did:webvh entries can hold a document that is not an Agent-DID document
      return cached as AgentDIDDocument;
    }

    if (this.isDidWba(did)) {
      return this.clone(await this.guardedFetch(did, startedAt, () => this.resolveDidWba(did, startedAt, now)));
    }

    this.emitEvent({ did, stage: 'registry-lookup', durationMs: Date.now() - startedAt });
    const record = await this.registry.getRecord(did);

    if (!record) {
      return this.resolveWithFallback(did, `DID not found in registry: ${did}`, startedAt);
    }

    if (!record.documentRef) {
      return this.resolveWithFallback(did, `Missing documentRef for DID: ${did}`, startedAt);
    }

    this.emitEvent({
      did,
      stage: 'source-fetch',
      durationMs: Date.now() - startedAt,
      message: `documentRef=${record.documentRef}`
    });

    // Only availability failures (source error, document missing) may fall back.
    // Integrity failures below throw and never degrade to another source.
    let resolved: AgentDIDDocument | null;
    try {
      resolved = await this.documentSource.getByReference(record.documentRef);
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      this.emitEvent({ did, stage: 'error', durationMs: Date.now() - startedAt, message });
      return this.resolveWithFallback(did, message, startedAt);
    }

    if (!resolved) {
      return this.resolveWithFallback(did, `Document not found for reference: ${record.documentRef}`, startedAt);
    }

    if (resolved.id !== did) {
      throw this.integrityFailure(
        did,
        `Resolved document DID mismatch. Expected ${did}, got ${resolved.id}`,
        startedAt
      );
    }

    this.assertDocumentMatchesReference(did, record.documentRef, resolved, startedAt);

    this.emitEvent({ did, stage: 'source-fetched', durationMs: Date.now() - startedAt });

    this.cachePut(did, resolved, now + this.cacheTtlMs);

    this.emitEvent({ did, stage: 'resolved', durationMs: Date.now() - startedAt });

    return this.clone(resolved);
  }

  /**
   * The DID Core document of `did`. A did:webvh document need not be an Agent-DID document (a controller, RFC-001
   * §4.2.1): the log is verified as for `resolve`, and the state only has to be a DID Core document. Any other DID
   * is answered by `resolve`.
   */
  public async resolveDocument(did: string): Promise<DidDocument> {
    if (!this.isDidWebvh(did)) {
      return this.resolve(did);
    }
    const startedAt = Date.now();
    const now = Date.now();
    const cached = this.cacheHit(did, startedAt, now);
    if (cached !== undefined) {
      return cached;
    }
    return this.resolveDidWebvh(did, startedAt, now);
  }

  /**
   * A fresh cached document of `did` (rejecting a deactivated did:webvh DID), or `undefined` on a miss. Counts the
   * hit or the miss.
   */
  private cacheHit(did: string, startedAt: number, now: number): DidDocument | undefined {
    const cached = this.cache.get(did);
    if (cached && cached.expiresAt > now) {
      // Most recently used goes last, so eviction drops the least recently used first.
      this.cache.delete(did);
      this.cache.set(did, cached);
      this.hits += 1;
      this.emitEvent({ did, stage: 'cache-hit', durationMs: Date.now() - startedAt });
      if (cached.deactivated) {
        throw this.deactivatedError(did, startedAt);
      }
      return this.clone(cached.document);
    }
    this.misses += 1;
    this.emitEvent({ did, stage: 'cache-miss', durationMs: Date.now() - startedAt });
    return undefined;
  }

  /** `document` as an Agent-DID document; rejects a DID Core document that is not one (a plain controller). */
  private agentDocument(did: string, document: DidDocument): AgentDIDDocument {
    const problem = agentDidDocumentProblem(document);
    if (problem !== undefined) {
      const message = `${did} is not an Agent-DID document: ${problem}`;
      this.emitEvent({ did, stage: 'error', durationMs: 0, message });
      throw new Error(message);
    }
    return document as AgentDIDDocument;
  }

  /**
   * The verified did:webvh log behind `did`: from the cache while the entry is fresh, otherwise fetched and verified
   * (rejecting when it cannot be, with no fallback). The log of a deactivated DID is returned with
   * `deactivated: true`. `undefined` when the cached entry holds only a document that was registered without its log.
   */
  public async resolveDidWebvhLog(did: string): Promise<DidWebvhResolution | undefined> {
    if (!this.isDidWebvh(did)) {
      return undefined;
    }
    const startedAt = Date.now();
    let entry = this.cache.get(did);
    if (entry && entry.expiresAt > startedAt) {
      this.cache.delete(did);
      this.cache.set(did, entry);
      this.hits += 1;
      this.emitEvent({ did, stage: 'cache-hit', durationMs: Date.now() - startedAt });
    } else {
      this.misses += 1;
      this.emitEvent({ did, stage: 'cache-miss', durationMs: Date.now() - startedAt });
      entry = await this.guardedFetch(did, startedAt, () => this.loadDidWebvh(did, startedAt, startedAt));
    }
    return entry.webvh ? JSON.parse(JSON.stringify(entry.webvh)) as DidWebvhResolution : undefined;
  }

  /**
   * Runs `load` (a did:webvh or did:wba fetch) under the resolution limits: the host allow-list, the negative cache,
   * one shared fetch per DID, at most `maxConcurrentFetches` fetches at once (`maxConcurrentFetchesPerHost` per host),
   * at most `maxQueuedFetches` waiting, and `fetchDeadlineMs` for the wait and the fetch together.
   */
  private async guardedFetch<T>(did: string, startedAt: number, load: () => Promise<T>): Promise<T> {
    this.assertHostAllowed(did, startedAt);
    const recent = this.negativeCache.get(did);
    if (recent && recent.expiresAt > Date.now()) {
      const message = recent.error instanceof Error ? recent.error.message : String(recent.error);
      this.emitEvent({ did, stage: 'error', durationMs: Date.now() - startedAt, message: `recent failure: ${message}` });
      throw recent.error;
    }
    const pending = this.inFlight.get(did);
    if (pending) {
      return pending as Promise<T>;
    }
    const run = this.withFetchSlot(this.fetchHostOf(did), load).then(
      (value) => {
        this.negativeCache.delete(did);
        return value;
      },
      (error: unknown) => {
        if (error instanceof FetchCapacityError) {
          this.emitEvent({ did, stage: 'error', durationMs: Date.now() - startedAt, message: error.message });
        } else {
          this.rememberFailure(did, error);
        }
        throw error;
      }
    );
    this.inFlight.set(did, run);
    try {
      return await run;
    } finally {
      this.inFlight.delete(did);
    }
  }

  /** The host name a did:webvh / did:wba DID is fetched from, or '' for a DID that does not derive a URL. */
  private fetchHostOf(did: string): string {
    try {
      const url = this.isDidWebvh(did) ? deriveDidWebvhLogUrl(did) : this.deriveDidWbaDocumentUrl(did);
      return new URL(url).hostname;
    } catch {
      return '';
    }
  }

  private hasFetchSlot(host: string): boolean {
    return (
      this.activeFetches < this.maxConcurrentFetches &&
      (this.activeFetchesByHost.get(host) ?? 0) < this.maxConcurrentFetchesPerHost
    );
  }

  private takeFetchSlot(host: string): void {
    this.activeFetches += 1;
    this.activeFetchesByHost.set(host, (this.activeFetchesByHost.get(host) ?? 0) + 1);
  }

  private releaseFetchSlot(host: string): void {
    this.activeFetches -= 1;
    const count = (this.activeFetchesByHost.get(host) ?? 1) - 1;
    if (count > 0) {
      this.activeFetchesByHost.set(host, count);
    } else {
      this.activeFetchesByHost.delete(host);
    }
    // Start the oldest waiters whose host has room; a waiter for a busy host does not hold up the others.
    for (let i = 0; i < this.fetchQueue.length && this.activeFetches < this.maxConcurrentFetches; ) {
      const waiter = this.fetchQueue[i];
      if (this.hasFetchSlot(waiter.host)) {
        this.fetchQueue.splice(i, 1);
        this.takeFetchSlot(waiter.host);
        waiter.start();
      } else {
        i += 1;
      }
    }
  }

  private async withFetchSlot<T>(host: string, load: () => Promise<T>): Promise<T> {
    const deadline = Date.now() + this.fetchDeadlineMs;
    if (this.hasFetchSlot(host)) {
      this.takeFetchSlot(host);
    } else {
      if (this.fetchQueue.length >= this.maxQueuedFetches) {
        throw new FetchCapacityError('Resolution refused: too many DID fetches are waiting (maxQueuedFetches)');
      }
      await new Promise<void>((resolve, reject) => {
        const waiter: FetchWaiter = {
          host,
          start: () => {
            clearTimeout(timer);
            resolve();
          }
        };
        const timer = setTimeout(() => {
          const index = this.fetchQueue.indexOf(waiter);
          if (index !== -1) {
            this.fetchQueue.splice(index, 1);
          }
          reject(new FetchCapacityError(`Resolution refused: no fetch slot freed up within ${this.fetchDeadlineMs} ms`));
        }, this.fetchDeadlineMs);
        this.fetchQueue.push(waiter);
      });
    }

    // The slot is held until the fetch settles, even when the caller stops waiting at the deadline.
    let loading: Promise<T>;
    try {
      loading = load();
    } catch (error) {
      this.releaseFetchSlot(host);
      throw error;
    }
    loading.then(
      () => this.releaseFetchSlot(host),
      () => this.releaseFetchSlot(host)
    );
    let timer: ReturnType<typeof setTimeout> | undefined;
    const expired = new Promise<never>((_, reject) => {
      timer = setTimeout(
        () => reject(new Error(`DID fetch did not finish within ${this.fetchDeadlineMs} ms (fetchDeadlineMs)`)),
        Math.max(0, deadline - Date.now())
      );
    });
    try {
      return await Promise.race([loading, expired]);
    } finally {
      clearTimeout(timer);
    }
  }

  private rememberFailure(did: string, error: unknown): void {
    if (this.negativeCacheTtlMs === 0) {
      return;
    }
    this.negativeCache.delete(did);
    this.negativeCache.set(did, { error, expiresAt: Date.now() + this.negativeCacheTtlMs });
    while (this.negativeCache.size > this.maxCacheEntries) {
      this.negativeCache.delete(this.negativeCache.keys().next().value as string);
    }
  }

  /** Throws before any request when `allowedHosts` is set and the DID's host is not in it. */
  private assertHostAllowed(did: string, startedAt: number): void {
    if (this.allowedHosts === undefined) {
      return;
    }
    let host: string;
    try {
      host = new URL(this.isDidWebvh(did) ? deriveDidWebvhLogUrl(did) : this.deriveDidWbaDocumentUrl(did)).hostname;
    } catch {
      return; // an invalid DID fails in the fetch itself
    }
    if (!hostAllowed(host, this.allowedHosts)) {
      const message = `Resolution of ${did} is not allowed: ${host} is not in allowedHosts`;
      this.emitEvent({ did, stage: 'error', durationMs: Date.now() - startedAt, message });
      throw new Error(message);
    }
  }

  private deactivatedError(did: string, startedAt: number): Error {
    const message = `DID is deactivated: ${did}`;
    this.emitEvent({ did, stage: 'error', durationMs: Date.now() - startedAt, message });
    return new Error(message);
  }

  public remove(did: string): void {
    this.cache.delete(did);
    this.negativeCache.delete(did);
    this.fallbackResolver?.remove(did);
  }

  /**
   * Drops the cached resolution of `did`, including a remembered failure (not the fallback resolver's documents):
   * the next resolution fetches.
   */
  public evict(did: string): void {
    this.cache.delete(did);
    this.negativeCache.delete(did);
  }

  public getCacheStats(): ResolverCacheStats {
    return {
      hits: this.hits,
      misses: this.misses,
      size: this.cache.size
    };
  }

  private async resolveWithFallback(did: string, errorMessage: string, startedAt: number): Promise<AgentDIDDocument> {
    if (!this.fallbackResolver) {
      this.emitEvent({ did, stage: 'error', durationMs: Date.now() - startedAt, message: errorMessage });
      throw new Error(errorMessage);
    }

    this.emitEvent({ did, stage: 'fallback', durationMs: Date.now() - startedAt, message: errorMessage });

    const fallbackDocument = await this.fallbackResolver.resolve(did);
    this.cachePut(did, fallbackDocument, Date.now() + this.cacheTtlMs);

    this.emitEvent({ did, stage: 'resolved', durationMs: Date.now() - startedAt, message: 'fallback' });

    return this.clone(fallbackDocument);
  }

  private async resolveDidWba(did: string, startedAt: number, now: number): Promise<AgentDIDDocument> {
    const documentUrl = this.deriveDidWbaDocumentUrl(did);

    this.emitEvent({
      did,
      stage: 'source-fetch',
      durationMs: Date.now() - startedAt,
      message: `url=${documentUrl}`
    });

    // Like did:webvh, a did:wba DID is answered only by its own host: no fallback to another resolver, which could
    // keep serving a copy the host has since changed.
    let resolved: AgentDIDDocument | null;
    try {
      resolved = await this.wbaDocumentSource.getByReference(documentUrl);
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      this.emitEvent({ did, stage: 'error', durationMs: Date.now() - startedAt, message });
      throw new Error(`did:wba document could not be fetched for ${did}: ${message}`);
    }

    if (!resolved) {
      const message = `Document not found for did:wba URL: ${documentUrl}`;
      this.emitEvent({ did, stage: 'error', durationMs: Date.now() - startedAt, message });
      throw new Error(message);
    }

    if (resolved.id !== did) {
      throw this.integrityFailure(did, `Resolved document DID mismatch. Expected ${did}, got ${resolved.id}`, startedAt);
    }

    this.emitEvent({ did, stage: 'source-fetched', durationMs: Date.now() - startedAt });

    this.cachePut(did, resolved, now + this.cacheTtlMs);

    this.emitEvent({ did, stage: 'resolved', durationMs: Date.now() - startedAt });

    return this.clone(resolved);
  }

  /**
   * did:webvh resolution: fetch `did.jsonl` from the URL derived from the DID,
   * verify the whole log with the did:webvh adapter, and return the latest
   * state. There is no fallback to another resolver: a fetch error, a missing
   * log, an invalid DID, a log that fails verification, a log that contradicts
   * the one held locally and a deactivated DID all fail closed.
   */
  private async resolveDidWebvh(did: string, startedAt: number, now: number): Promise<DidDocument> {
    const entry = await this.guardedFetch(did, startedAt, () => this.loadDidWebvh(did, startedAt, now));
    if (entry.deactivated) {
      throw this.deactivatedError(did, startedAt);
    }
    this.emitEvent({ did, stage: 'resolved', durationMs: Date.now() - startedAt });
    return this.clone(entry.document);
  }

  /** Fetches, verifies and caches the did:webvh log behind `did`, deactivated or not, and returns the cache entry. */
  private async loadDidWebvh(did: string, startedAt: number, now: number): Promise<CachedDocument> {
    let logUrl: string;
    try {
      logUrl = deriveDidWebvhLogUrl(did);
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      this.emitEvent({ did, stage: 'error', durationMs: Date.now() - startedAt, message });
      throw error;
    }

    const source = this.webvhDocumentSource;
    if (!source.getDidLogByReference) {
      const message = 'webvhDocumentSource must implement getDidLogByReference: did:webvh logs are verified, never trusted as plain documents';
      this.emitEvent({ did, stage: 'error', durationMs: Date.now() - startedAt, message });
      throw new Error(message);
    }

    this.emitEvent({ did, stage: 'source-fetch', durationMs: Date.now() - startedAt, message: `url=${logUrl}` });

    let logText: string | null;
    try {
      logText = await source.getDidLogByReference(logUrl);
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      this.emitEvent({ did, stage: 'error', durationMs: Date.now() - startedAt, message });
      throw new Error(`did:webvh log could not be fetched for ${did}: ${message}`);
    }

    if (logText === null) {
      const message = `DID log not found for did:webvh URL: ${logUrl}`;
      this.emitEvent({ did, stage: 'error', durationMs: Date.now() - startedAt, message });
      throw new Error(message);
    }

    const witnessFile = await this.fetchDidWebvhWitnessFile(did, logText, startedAt);

    let resolved;
    try {
      resolved = await resolveDidWebvhLog(logText, { did, ...(witnessFile !== undefined ? { witnessFile } : {}) });
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      throw this.integrityFailure(did, `did:webvh log verification failed for ${did}: ${message}`, startedAt);
    }

    resolved = await this.reconcileWithLocalLog(did, resolved, startedAt);

    // A controller need not be an Agent-DID document (RFC-001 §4.2.1): `resolve` checks the agent profile
    const problem = didDocumentProblem(resolved.state);
    if (problem !== undefined) {
      throw this.integrityFailure(did, `did:webvh state for ${did} is not a DID document: ${problem}`, startedAt);
    }
    const document = resolved.state as unknown as DidDocument;
    const deactivated = resolved.metadata.deactivated;
    this.emitEvent({
      did,
      stage: 'source-fetched',
      durationMs: Date.now() - startedAt,
      message: `versionId=${resolved.metadata.versionId}`
    });

    this.cachePut(did, document, now + this.cacheTtlMs, {
      document,
      log: resolved.log,
      versionId: resolved.metadata.versionId,
      updateKeys: [...resolved.metadata.updateKeys],
      lastEntrySignerKeys: didWebvhLastEntrySigners(resolved.log),
      deactivated,
      ...(resolved.witnessFile !== undefined ? { witnessFile: resolved.witnessFile } : {})
    }, deactivated);

    return this.cache.get(did) as CachedDocument;
  }

  /**
   * The `did-witness.json` of `did` when its log has witnessed entries (ADR-007), fetched from the same source and
   * under the same limits as the log; `undefined` when the log has none. A log with witnessed entries whose witness
   * file cannot be fetched is an integrity failure: resolving it without the approvals is never an option.
   */
  private async fetchDidWebvhWitnessFile(did: string, logText: string, startedAt: number): Promise<string | undefined> {
    let required: boolean;
    try {
      required = didWebvhLogRequiresWitnesses(logText);
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      throw this.integrityFailure(did, `did:webvh log verification failed for ${did}: ${message}`, startedAt);
    }
    if (!required) {
      return undefined;
    }
    const source = this.webvhDocumentSource;
    if (!source.getDidWitnessFileByReference) {
      throw this.integrityFailure(
        did,
        `The did:webvh log of ${did} has witnessed entries and webvhDocumentSource cannot fetch did-witness.json`,
        startedAt
      );
    }
    const witnessUrl = deriveDidWebvhWitnessUrl(did);
    this.emitEvent({ did, stage: 'source-fetch', durationMs: Date.now() - startedAt, message: `url=${witnessUrl}` });
    let witnessFile: string | null;
    try {
      witnessFile = await source.getDidWitnessFileByReference(witnessUrl);
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      this.emitEvent({ did, stage: 'error', durationMs: Date.now() - startedAt, message });
      throw new Error(`did:webvh witness file could not be fetched for ${did}: ${message}`);
    }
    if (witnessFile === null) {
      throw this.integrityFailure(
        did,
        `The did:webvh log of ${did} has witnessed entries and no did-witness.json was found at ${witnessUrl}`,
        startedAt
      );
    }
    return witnessFile;
  }

  /**
   * Applies the rule for a fetched log against the log the caller holds: the longer one wins and a log
   * that is not a prefix or an extension of the other is an integrity failure (never a fallback).
   */
  private async reconcileWithLocalLog(
    did: string,
    fetched: Awaited<ReturnType<typeof resolveDidWebvhLog>>,
    startedAt: number
  ): Promise<Awaited<ReturnType<typeof resolveDidWebvhLog>>> {
    const local = this.config.didWebvhLocalLog?.(did);
    if (local === undefined) {
      return fetched;
    }
    let relation;
    try {
      relation = compareDidWebvhLogs(local, fetched.log);
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      throw this.integrityFailure(did, `did:webvh log comparison failed for ${did}: ${message}`, startedAt);
    }
    if (relation === 'diverged') {
      throw this.integrityFailure(
        did,
        `The did:webvh log fetched for ${did} contradicts the log held locally (not a prefix or an extension)`,
        startedAt
      );
    }
    if (relation === 'prefix') {
      this.emitEvent({
        did,
        stage: 'source-fetched',
        durationMs: Date.now() - startedAt,
        message: 'fetched did:webvh log is older than the local one; using the local log'
      });
      const localWitnessFile = this.config.didWebvhLocalWitnessFile?.(did);
      try {
        return await resolveDidWebvhLog(local, {
          did,
          ...(localWitnessFile !== undefined ? { witnessFile: localWitnessFile } : {})
        });
      } catch (error) {
        const message = error instanceof Error ? error.message : String(error);
        throw this.integrityFailure(did, `did:webvh log verification failed for ${did}: ${message}`, startedAt);
      }
    }
    return fetched;
  }

  /** Stores a copy of `document`, keeping the cache within `maxCacheEntries`. */
  private cachePut(
    did: string,
    document: DidDocument,
    expiresAt: number,
    webvh?: DidWebvhResolution,
    deactivated = false
  ): void {
    this.cache.delete(did);
    this.cache.set(did, {
      document: this.clone(document),
      expiresAt,
      ...(webvh ? { webvh: JSON.parse(JSON.stringify(webvh)) as DidWebvhResolution } : {}),
      ...(deactivated ? { deactivated: true } : {})
    });
    if (this.cache.size <= this.maxCacheEntries) {
      return;
    }
    const now = Date.now();
    for (const [key, entry] of this.cache) {
      if (entry.expiresAt <= now) {
        this.cache.delete(key);
      }
    }
    for (const key of this.cache.keys()) {
      if (this.cache.size <= this.maxCacheEntries) {
        break;
      }
      this.cache.delete(key);
    }
  }

  private emitEvent(event: ResolverResolutionEvent): void {
    this.onResolutionEvent?.(event);
  }

  private isDidWba(did: string): boolean {
    return did.startsWith('did:wba:');
  }

  private isDidWebvh(did: string): boolean {
    return did.startsWith('did:webvh:');
  }

  private deriveDidWbaDocumentUrl(did: string): string {
    return deriveDidWbaDocumentUrl(did);
  }

  private assertDocumentMatchesReference(
    did: string,
    documentRef: string,
    document: AgentDIDDocument,
    startedAt: number
  ): void {
    if (!documentRef.startsWith(SHA256_DOCUMENT_REF_PREFIX)) {
      const scheme = documentRef.split('://', 1)[0].toLowerCase();
      if (documentRef.includes('://') && this.unverifiedDocumentRefSchemes.has(scheme)) {
        this.emitEvent({
          did,
          stage: 'source-fetched',
          durationMs: Date.now() - startedAt,
          message: `integrity=unverified scheme=${scheme} documentRef=${documentRef}`
        });
        return;
      }
      throw this.integrityFailure(
        did,
        `Unsupported documentRef scheme for ${did}: ${documentRef}. Only ${SHA256_DOCUMENT_REF_PREFIX} references can be verified.`,
        startedAt
      );
    }

    const computedRef = this.computeDocumentReference(document);
    if (computedRef !== documentRef.toLowerCase()) {
      throw this.integrityFailure(
        did,
        `Document integrity check failed for ${did}: registry documentRef=${documentRef}, fetched document hashes to ${computedRef}`,
        startedAt
      );
    }
  }

  private integrityFailure(did: string, message: string, startedAt: number): DocumentIntegrityError {
    this.emitEvent({ did, stage: 'error', durationMs: Date.now() - startedAt, message });
    return new DocumentIntegrityError(message);
  }

  private computeDocumentReference(document: AgentDIDDocument): string {
    return generateCanonicalDocumentHash(document);
  }

  private clone<T extends DidDocument>(document: T): T {
    return JSON.parse(JSON.stringify(document)) as T;
  }
}
