import { AgentDIDDocument } from '../core/types';
import { generateCanonicalDocumentHash } from '../crypto/hash';
import { HttpDIDDocumentSource } from './HttpDIDDocumentSource';
import { WebvhDIDDocumentSource } from './WebvhDIDDocumentSource';
import { deriveDidWebvhLogUrl, resolveDidWebvhLog } from '../webvh/adapter';
import {
  DEFAULT_RESOLVER_MAX_CACHE_ENTRIES,
  DocumentIntegrityError,
  DIDResolver,
  ResolverResolutionEvent,
  ResolverCacheStats,
  UniversalResolverConfig
} from './types';

const SHA256_DOCUMENT_REF_PREFIX = 'hash://sha256/';

interface CachedDocument {
  document: AgentDIDDocument;
  expiresAt: number;
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
      this.documentSource.storeByReference(documentRef, this.clone(document)).catch(() => {
        // Non-critical: cache is already updated, external store failure is tolerable
      });
    }
  }

  public async resolve(did: string): Promise<AgentDIDDocument> {
    const startedAt = Date.now();
    const cached = this.cache.get(did);
    const now = Date.now();

    if (cached && cached.expiresAt > now) {
      // Most recently used goes last, so eviction drops the least recently used first.
      this.cache.delete(did);
      this.cache.set(did, cached);
      this.hits += 1;
      this.emitEvent({ did, stage: 'cache-hit', durationMs: Date.now() - startedAt });
      return this.clone(cached.document);
    }

    this.misses += 1;
    this.emitEvent({ did, stage: 'cache-miss', durationMs: Date.now() - startedAt });

    if (this.isDidWba(did)) {
      return this.resolveDidWba(did, startedAt, now);
    }

    if (this.isDidWebvh(did)) {
      return this.resolveDidWebvh(did, startedAt, now);
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

  public remove(did: string): void {
    this.cache.delete(did);
    this.fallbackResolver?.remove(did);
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

    const resolved = await this.wbaDocumentSource.getByReference(documentUrl).catch(async (error) => {
      const message = error instanceof Error ? error.message : String(error);
      this.emitEvent({ did, stage: 'error', durationMs: Date.now() - startedAt, message });
      return this.resolveWithFallback(did, message, startedAt);
    });

    if (!resolved) {
      return this.resolveWithFallback(did, `Document not found for did:wba URL: ${documentUrl}`, startedAt);
    }

    if (resolved.id !== did) {
      throw new Error(`Resolved document DID mismatch. Expected ${did}, got ${resolved.id}`);
    }

    this.emitEvent({ did, stage: 'source-fetched', durationMs: Date.now() - startedAt });

    this.cachePut(did, resolved, now + this.cacheTtlMs);

    this.emitEvent({ did, stage: 'resolved', durationMs: Date.now() - startedAt });

    return this.clone(resolved);
  }

  /**
   * did:webvh resolution: fetch `did.jsonl` from the URL derived from the DID,
   * verify the whole log with the did:webvh adapter, and return the latest
   * state. Only availability failures (fetch error, log not found) may fall
   * back; an invalid DID, a log that fails verification or a deactivated DID
   * never does.
   */
  private async resolveDidWebvh(did: string, startedAt: number, now: number): Promise<AgentDIDDocument> {
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
      return this.resolveWithFallback(did, message, startedAt);
    }

    if (logText === null) {
      return this.resolveWithFallback(did, `DID log not found for did:webvh URL: ${logUrl}`, startedAt);
    }

    let resolved;
    try {
      resolved = await resolveDidWebvhLog(logText, { did });
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      throw this.integrityFailure(did, `did:webvh log verification failed for ${did}: ${message}`, startedAt);
    }

    if (resolved.metadata.deactivated) {
      const message = `DID is deactivated: ${did}`;
      this.emitEvent({ did, stage: 'error', durationMs: Date.now() - startedAt, message });
      throw new Error(message);
    }

    const document = resolved.state as unknown as AgentDIDDocument;
    this.emitEvent({
      did,
      stage: 'source-fetched',
      durationMs: Date.now() - startedAt,
      message: `versionId=${resolved.metadata.versionId}`
    });

    this.cachePut(did, document, now + this.cacheTtlMs);

    this.emitEvent({ did, stage: 'resolved', durationMs: Date.now() - startedAt });

    return this.clone(document);
  }

  /** Stores a copy of `document`, keeping the cache within `maxCacheEntries`. */
  private cachePut(did: string, document: AgentDIDDocument, expiresAt: number): void {
    this.cache.delete(did);
    this.cache.set(did, { document: this.clone(document), expiresAt });
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
    const suffix = did.slice('did:wba:'.length);

    if (!suffix) {
      throw new Error(`Invalid did:wba DID: ${did}`);
    }

    const [domainSegment, ...pathSegments] = suffix.split(':');
    const domain = this.decodeDidWbaSegment(domainSegment, 'domain');

    if (!domain) {
      throw new Error(`Invalid did:wba DID: missing domain in ${did}`);
    }

    const normalizedPathSegments = pathSegments
      .filter((segment) => segment.length > 0)
      .map((segment) => encodeURIComponent(this.decodeDidWbaSegment(segment, 'path')));

    const pathname = normalizedPathSegments.length === 0
      ? '/.well-known/did.json'
      : `/${normalizedPathSegments.join('/')}/did.json`;

    try {
      return new URL(pathname, `https://${domain}`).toString();
    } catch {
      throw new Error(`Invalid did:wba DID: ${did}`);
    }
  }

  private decodeDidWbaSegment(segment: string, segmentType: 'domain' | 'path'): string {
    try {
      return decodeURIComponent(segment);
    } catch {
      throw new Error(`Invalid did:wba ${segmentType} segment: ${segment}`);
    }
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

  private clone(document: AgentDIDDocument): AgentDIDDocument {
    return JSON.parse(JSON.stringify(document)) as AgentDIDDocument;
  }
}
