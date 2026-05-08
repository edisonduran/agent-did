import { AgentDIDDocument } from '../core/types';
import { generateAgentMetadataHash } from '../crypto/hash';
import { HttpDIDDocumentSource } from './HttpDIDDocumentSource';
import {
  DIDResolver,
  ResolverResolutionEvent,
  ResolverCacheStats,
  UniversalResolverConfig
} from './types';

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
  private readonly onResolutionEvent;
  private readonly cache = new Map<string, CachedDocument>();
  private hits = 0;
  private misses = 0;

  constructor(private readonly config: UniversalResolverConfig) {
    this.registry = config.registry;
    this.documentSource = config.documentSource;
    this.wbaDocumentSource = config.wbaDocumentSource ?? new HttpDIDDocumentSource();
    this.webvhDocumentSource = config.webvhDocumentSource ?? new HttpDIDDocumentSource();
    this.fallbackResolver = config.fallbackResolver;
    this.cacheTtlMs = config.cacheTtlMs ?? 60_000;
    this.onResolutionEvent = config.onResolutionEvent;
  }

  public registerDocument(document: AgentDIDDocument): void {
    const did = document.id;
    this.cache.set(did, {
      document: this.clone(document),
      expiresAt: Date.now() + this.cacheTtlMs
    });

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

    const resolved = await this.documentSource.getByReference(record.documentRef).catch(async (error) => {
      const message = error instanceof Error ? error.message : String(error);
      this.emitEvent({ did, stage: 'error', durationMs: Date.now() - startedAt, message });
      return this.resolveWithFallback(did, message, startedAt);
    });

    if (!resolved) {
      return this.resolveWithFallback(did, `Document not found for reference: ${record.documentRef}`, startedAt);
    }

    if (resolved.id !== did) {
      throw new Error(`Resolved document DID mismatch. Expected ${did}, got ${resolved.id}`);
    }

    this.emitEvent({ did, stage: 'source-fetched', durationMs: Date.now() - startedAt });

    this.cache.set(did, {
      document: this.clone(resolved),
      expiresAt: now + this.cacheTtlMs
    });

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
    this.cache.set(did, {
      document: this.clone(fallbackDocument),
      expiresAt: Date.now() + this.cacheTtlMs
    });

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

    this.cache.set(did, {
      document: this.clone(resolved),
      expiresAt: now + this.cacheTtlMs
    });

    this.emitEvent({ did, stage: 'resolved', durationMs: Date.now() - startedAt });

    return this.clone(resolved);
  }

  private async resolveDidWebvh(did: string, startedAt: number, now: number): Promise<AgentDIDDocument> {
    const documentUrl = this.deriveDidWebvhDocumentUrl(did);

    this.emitEvent({
      did,
      stage: 'source-fetch',
      durationMs: Date.now() - startedAt,
      message: `url=${documentUrl}`
    });

    const resolved = await this.webvhDocumentSource.getByReference(documentUrl).catch(async (error) => {
      const message = error instanceof Error ? error.message : String(error);
      this.emitEvent({ did, stage: 'error', durationMs: Date.now() - startedAt, message });
      return this.resolveWithFallback(did, message, startedAt);
    });

    if (!resolved) {
      return this.resolveWithFallback(did, `Document not found for did:webvh URL: ${documentUrl}`, startedAt);
    }

    if (resolved.id !== did) {
      throw new Error(`Resolved document DID mismatch. Expected ${did}, got ${resolved.id}`);
    }

    this.emitEvent({ did, stage: 'source-fetched', durationMs: Date.now() - startedAt });

    this.cache.set(did, {
      document: this.clone(resolved),
      expiresAt: now + this.cacheTtlMs
    });

    this.emitEvent({ did, stage: 'resolved', durationMs: Date.now() - startedAt });

    return this.clone(resolved);
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

  private deriveDidWebvhDocumentUrl(did: string): string {
    const suffix = did.slice('did:webvh:'.length);

    if (!suffix) {
      throw new Error(`Invalid did:webvh DID: ${did}`);
    }

    const [scidSegment, domainSegment, ...pathSegments] = suffix.split(':');

    if (!scidSegment) {
      throw new Error(`Invalid did:webvh DID: missing SCID in ${did}`);
    }

    const domain = this.decodeDidWbaSegment(domainSegment || '', 'domain');

    if (!domain) {
      throw new Error(`Invalid did:webvh DID: missing domain in ${did}`);
    }

    const normalizedPathSegments = pathSegments
      .filter((segment) => segment.length > 0)
      .map((segment) => encodeURIComponent(this.decodeDidWbaSegment(segment, 'path')));

    const pathname = normalizedPathSegments.length === 0
      ? '/.well-known/did.jsonl'
      : `/${normalizedPathSegments.join('/')}/did.jsonl`;

    try {
      return new URL(pathname, `https://${domain}`).toString();
    } catch {
      throw new Error(`Invalid did:webvh DID: ${did}`);
    }
  }

  private decodeDidWbaSegment(segment: string, segmentType: 'domain' | 'path'): string {
    try {
      return decodeURIComponent(segment);
    } catch {
      throw new Error(`Invalid did:wba ${segmentType} segment: ${segment}`);
    }
  }

  private computeDocumentReference(document: AgentDIDDocument): string {
    return generateAgentMetadataHash(JSON.stringify(document));
  }

  private clone(document: AgentDIDDocument): AgentDIDDocument {
    return JSON.parse(JSON.stringify(document)) as AgentDIDDocument;
  }
}
