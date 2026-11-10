import { AgentDIDDocument } from '../core/types';
import { AgentRegistry } from '../registry/types';

export interface DIDResolver {
  registerDocument(document: AgentDIDDocument): void;
  resolve(did: string): Promise<AgentDIDDocument>;
  remove(did: string): void;
}

export interface DIDDocumentSource {
  getByReference(documentRef: string): Promise<AgentDIDDocument | null>;
  storeByReference?(documentRef: string, document: AgentDIDDocument): Promise<void>;
  getDidLogByReference?(documentRef: string): Promise<string | null>;
  storeDidLogByReference?(documentRef: string, didLog: string): Promise<void>;
}

/** Default maximum number of documents in the `UniversalResolverClient` cache. */
export const DEFAULT_RESOLVER_MAX_CACHE_ENTRIES = 1000;

export interface UniversalResolverConfig {
  registry: AgentRegistry;
  documentSource: DIDDocumentSource;
  wbaDocumentSource?: DIDDocumentSource;
  webvhDocumentSource?: DIDDocumentSource;
  fallbackResolver?: DIDResolver;
  cacheTtlMs?: number;
  /**
   * Maximum documents kept in the cache. When it is full, expired entries are dropped first and
   * then the least recently used. Default: `DEFAULT_RESOLVER_MAX_CACHE_ENTRIES` (1000).
   */
  maxCacheEntries?: number;
  onResolutionEvent?: (event: ResolverResolutionEvent) => void;
  /**
   * documentRef schemes (without `://`, e.g. `'ipfs'`) whose documents are accepted
   * without a content-hash check. Defaults to none: only `hash://sha256/` references,
   * which the SDK always produces, are accepted and they are always verified.
   * Each unverified resolution emits a `source-fetched` event saying so.
   */
  unverifiedDocumentRefSchemes?: string[];
}

export interface ResolverCacheStats {
  hits: number;
  misses: number;
  size: number;
}

export type ResolverResolutionStage =
  | 'cache-hit'
  | 'cache-miss'
  | 'registry-lookup'
  | 'source-fetch'
  | 'source-fetched'
  | 'fallback'
  | 'resolved'
  | 'error';

export interface ResolverResolutionEvent {
  did: string;
  stage: ResolverResolutionStage;
  durationMs: number;
  message?: string;
}

/**
 * Thrown when a resolved DID document cannot be trusted: its `id` differs from
 * the requested DID, its content does not hash to the registry `documentRef`, or
 * the `documentRef` uses a scheme that cannot be verified. Resolvers never fall
 * back to another source on this error.
 */
export class DocumentIntegrityError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'DocumentIntegrityError';
  }
}
