import { AgentDIDDocument } from '../core/types';
import { AgentRegistry } from '../registry/types';

/**
 * A verified did:webvh log and what is derived from it. `lastEntrySignerKeys` are the multikeys that made the proofs
 * of the last entry: the keys that endorsed the current document (see ADR-005 / RFC-001 §6.6 item 7).
 */
export interface DidWebvhResolution {
  /** The document in force (the state of the last entry). */
  document: AgentDIDDocument;
  /** The verified log text (`did.jsonl`). */
  log: string;
  versionId: string;
  /** The `updateKeys` in force after the last entry. */
  updateKeys: string[];
  /** Multikeys (`z6Mk...`) that signed the last entry. */
  lastEntrySignerKeys: string[];
  /** `true` when the log ends in a deactivation entry. A resolver that leaves it out reports an active DID. */
  deactivated?: boolean;
}

/** A `DidWebvhResolution` and where the client got it from (see `AgentDidClient.resolveDidWebvhState`). */
export interface DidWebvhState extends DidWebvhResolution {
  /**
   * `local`: created or changed in this client (its controller signer is retained), authoritative here.
   * `imported`: a log loaded with `importDidWebvhHistory`, a cache of what the log host serves.
   * `fetched`: fetched and verified by the resolver.
   */
  provenance: 'local' | 'imported' | 'fetched';
}

export interface DIDResolver {
  registerDocument(document: AgentDIDDocument): void;
  resolve(did: string): Promise<AgentDIDDocument>;
  remove(did: string): void;
  /**
   * Optional: the verified did:webvh log behind `did`, or `undefined` when the resolver holds only the document
   * (for example a document registered without its log). A resolver that fetches logs implements this so the
   * controller binding and a key at a stated time can be checked; failing to fetch rejects (fail closed). The log
   * of a deactivated DID is returned with `deactivated: true` (`resolve` rejects it), so the history before the
   * deactivation can still be checked.
   */
  resolveDidWebvhLog?(did: string): Promise<DidWebvhResolution | undefined>;
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
  /**
   * Resolver used when the registry has no record or the document source cannot answer. It is never
   * used for did:webvh: a did:webvh DID that cannot be fetched fails closed, because falling back to an
   * older copy would let whoever can block the log host keep a revoked or rotated-out state alive.
   */
  fallbackResolver?: DIDResolver;
  /**
   * Returns the did:webvh log the caller already holds for a DID (`AgentDidClient` passes its imported
   * logs). A fetched log must equal it, extend it or be a prefix of it; when it is a prefix the longer
   * local log wins (a stale host never rolls the DID back), and a log that diverges is an integrity failure.
   */
  didWebvhLocalLog?: (did: string) => string | undefined;
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
