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

export interface UniversalResolverConfig {
  registry: AgentRegistry;
  documentSource: DIDDocumentSource;
  wbaDocumentSource?: DIDDocumentSource;
  webvhDocumentSource?: DIDDocumentSource;
  fallbackResolver?: DIDResolver;
  cacheTtlMs?: number;
  onResolutionEvent?: (event: ResolverResolutionEvent) => void;
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
