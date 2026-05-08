import { AgentDIDDocument } from '../core/types';
import { HttpDIDDocumentSourceConfig } from './HttpDIDDocumentSource';
import {
  PresignedHttpDIDDocumentSource,
  PresignedHttpDIDDocumentSourceConfig
} from './PresignedHttpDIDDocumentSource';
import { DIDDocumentSource } from './types';

export interface S3CompatibleDIDDocumentSourceConfig {
  bucket: string;
  endpoint?: string;
  publicBaseUrl?: string;
  didLogPublicBaseUrl?: string;
  keyPrefix?: string;
  didLogKeyPrefix?: string;
  forcePathStyle?: boolean;
  referenceToObjectKey?: (documentRef: string) => string;
  referenceToDidLogObjectKey?: (documentRef: string) => string;
  referenceToWriteUrl?: (documentRef: string, objectKey: string) => string;
  didLogReferenceToWriteUrl?: (documentRef: string, objectKey: string) => string;
  fetchFn?: HttpDIDDocumentSourceConfig['fetchFn'];
  httpSecurity?: HttpDIDDocumentSourceConfig['httpSecurity'];
  storeMethod?: HttpDIDDocumentSourceConfig['storeMethod'];
  didLogStoreMethod?: HttpDIDDocumentSourceConfig['didLogStoreMethod'];
}

export class S3CompatibleDIDDocumentSource implements DIDDocumentSource {
  private readonly source: PresignedHttpDIDDocumentSource;
  private readonly documentKeyResolver: (documentRef: string) => string;
  private readonly didLogKeyResolver: (documentRef: string) => string;
  private readonly documentReadBaseUrl: string;
  private readonly didLogReadBaseUrl: string;
  private readonly referenceToWriteUrl: S3CompatibleDIDDocumentSourceConfig['referenceToWriteUrl'];
  private readonly didLogReferenceToWriteUrl: S3CompatibleDIDDocumentSourceConfig['didLogReferenceToWriteUrl'];

  constructor(config: S3CompatibleDIDDocumentSourceConfig) {
    this.documentKeyResolver = config.referenceToObjectKey || ((documentRef) => this.defaultObjectKey(documentRef, config.keyPrefix || 'documents', '.json'));
    this.didLogKeyResolver = config.referenceToDidLogObjectKey || ((documentRef) => this.defaultObjectKey(documentRef, config.didLogKeyPrefix || 'did-logs', '.jsonl'));
    this.documentReadBaseUrl = config.publicBaseUrl || this.defaultBaseUrl(config);
    this.didLogReadBaseUrl = config.didLogPublicBaseUrl || this.documentReadBaseUrl;
    this.referenceToWriteUrl = config.referenceToWriteUrl;
    this.didLogReferenceToWriteUrl = config.didLogReferenceToWriteUrl;

    const presignedConfig: PresignedHttpDIDDocumentSourceConfig = {
      referenceToReadUrl: (documentRef) => this.buildObjectUrl(this.documentReadBaseUrl, this.documentKeyResolver(documentRef)),
      didLogReferenceToReadUrl: (documentRef) => this.buildObjectUrl(this.didLogReadBaseUrl, this.didLogKeyResolver(documentRef)),
      referenceToWriteUrl: (documentRef) => this.resolveDocumentWriteUrl(documentRef),
      didLogReferenceToWriteUrl: (documentRef) => this.resolveDidLogWriteUrl(documentRef),
      fetchFn: config.fetchFn,
      httpSecurity: config.httpSecurity,
      storeMethod: config.storeMethod,
      didLogStoreMethod: config.didLogStoreMethod
    };

    this.source = new PresignedHttpDIDDocumentSource(presignedConfig);
  }

  public async getByReference(documentRef: string): Promise<AgentDIDDocument | null> {
    return this.source.getByReference(documentRef);
  }

  public async storeByReference(documentRef: string, document: AgentDIDDocument): Promise<void> {
    await this.source.storeByReference(documentRef, document);
  }

  public async getDidLogByReference(documentRef: string): Promise<string | null> {
    return this.source.getDidLogByReference(documentRef);
  }

  public async storeDidLogByReference(documentRef: string, didLog: string): Promise<void> {
    await this.source.storeDidLogByReference(documentRef, didLog);
  }

  private resolveDocumentWriteUrl(documentRef: string): string {
    const objectKey = this.documentKeyResolver(documentRef);
    if (this.referenceToWriteUrl) {
      return this.referenceToWriteUrl(documentRef, objectKey);
    }

    return this.buildObjectUrl(this.documentReadBaseUrl, objectKey);
  }

  private resolveDidLogWriteUrl(documentRef: string): string {
    const objectKey = this.didLogKeyResolver(documentRef);
    if (this.didLogReferenceToWriteUrl) {
      return this.didLogReferenceToWriteUrl(documentRef, objectKey);
    }

    return this.buildObjectUrl(this.didLogReadBaseUrl, objectKey);
  }

  private defaultObjectKey(documentRef: string, prefix: string, suffix: string): string {
    const normalizedPrefix = prefix.replace(/^\/+|\/+$/gu, '');
    const encodedRef = encodeURIComponent(documentRef);
    return normalizedPrefix ? `${normalizedPrefix}/${encodedRef}${suffix}` : `${encodedRef}${suffix}`;
  }

  private defaultBaseUrl(config: S3CompatibleDIDDocumentSourceConfig): string {
    const endpoint = new URL(config.endpoint || 'https://s3.amazonaws.com');
    const bucket = config.bucket.replace(/^\/+|\/+$/gu, '');
    const forcePathStyle = config.forcePathStyle !== false;

    if (forcePathStyle) {
      return this.ensureTrailingSlash(new URL(`${bucket}/`, this.ensureTrailingSlash(endpoint.toString())).toString());
    }

    endpoint.hostname = `${bucket}.${endpoint.hostname}`;
    endpoint.pathname = this.ensureTrailingSlash(endpoint.pathname);
    endpoint.search = '';
    endpoint.hash = '';
    return endpoint.toString();
  }

  private buildObjectUrl(baseUrl: string, objectKey: string): string {
    return new URL(objectKey, this.ensureTrailingSlash(baseUrl)).toString();
  }

  private ensureTrailingSlash(value: string): string {
    return value.endsWith('/') ? value : `${value}/`;
  }
}