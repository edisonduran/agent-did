import { AgentDIDDocument } from '../core/types';
import { HttpDIDDocumentSource, HttpDIDDocumentSourceConfig } from './HttpDIDDocumentSource';
import { DIDDocumentSource } from './types';

export interface PresignedHttpDIDDocumentSourceConfig {
  referenceToReadUrl?: HttpDIDDocumentSourceConfig['referenceToUrl'];
  referenceToReadUrls?: HttpDIDDocumentSourceConfig['referenceToUrls'];
  didLogReferenceToReadUrl?: HttpDIDDocumentSourceConfig['referenceToUrl'];
  didLogReferenceToReadUrls?: HttpDIDDocumentSourceConfig['referenceToUrls'];
  referenceToWriteUrl?: HttpDIDDocumentSourceConfig['referenceToUrl'];
  didLogReferenceToWriteUrl?: HttpDIDDocumentSourceConfig['referenceToUrl'];
  fetchFn?: HttpDIDDocumentSourceConfig['fetchFn'];
  ipfsGateways?: HttpDIDDocumentSourceConfig['ipfsGateways'];
  httpSecurity?: HttpDIDDocumentSourceConfig['httpSecurity'];
  storeMethod?: HttpDIDDocumentSourceConfig['storeMethod'];
  didLogStoreMethod?: HttpDIDDocumentSourceConfig['didLogStoreMethod'];
}

export class PresignedHttpDIDDocumentSource implements DIDDocumentSource {
  private readonly documentReadSource: HttpDIDDocumentSource;
  private readonly didLogReadSource: HttpDIDDocumentSource;
  private readonly documentWriteSource: HttpDIDDocumentSource;
  private readonly didLogWriteSource: HttpDIDDocumentSource;

  constructor(config: PresignedHttpDIDDocumentSourceConfig = {}) {
    const fallbackReadUrl = config.referenceToReadUrl || config.referenceToWriteUrl || ((documentRef: string) => documentRef);
    const fallbackDidLogReadUrl = config.didLogReferenceToReadUrl || config.referenceToReadUrl || config.didLogReferenceToWriteUrl || config.referenceToWriteUrl || ((documentRef: string) => documentRef);
    const fallbackWriteUrl = config.referenceToWriteUrl || config.referenceToReadUrl || ((documentRef: string) => documentRef);
    const fallbackDidLogWriteUrl = config.didLogReferenceToWriteUrl || config.referenceToWriteUrl || config.referenceToReadUrl || ((documentRef: string) => documentRef);

    this.documentReadSource = new HttpDIDDocumentSource({
      referenceToUrl: fallbackReadUrl,
      referenceToUrls: config.referenceToReadUrls,
      fetchFn: config.fetchFn,
      ipfsGateways: config.ipfsGateways,
      httpSecurity: config.httpSecurity
    });
    this.didLogReadSource = new HttpDIDDocumentSource({
      referenceToUrl: fallbackDidLogReadUrl,
      referenceToUrls: config.didLogReferenceToReadUrls || config.referenceToReadUrls,
      fetchFn: config.fetchFn,
      ipfsGateways: config.ipfsGateways,
      httpSecurity: config.httpSecurity
    });
    this.documentWriteSource = new HttpDIDDocumentSource({
      referenceToUrl: fallbackWriteUrl,
      fetchFn: config.fetchFn,
      httpSecurity: config.httpSecurity,
      storeMethod: config.storeMethod
    });
    this.didLogWriteSource = new HttpDIDDocumentSource({
      referenceToUrl: fallbackDidLogWriteUrl,
      fetchFn: config.fetchFn,
      httpSecurity: config.httpSecurity,
      storeMethod: config.storeMethod,
      didLogStoreMethod: config.didLogStoreMethod
    });
  }

  public async getByReference(documentRef: string): Promise<AgentDIDDocument | null> {
    return this.documentReadSource.getByReference(documentRef);
  }

  public async storeByReference(documentRef: string, document: AgentDIDDocument): Promise<void> {
    await this.documentWriteSource.storeByReference(documentRef, document);
  }

  public async getDidLogByReference(documentRef: string): Promise<string | null> {
    return this.didLogReadSource.getDidLogByReference(documentRef);
  }

  public async storeDidLogByReference(documentRef: string, didLog: string): Promise<void> {
    await this.didLogWriteSource.storeDidLogByReference(documentRef, didLog);
  }
}