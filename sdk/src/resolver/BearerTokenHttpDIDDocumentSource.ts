import { AgentDIDDocument } from '../core/types';
import { HttpDIDDocumentSource, HttpDIDDocumentSourceConfig } from './HttpDIDDocumentSource';
import { DIDDocumentSource } from './types';

type FetchLike = NonNullable<HttpDIDDocumentSourceConfig['fetchFn']>;
type FetchLikeInit = NonNullable<Parameters<FetchLike>[1]>;

export interface BearerTokenHttpDIDDocumentSourceConfig {
  token?: string;
  getToken?: () => string | Promise<string>;
  headerName?: string;
  scheme?: string;
  referenceToUrl?: HttpDIDDocumentSourceConfig['referenceToUrl'];
  referenceToUrls?: HttpDIDDocumentSourceConfig['referenceToUrls'];
  fetchFn?: HttpDIDDocumentSourceConfig['fetchFn'];
  ipfsGateways?: HttpDIDDocumentSourceConfig['ipfsGateways'];
  httpSecurity?: HttpDIDDocumentSourceConfig['httpSecurity'];
  storeMethod?: HttpDIDDocumentSourceConfig['storeMethod'];
  didLogStoreMethod?: HttpDIDDocumentSourceConfig['didLogStoreMethod'];
}

export class BearerTokenHttpDIDDocumentSource implements DIDDocumentSource {
  private readonly source: HttpDIDDocumentSource;
  private readonly headerName: string;
  private readonly scheme: string;
  private readonly token: string | undefined;
  private readonly getToken: (() => string | Promise<string>) | undefined;

  constructor(config: BearerTokenHttpDIDDocumentSourceConfig) {
    this.headerName = (config.headerName || 'authorization').toLowerCase();
    this.scheme = config.scheme === undefined ? 'Bearer' : config.scheme;
    this.token = config.token;
    this.getToken = config.getToken;

    this.source = new HttpDIDDocumentSource({
      referenceToUrl: config.referenceToUrl,
      referenceToUrls: config.referenceToUrls,
      fetchFn: this.createAuthenticatedFetchFn(config),
      ipfsGateways: config.ipfsGateways,
      httpSecurity: config.httpSecurity,
      storeMethod: config.storeMethod,
      didLogStoreMethod: config.didLogStoreMethod
    });
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

  private createAuthenticatedFetchFn(config: BearerTokenHttpDIDDocumentSourceConfig): FetchLike {
    const baseFetch = config.fetchFn || (globalThis.fetch as unknown as FetchLike);
    if (!baseFetch) {
      throw new Error('No fetch implementation available for BearerTokenHttpDIDDocumentSource');
    }

    return async (url: string, init?: FetchLikeInit) => {
      const token = await this.resolveToken();
      const headers = Object.fromEntries(
        Object.entries(init?.headers || {}).map(([key, value]) => [key.toLowerCase(), value])
      );
      headers[this.headerName] = this.formatToken(token);

      return baseFetch(url, {
        ...init,
        headers
      });
    };
  }

  private async resolveToken(): Promise<string> {
    if (this.getToken) {
      const token = await this.getToken();
      if (!token) {
        throw new Error('BearerTokenHttpDIDDocumentSource received an empty token from getToken');
      }
      return token;
    }

    if (!this.token) {
      throw new Error('BearerTokenHttpDIDDocumentSource requires token or getToken');
    }

    return this.token;
  }

  private formatToken(token: string): string {
    return this.scheme ? `${this.scheme} ${token}` : token;
  }
}