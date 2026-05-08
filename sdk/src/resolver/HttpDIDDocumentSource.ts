import { AgentDIDDocument } from '../core/types';
import { validateHttpTarget, HttpTargetValidationOptions } from '../core/http-security';
import { DIDDocumentSource } from './types';

type FetchLikeResponse = {
  ok: boolean;
  status: number;
  json?: () => Promise<unknown>;
  text?: () => Promise<string>;
};

type FetchLikeInit = {
  method?: string;
  headers?: Record<string, string>;
  body?: string;
};

type FetchLike = (url: string, init?: FetchLikeInit) => Promise<FetchLikeResponse>;

export interface HttpDIDDocumentSourceConfig {
  referenceToUrl?: (documentRef: string) => string;
  referenceToUrls?: (documentRef: string) => string[];
  fetchFn?: FetchLike;
  ipfsGateways?: string[];
  httpSecurity?: HttpTargetValidationOptions;
  storeMethod?: string;
  didLogStoreMethod?: string;
}

export class HttpDIDDocumentSource implements DIDDocumentSource {
  private readonly referenceToUrl: (documentRef: string) => string;
  private readonly referenceToUrls: ((documentRef: string) => string[]) | undefined;
  private readonly fetchFn: FetchLike;
  private readonly ipfsGateways: string[];
  private readonly httpSecurity: HttpTargetValidationOptions;
  private readonly storeMethod: string;
  private readonly didLogStoreMethod: string;

  constructor(config: HttpDIDDocumentSourceConfig = {}) {
    this.referenceToUrl = config.referenceToUrl || ((documentRef) => documentRef);
    this.referenceToUrls = config.referenceToUrls;
    this.fetchFn = config.fetchFn || (globalThis.fetch as unknown as FetchLike);
    this.ipfsGateways = config.ipfsGateways || [
      'https://cloudflare-ipfs.com/ipfs/',
      'https://ipfs.io/ipfs/'
    ];
    this.httpSecurity = config.httpSecurity || {};
    this.storeMethod = (config.storeMethod || 'PUT').toUpperCase();
    this.didLogStoreMethod = (config.didLogStoreMethod || this.storeMethod).toUpperCase();
  }

  public async getByReference(documentRef: string): Promise<AgentDIDDocument | null> {
    if (!this.fetchFn) {
      throw new Error('No fetch implementation available for HttpDIDDocumentSource');
    }

    const urls = this.resolveCandidateUrls(documentRef);
    const errors: string[] = [];
    let allNotFound = true;

    for (const url of urls) {
      try {
        validateHttpTarget(url, this.httpSecurity);
      } catch {
        errors.push(`${url}: blocked by SSRF policy`);
        continue;
      }
      try {
        const response = await this.fetchFn(url);

        if (response.ok) {
          return this.readResponseJson(response);
        }

        if (response.status !== 404) {
          allNotFound = false;
          errors.push(`${url}: HTTP ${response.status}`);
        }
      } catch (error) {
        allNotFound = false;
        const message = error instanceof Error ? error.message : String(error);
        errors.push(`${url}: ${message}`);
      }
    }

    if (allNotFound) {
      return null;
    }

    throw new Error(`Failed to fetch DID document from all endpoints. ${errors.join(' | ')}`);
  }

  public async storeByReference(documentRef: string, document: AgentDIDDocument): Promise<void> {
    await this.writeReference(
      this.resolvePrimaryUrl(documentRef),
      JSON.stringify(document),
      this.storeMethod,
      'application/json; charset=utf-8'
    );
  }

  public async getDidLogByReference(documentRef: string): Promise<string | null> {
    if (!this.fetchFn) {
      throw new Error('No fetch implementation available for HttpDIDDocumentSource');
    }

    const urls = this.resolveCandidateUrls(documentRef);
    const errors: string[] = [];
    let allNotFound = true;

    for (const url of urls) {
      try {
        validateHttpTarget(url, this.httpSecurity);
      } catch {
        errors.push(`${url}: blocked by SSRF policy`);
        continue;
      }

      try {
        const response = await this.fetchFn(url);

        if (response.ok) {
          return this.readResponseText(response);
        }

        if (response.status !== 404) {
          allNotFound = false;
          errors.push(`${url}: HTTP ${response.status}`);
        }
      } catch (error) {
        allNotFound = false;
        const message = error instanceof Error ? error.message : String(error);
        errors.push(`${url}: ${message}`);
      }
    }

    if (allNotFound) {
      return null;
    }

    throw new Error(`Failed to fetch did:webvh DID log from all endpoints. ${errors.join(' | ')}`);
  }

  public async storeDidLogByReference(documentRef: string, didLog: string): Promise<void> {
    await this.writeReference(
      this.resolvePrimaryUrl(documentRef),
      didLog,
      this.didLogStoreMethod,
      'application/jsonl; charset=utf-8'
    );
  }

  private resolveCandidateUrls(documentRef: string): string[] {
    if (this.referenceToUrls) {
      return this.referenceToUrls(documentRef);
    }

    if (documentRef.startsWith('ipfs://')) {
      const cidPath = documentRef.slice('ipfs://'.length).replace(/^\/+/, '');
      return this.ipfsGateways.map((gateway) => `${gateway.replace(/\/+$/, '')}/${cidPath}`);
    }

    return [this.referenceToUrl(documentRef)];
  }

  private resolvePrimaryUrl(documentRef: string): string {
    const urls = this.resolveCandidateUrls(documentRef);
    if (urls.length === 0) {
      throw new Error(`No HTTP target candidates configured for reference: ${documentRef}`);
    }

    return urls[0];
  }

  private async writeReference(
    url: string,
    body: string,
    method: string,
    contentType: string
  ): Promise<void> {
    if (!this.fetchFn) {
      throw new Error('No fetch implementation available for HttpDIDDocumentSource');
    }

    try {
      validateHttpTarget(url, this.httpSecurity);
    } catch {
      throw new Error(`${url}: blocked by SSRF policy`);
    }

    const response = await this.fetchFn(url, {
      method,
      headers: {
        'content-type': contentType
      },
      body
    });

    if (!response.ok) {
      throw new Error(`Failed to write remote DID content. ${url}: HTTP ${response.status}`);
    }
  }

  private async readResponseText(response: FetchLikeResponse): Promise<string> {
    if (response.text) {
      return response.text();
    }

    if (response.json) {
      const body = await response.json();
      if (typeof body === 'string') {
        return body;
      }
    }

    throw new Error('HTTP DID-log response does not expose a readable text body');
  }

  private async readResponseJson(response: FetchLikeResponse): Promise<AgentDIDDocument> {
    if (!response.json) {
      throw new Error('HTTP DID document response does not expose a readable JSON body');
    }

    return response.json() as Promise<AgentDIDDocument>;
  }
}
