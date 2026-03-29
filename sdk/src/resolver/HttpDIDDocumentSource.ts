import { AgentDIDDocument } from '../core/types';
import { validateHttpTarget, HttpTargetValidationOptions } from '../core/http-security';
import { DIDDocumentSource } from './types';

type FetchLikeResponse = {
  ok: boolean;
  status: number;
  json: () => Promise<unknown>;
};

type FetchLike = (url: string) => Promise<FetchLikeResponse>;

export interface HttpDIDDocumentSourceConfig {
  referenceToUrl?: (documentRef: string) => string;
  referenceToUrls?: (documentRef: string) => string[];
  fetchFn?: FetchLike;
  ipfsGateways?: string[];
  httpSecurity?: HttpTargetValidationOptions;
}

export class HttpDIDDocumentSource implements DIDDocumentSource {
  private readonly referenceToUrl: (documentRef: string) => string;
  private readonly referenceToUrls: ((documentRef: string) => string[]) | undefined;
  private readonly fetchFn: FetchLike;
  private readonly ipfsGateways: string[];
  private readonly httpSecurity: HttpTargetValidationOptions;

  constructor(config: HttpDIDDocumentSourceConfig = {}) {
    this.referenceToUrl = config.referenceToUrl || ((documentRef) => documentRef);
    this.referenceToUrls = config.referenceToUrls;
    this.fetchFn = config.fetchFn || (globalThis.fetch as unknown as FetchLike);
    this.ipfsGateways = config.ipfsGateways || [
      'https://cloudflare-ipfs.com/ipfs/',
      'https://ipfs.io/ipfs/'
    ];
    this.httpSecurity = config.httpSecurity || {};
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
          return response.json() as Promise<AgentDIDDocument>;
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
}
