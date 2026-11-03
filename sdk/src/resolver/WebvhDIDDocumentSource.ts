import { AgentDIDDocument } from '../core/types';
import { validateHttpTarget, HttpTargetValidationOptions } from '../core/http-security';
import { DIDDocumentSource, DocumentIntegrityError } from './types';
import { DidWebvhError, resolveDidWebvhLog } from '../webvh/adapter';

type FetchLikeResponse = {
  ok: boolean;
  status: number;
  text?: () => Promise<string>;
  json?: () => Promise<unknown>;
};

type FetchLike = (url: string) => Promise<FetchLikeResponse>;

export interface WebvhDIDDocumentSourceConfig {
  referenceToUrl?: (documentRef: string) => string;
  referenceToUrls?: (documentRef: string) => string[];
  fetchFn?: FetchLike;
  httpSecurity?: HttpTargetValidationOptions;
}

export class WebvhDIDDocumentSource implements DIDDocumentSource {
  private readonly referenceToUrl: (documentRef: string) => string;
  private readonly referenceToUrls: ((documentRef: string) => string[]) | undefined;
  private readonly fetchFn: FetchLike;
  private readonly httpSecurity: HttpTargetValidationOptions;

  constructor(config: WebvhDIDDocumentSourceConfig = {}) {
    this.referenceToUrl = config.referenceToUrl || ((documentRef) => documentRef);
    this.referenceToUrls = config.referenceToUrls;
    this.fetchFn = config.fetchFn || (globalThis.fetch as unknown as FetchLike);
    this.httpSecurity = config.httpSecurity || {};
  }

  /**
   * Fetches the did:webvh log and returns the latest state after verifying the
   * whole log (SCID, hash chain, controller-signed proofs). Throws
   * `DocumentIntegrityError` when verification fails; returns `null` when no
   * endpoint has the log.
   */
  public async getByReference(documentRef: string): Promise<AgentDIDDocument | null> {
    const logText = await this.getDidLogByReference(documentRef);
    if (logText === null) {
      return null;
    }

    try {
      const resolved = await resolveDidWebvhLog(logText);
      return resolved.state as unknown as AgentDIDDocument;
    } catch (error) {
      if (error instanceof DidWebvhError) {
        throw new DocumentIntegrityError(error.message);
      }
      throw error;
    }
  }

  /** Fetches the raw `did.jsonl` text. The caller must verify it before trusting it. */
  public async getDidLogByReference(documentRef: string): Promise<string | null> {
    if (!this.fetchFn) {
      throw new Error('No fetch implementation available for WebvhDIDDocumentSource');
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
          return await this.readResponseText(response);
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

  private resolveCandidateUrls(documentRef: string): string[] {
    if (this.referenceToUrls) {
      return this.referenceToUrls(documentRef);
    }

    return [this.referenceToUrl(documentRef)];
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

    throw new Error('did:webvh response does not expose a readable text body');
  }
}
