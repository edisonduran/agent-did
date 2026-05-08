import { AgentDIDDocument } from '../core/types';
import { validateHttpTarget, HttpTargetValidationOptions } from '../core/http-security';
import { DIDDocumentSource } from './types';

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

interface DidLogEntry {
  state?: AgentDIDDocument;
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

  public async getByReference(documentRef: string): Promise<AgentDIDDocument | null> {
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
          const logText = await this.readResponseText(response);
          return this.extractLatestState(logText);
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

  private extractLatestState(logText: string): AgentDIDDocument {
    const lines = logText
      .split(/\r?\n/u)
      .map((line) => line.trim())
      .filter((line) => line.length > 0);

    if (lines.length === 0) {
      throw new Error('did:webvh DID log is empty');
    }

    let latestState: AgentDIDDocument | undefined;

    for (const line of lines) {
      let parsed: DidLogEntry;

      try {
        parsed = JSON.parse(line) as DidLogEntry;
      } catch {
        throw new Error('did:webvh DID log contains invalid JSON Lines content');
      }

      if (parsed.state) {
        latestState = parsed.state;
      }
    }

    if (!latestState) {
      throw new Error('did:webvh DID log does not contain a resolvable state entry');
    }

    return latestState;
  }
}