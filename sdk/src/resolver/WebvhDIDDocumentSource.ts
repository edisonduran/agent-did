import { assertAgentDidDocument } from '../core/document-guard';
import { createSafeFetch } from '../core/safe-fetch';
import { AgentDIDDocument } from '../core/types';
import { validateHttpTarget, HttpSecurityOptions } from '../core/http-security';
import { DIDDocumentSource, DocumentIntegrityError } from './types';
import { DidWebvhError, didWebvhLogRequiresWitnesses, resolveDidWebvhLog } from '../webvh/adapter';

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
  httpSecurity?: HttpSecurityOptions;
}

export class WebvhDIDDocumentSource implements DIDDocumentSource {
  private readonly referenceToUrl: (documentRef: string) => string;
  private readonly referenceToUrls: ((documentRef: string) => string[]) | undefined;
  private readonly fetchFn: FetchLike;
  private readonly httpSecurity: HttpSecurityOptions;

  constructor(config: WebvhDIDDocumentSourceConfig = {}) {
    this.referenceToUrl = config.referenceToUrl || ((documentRef) => documentRef);
    this.referenceToUrls = config.referenceToUrls;
    this.httpSecurity = config.httpSecurity || {};
    this.fetchFn = config.fetchFn || (createSafeFetch(this.httpSecurity) as unknown as FetchLike);
  }

  /**
   * Fetches the did:webvh log and returns the latest state after verifying the
   * whole log (SCID, hash chain, controller-signed proofs and, when the log has
   * witnessed entries, the `did-witness.json` next to it). Throws
   * `DocumentIntegrityError` when verification fails; returns `null` when no
   * endpoint has the log.
   */
  public async getByReference(documentRef: string): Promise<AgentDIDDocument | null> {
    const logText = await this.getDidLogByReference(documentRef);
    if (logText === null) {
      return null;
    }

    try {
      let witnessFile: string | undefined;
      if (didWebvhLogRequiresWitnesses(logText)) {
        if (!/did\.jsonl$/u.test(documentRef)) {
          throw new DocumentIntegrityError(
            `The did:webvh log at ${documentRef} has witnessed entries and its did-witness.json cannot be located`
          );
        }
        const fetched = await this.getDidWitnessFileByReference(documentRef.replace(/did\.jsonl$/u, 'did-witness.json'));
        if (fetched === null) {
          throw new DocumentIntegrityError(`The did:webvh log at ${documentRef} has witnessed entries and no did-witness.json`);
        }
        witnessFile = fetched;
      }
      const resolved = await resolveDidWebvhLog(logText, witnessFile !== undefined ? { witnessFile } : {});
      assertAgentDidDocument(resolved.state, `The did:webvh state at ${documentRef}`);
      return resolved.state;
    } catch (error) {
      if (error instanceof DidWebvhError) {
        throw new DocumentIntegrityError(error.message);
      }
      throw error;
    }
  }

  /** Fetches the raw `did.jsonl` text. The caller must verify it before trusting it. */
  public async getDidLogByReference(documentRef: string): Promise<string | null> {
    return this.fetchText(documentRef, 'did:webvh DID log');
  }

  /**
   * Fetches the raw `did-witness.json` text (ADR-007), with the same SSRF policy and limits as the log. The caller
   * verifies the proofs (`resolveDidWebvhLog`).
   */
  public async getDidWitnessFileByReference(documentRef: string): Promise<string | null> {
    return this.fetchText(documentRef, 'did:webvh witness file');
  }

  private async fetchText(documentRef: string, what: string): Promise<string | null> {
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
        // Blocked by policy is not "not found": the log may well exist.
        allNotFound = false;
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

    throw new Error(`Failed to fetch ${what} from all endpoints. ${errors.join(' | ')}`);
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
