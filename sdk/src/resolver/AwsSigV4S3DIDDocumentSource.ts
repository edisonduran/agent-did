import { ethers } from 'ethers';
import { AgentDIDDocument } from '../core/types';
import { HttpDIDDocumentSourceConfig } from './HttpDIDDocumentSource';
import {
  S3CompatibleDIDDocumentSource,
  S3CompatibleDIDDocumentSourceConfig
} from './S3CompatibleDIDDocumentSource';
import { DIDDocumentSource } from './types';

export interface AwsSigV4S3DIDDocumentSourceConfig extends Omit<S3CompatibleDIDDocumentSourceConfig, 'fetchFn'> {
  region: string;
  accessKeyId: string;
  secretAccessKey: string;
  sessionToken?: string;
  service?: string;
  fetchFn?: HttpDIDDocumentSourceConfig['fetchFn'];
  now?: () => Date;
}

type FetchLike = NonNullable<HttpDIDDocumentSourceConfig['fetchFn']>;
type FetchLikeInit = NonNullable<Parameters<FetchLike>[1]>;

const EMPTY_PAYLOAD_HASH = ethers.sha256(ethers.toUtf8Bytes('')).slice(2);

export class AwsSigV4S3DIDDocumentSource implements DIDDocumentSource {
  private readonly source: S3CompatibleDIDDocumentSource;

  constructor(private readonly config: AwsSigV4S3DIDDocumentSourceConfig) {
    this.source = new S3CompatibleDIDDocumentSource({
      ...config,
      fetchFn: this.createSignedFetchFn(config)
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

  private createSignedFetchFn(config: AwsSigV4S3DIDDocumentSourceConfig): FetchLike {
    const baseFetch = config.fetchFn || (globalThis.fetch as unknown as FetchLike);
    if (!baseFetch) {
      throw new Error('No fetch implementation available for AwsSigV4S3DIDDocumentSource');
    }

    return async (url: string, init?: FetchLikeInit) => {
      const signedInit = this.signRequest(url, init || {});
      return baseFetch(url, signedInit);
    };
  }

  private signRequest(url: string, init: FetchLikeInit): FetchLikeInit {
    const requestUrl = new URL(url);
    const method = (init.method || 'GET').toUpperCase();
    const body = init.body || '';
    const payloadHash = this.hashHex(body);
    const timestamp = this.config.now ? this.config.now() : new Date();
    const amzDate = this.formatAmzDate(timestamp);
    const dateStamp = amzDate.slice(0, 8);
    const headers = this.normalizeHeaders(init.headers);

    headers.host = requestUrl.host;
    headers['x-amz-date'] = amzDate;
    headers['x-amz-content-sha256'] = payloadHash;

    if (this.config.sessionToken) {
      headers['x-amz-security-token'] = this.config.sessionToken;
    }

    const canonicalHeaders = this.buildCanonicalHeaders(headers);
    const signedHeaders = Object.keys(canonicalHeaders).join(';');
    const canonicalRequest = [
      method,
      this.buildCanonicalUri(requestUrl),
      this.buildCanonicalQuery(requestUrl),
      `${Object.entries(canonicalHeaders)
        .map(([key, value]) => `${key}:${value}`)
        .join('\n')}\n`,
      signedHeaders,
      payloadHash
    ].join('\n');

    const scope = `${dateStamp}/${this.config.region}/${this.config.service || 's3'}/aws4_request`;
    const stringToSign = [
      'AWS4-HMAC-SHA256',
      amzDate,
      scope,
      this.hashHex(canonicalRequest)
    ].join('\n');

    const signature = this.signHex(stringToSign, dateStamp);
    headers.authorization = [
      'AWS4-HMAC-SHA256',
      `Credential=${this.config.accessKeyId}/${scope},`,
      `SignedHeaders=${signedHeaders},`,
      `Signature=${signature}`
    ].join(' ');

    return {
      ...init,
      method,
      headers,
      body: init.body
    };
  }

  private buildCanonicalHeaders(headers: Record<string, string>): Record<string, string> {
    return Object.fromEntries(
      Object.entries(headers)
        .map(([key, value]) => [key.toLowerCase(), value.trim().replace(/\s+/gu, ' ')])
        .sort(([left], [right]) => left.localeCompare(right))
    );
  }

  private normalizeHeaders(headers: Record<string, string> | undefined): Record<string, string> {
    return Object.fromEntries(
      Object.entries(headers || {}).map(([key, value]) => [key.toLowerCase(), value])
    );
  }

  private buildCanonicalUri(url: URL): string {
    const pathname = url.pathname || '/';
    return pathname
      .split('/')
      .map((segment) => this.encodeRfc3986(decodeURIComponent(segment)))
      .join('/');
  }

  private buildCanonicalQuery(url: URL): string {
    return Array.from(url.searchParams.entries())
      .map(([key, value]) => [this.encodeRfc3986(key), this.encodeRfc3986(value)] as const)
      .sort(([leftKey, leftValue], [rightKey, rightValue]) => {
        if (leftKey === rightKey) {
          return leftValue.localeCompare(rightValue);
        }

        return leftKey.localeCompare(rightKey);
      })
      .map(([key, value]) => `${key}=${value}`)
      .join('&');
  }

  private signHex(stringToSign: string, dateStamp: string): string {
    const service = this.config.service || 's3';
    const kDate = ethers.computeHmac('sha256', ethers.toUtf8Bytes(`AWS4${this.config.secretAccessKey}`), ethers.toUtf8Bytes(dateStamp));
    const kRegion = ethers.computeHmac('sha256', kDate, ethers.toUtf8Bytes(this.config.region));
    const kService = ethers.computeHmac('sha256', kRegion, ethers.toUtf8Bytes(service));
    const kSigning = ethers.computeHmac('sha256', kService, ethers.toUtf8Bytes('aws4_request'));
    return ethers.computeHmac('sha256', kSigning, ethers.toUtf8Bytes(stringToSign)).slice(2);
  }

  private hashHex(value: string): string {
    if (!value) {
      return EMPTY_PAYLOAD_HASH;
    }

    return ethers.sha256(ethers.toUtf8Bytes(value)).slice(2);
  }

  private formatAmzDate(value: Date): string {
    return value.toISOString().replace(/[:-]|\.\d{3}/gu, '');
  }

  private encodeRfc3986(value: string): string {
    return encodeURIComponent(value).replace(/[!'()*]/gu, (character) => `%${character.charCodeAt(0).toString(16).toUpperCase()}`);
  }
}