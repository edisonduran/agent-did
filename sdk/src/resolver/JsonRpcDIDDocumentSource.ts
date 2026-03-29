import { AgentDIDDocument } from '../core/types';
import { validateHttpTarget, HttpTargetValidationOptions } from '../core/http-security';
import { DIDDocumentSource } from './types';

type JsonRpcResponse = {
  ok: boolean;
  status: number;
  json: () => Promise<unknown>;
};

type JsonRpcTransport = (url: string, body: string, headers: Record<string, string>) => Promise<JsonRpcResponse>;

interface JsonRpcErrorPayload {
  code?: number;
  message?: string;
  data?: unknown;
}

interface JsonRpcEnvelope {
  result?: unknown;
  error?: JsonRpcErrorPayload;
}

export interface JsonRpcDIDDocumentSourceConfig {
  endpoint?: string;
  endpoints?: string[];
  method?: string;
  buildParams?: (documentRef: string) => unknown[];
  transport?: JsonRpcTransport;
  headers?: Record<string, string>;
  httpSecurity?: HttpTargetValidationOptions;
}

export class JsonRpcDIDDocumentSource implements DIDDocumentSource {
  private readonly endpoints: string[];
  private readonly method: string;
  private readonly buildParams: (documentRef: string) => unknown[];
  private readonly transport: JsonRpcTransport;
  private readonly headers: Record<string, string>;
  private readonly httpSecurity: HttpTargetValidationOptions;

  constructor(config: JsonRpcDIDDocumentSourceConfig = {}) {
    this.endpoints = config.endpoints || (config.endpoint ? [config.endpoint] : []);
    this.method = config.method || 'agent_resolveDocumentRef';
    this.buildParams = config.buildParams || ((documentRef: string) => [documentRef]);
    this.transport = config.transport || this.defaultTransport;
    this.headers = {
      'content-type': 'application/json',
      ...(config.headers || {})
    };
    this.httpSecurity = config.httpSecurity || {};

    if (this.endpoints.length === 0) {
      throw new Error('JsonRpcDIDDocumentSource requires at least one endpoint');
    }
  }

  public async getByReference(documentRef: string): Promise<AgentDIDDocument | null> {
    const payload = JSON.stringify({
      jsonrpc: '2.0',
      id: Date.now(),
      method: this.method,
      params: this.buildParams(documentRef)
    });

    const errors: string[] = [];
    let hadValidEndpoint = false;

    for (const endpoint of this.endpoints) {
      try {
        validateHttpTarget(endpoint, this.httpSecurity);
      } catch {
        continue;
      }

      hadValidEndpoint = true;

      try {
        const response = await this.transport(endpoint, payload, this.headers);

        if (!response.ok) {
          errors.push(`${endpoint}: HTTP ${response.status}`);
          continue;
        }

        const responseBody = await response.json() as JsonRpcEnvelope;

        if (responseBody.error) {
          if (responseBody.error.code === 404 || responseBody.error.code === -32004) {
            continue;
          }

          errors.push(`${endpoint}: RPC ${responseBody.error.code ?? 'unknown'} ${responseBody.error.message ?? ''}`.trim());
          continue;
        }

        if (!responseBody.result) {
          continue;
        }

        return responseBody.result as AgentDIDDocument;
      } catch (error) {
        const message = error instanceof Error ? error.message : String(error);
        errors.push(`${endpoint}: ${message}`);
      }
    }

    if (errors.length === 0 || !hadValidEndpoint) {
      return null;
    }

    throw new Error(`Failed to resolve DID document via JSON-RPC endpoints. ${errors.join(' | ')}`);
  }

  private defaultTransport = async (url: string, body: string, headers: Record<string, string>): Promise<JsonRpcResponse> => {
    const fetchFn = globalThis.fetch as unknown as (
      input: string,
      init: { method: string; headers: Record<string, string>; body: string }
    ) => Promise<JsonRpcResponse>;

    if (!fetchFn) {
      throw new Error('No fetch implementation available for JsonRpcDIDDocumentSource');
    }

    return fetchFn(url, {
      method: 'POST',
      headers,
      body
    });
  };
}
