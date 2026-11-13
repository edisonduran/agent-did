/**
 * Default `fetch` for the SDK's HTTP sources.
 *
 * - Redirects are not followed: targets are validated before the request is sent, so a redirect
 *   would move it to a destination that was never validated. A 3xx surfaces as a non-OK status.
 * - Host names are resolved once, at connection time, and the connection is refused when any
 *   resolved address is not globally routable. The address that was validated is the address that
 *   is connected to, so a DNS answer that changes after the check (rebinding) cannot redirect the
 *   request. TLS still verifies the original host name. Each request opens its own connection, never a pooled
 *   one, so a socket another part of the process opened to the same host is not reused unchecked.
 *
 * - Every request has one deadline (`timeoutMs`) covering lookup, connection and the whole body,
 *   and a maximum body size (`maxResponseBytes`). It asks for an unencoded body and rejects any
 *   other `Content-Encoding`, so the size limit applies to the bytes that are parsed.
 *
 * IP literals and `allowPrivateTargets` use the platform `fetch` (with redirects disabled and the
 * same limits), since there is nothing to resolve or the caller opted out. Callers that supply
 * their own `fetchFn` own their redirect, DNS and limit policy. Node.js only: it relies on
 * `node:http`, `node:https` and `node:dns`.
 */
import { HttpSecurityOptions, HttpTargetValidationOptions, isNonGlobalAddress, resolveHttpClientLimits } from './http-security';

type AnyInit = Record<string, unknown> | undefined;
type LookupFn = (hostname: string) => Promise<Array<{ address: string }>>;

export interface SafeFetchResponse {
  ok: boolean;
  status: number;
  headers: Headers;
  text: () => Promise<string>;
  json: () => Promise<unknown>;
}

async function defaultLookup(hostname: string): Promise<Array<{ address: string }>> {
  const dns = await import('node:dns');
  return dns.promises.lookup(hostname, { all: true, verbatim: true });
}

function isIpLiteral(hostname: string): boolean {
  return hostname.startsWith('[') || /^[\d.]+$/.test(hostname) || hostname.includes(':');
}

/**
 * Resolves `hostname` and returns its addresses, throwing when the name cannot be resolved or any
 * address is not allowed (fail closed).
 */
async function resolveAllowedAddresses(
  hostname: string,
  lookup: LookupFn,
  isBlockedAddress: (address: string) => boolean
): Promise<Array<{ address: string; family: number }>> {
  let addresses: Array<{ address: string }>;
  try {
    addresses = await lookup(hostname);
  } catch {
    throw new Error(`Blocked request: could not resolve ${hostname}`);
  }
  if (addresses.length === 0 || addresses.some(({ address }) => isBlockedAddress(address))) {
    throw new Error(`Blocked request to private/reserved address: ${hostname}`);
  }
  return addresses.map(({ address }) => ({ address, family: address.includes(':') ? 6 : 4 }));
}

/** Resolves the host of `url` and throws unless every address is globally routable. */
export async function assertResolvedTargetAllowed(
  url: string,
  options: HttpTargetValidationOptions = {},
  lookup: LookupFn = defaultLookup
): Promise<void> {
  if (options.allowPrivateTargets) return;

  const hostname = new URL(url).hostname;
  if (isIpLiteral(hostname)) return; // already classified by validateHttpTarget

  await resolveAllowedAddresses(hostname, lookup, isNonGlobalAddress);
}

interface ClientLimits {
  timeoutMs: number;
  maxResponseBytes: number;
}

function hostOf(url: string): string {
  return new URL(url).host;
}

function deadlineError(url: string, limits: ClientLimits): Error {
  return new Error(`Request to ${hostOf(url)} exceeded the ${limits.timeoutMs} ms deadline`);
}

function tooLargeError(url: string, limits: ClientLimits): Error {
  return new Error(`Response from ${hostOf(url)} exceeds the ${limits.maxResponseBytes}-byte limit`);
}

/** Throws unless the body is unencoded, so the size limit applies to the bytes that are parsed. */
function assertIdentityEncoding(url: string, contentEncoding: string | null | undefined): void {
  if (contentEncoding && contentEncoding.trim().toLowerCase() !== 'identity') {
    throw new Error(
      `Response from ${hostOf(url)} uses Content-Encoding "${contentEncoding}"; the SDK HTTP client accepts only unencoded bodies`
    );
  }
}

function assertDeclaredLength(url: string, contentLength: string | null | undefined, limits: ClientLimits): void {
  if (contentLength && Number(contentLength) > limits.maxResponseBytes) {
    throw tooLargeError(url, limits);
  }
}

/** Request headers as strings, asking for an unencoded body whatever the caller set. */
function requestHeaders(init: Record<string, unknown>): Record<string, string> {
  const headers = Object.fromEntries(
    Object.entries((init.headers as Record<string, string> | undefined) || {})
      .filter(([key]) => key.toLowerCase() !== 'accept-encoding')
      .map(([key, value]) => [key, String(value)])
  );
  headers['accept-encoding'] = 'identity';
  return headers;
}

function toSafeResponse(status: number, headers: Headers, text: string): SafeFetchResponse {
  return {
    ok: status >= 200 && status <= 299,
    status,
    headers,
    text: async () => text,
    json: async () => JSON.parse(text)
  };
}

function decodeUtf8(chunks: Uint8Array[], size: number): string {
  const bytes = new Uint8Array(size);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return new TextDecoder().decode(bytes);
}

async function pinnedRequest(
  url: string,
  init: Record<string, unknown>,
  lookup: LookupFn,
  isBlockedAddress: (address: string) => boolean,
  limits: ClientLimits
): Promise<SafeFetchResponse> {
  const parsed = new URL(url);
  const transport = parsed.protocol === 'https:' ? await import('node:https') : await import('node:http');

  // Called by the socket right before connecting, so the addresses validated here are the ones used.
  const validatedLookup = (
    hostname: string,
    opts: { all?: boolean },
    callback: (err: Error | null, address?: unknown, family?: number) => void
  ): void => {
    resolveAllowedAddresses(hostname, lookup, isBlockedAddress).then(
      (addresses) => (opts && opts.all ? callback(null, addresses) : callback(null, addresses[0].address, addresses[0].family)),
      (error: Error) => callback(error)
    );
  };

  const headers = requestHeaders(init);
  const body = init.body === undefined || init.body === null ? undefined : String(init.body);
  if (body !== undefined && !Object.keys(headers).some((k) => k.toLowerCase() === 'content-length')) {
    headers['content-length'] = String(Buffer.byteLength(body));
  }

  return new Promise<SafeFetchResponse>((resolve, reject) => {
    let settled = false;
    let request: ReturnType<typeof transport.request> | undefined;
    const fail = (error: Error): void => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      request?.destroy();
      reject(error);
    };
    // One deadline for the whole request: lookup, connection, headers and every body byte.
    const timer = setTimeout(() => fail(deadlineError(url, limits)), limits.timeoutMs);

    request = transport.request(
      {
        protocol: parsed.protocol,
        hostname: parsed.hostname.replace(/^\[|\]$/g, ''),
        port: parsed.port || undefined,
        path: `${parsed.pathname}${parsed.search}`,
        method: String(init.method || 'GET').toUpperCase(),
        headers,
        lookup: validatedLookup as never,
        // A connection of its own: a pooled keep-alive socket to the same host and port (from the global agent,
        // opened by other code in the process) would be reused without going through `validatedLookup`.
        agent: false
      },
      (res) => {
        try {
          assertIdentityEncoding(url, res.headers['content-encoding']);
          assertDeclaredLength(url, res.headers['content-length'], limits);
        } catch (error) {
          fail(error as Error);
          return;
        }
        const chunks: Uint8Array[] = [];
        let size = 0;
        res.on('data', (chunk: Uint8Array) => {
          size += chunk.byteLength;
          if (size > limits.maxResponseBytes) {
            fail(tooLargeError(url, limits));
            return;
          }
          chunks.push(chunk);
        });
        res.on('error', fail);
        res.on('end', () => {
          if (settled) return;
          settled = true;
          clearTimeout(timer);
          const responseHeaders = new Headers();
          for (const [key, value] of Object.entries(res.headers)) {
            if (value !== undefined) responseHeaders.set(key, Array.isArray(value) ? value.join(', ') : value);
          }
          resolve(toSafeResponse(res.statusCode || 0, responseHeaders, decodeUtf8(chunks, size)));
        });
      }
    );
    request.on('error', fail);
    if (body !== undefined) request.write(body);
    request.end();
  });
}

/** The platform `fetch` (IP literals, `allowPrivateTargets`), with redirects off and the same limits. */
async function platformRequest(url: string, init: Record<string, unknown>, limits: ClientLimits): Promise<SafeFetchResponse> {
  const signal = AbortSignal.timeout(limits.timeoutMs);
  try {
    const response = await globalThis.fetch(url, {
      ...init,
      headers: requestHeaders(init),
      redirect: 'manual',
      signal
    } as RequestInit);
    assertIdentityEncoding(url, response.headers.get('content-encoding'));
    assertDeclaredLength(url, response.headers.get('content-length'), limits);

    const chunks: Uint8Array[] = [];
    let size = 0;
    const reader = response.body?.getReader();
    while (reader) {
      const { done, value } = await reader.read();
      if (done) break;
      size += value.byteLength;
      if (size > limits.maxResponseBytes) {
        await reader.cancel().catch(() => undefined);
        throw tooLargeError(url, limits);
      }
      chunks.push(value);
    }
    return toSafeResponse(response.status, response.headers, decodeUtf8(chunks, size));
  } catch (error) {
    if (signal.aborted) {
      throw deadlineError(url, limits);
    }
    throw error;
  }
}

export function createSafeFetch(
  options: HttpSecurityOptions = {},
  lookup: LookupFn = defaultLookup,
  isBlockedAddress: (address: string) => boolean = isNonGlobalAddress
): (url: string, init?: AnyInit) => Promise<any> {
  const limits = resolveHttpClientLimits(options);
  return async (url, init) => {
    const hostname = new URL(url).hostname;
    if (options.allowPrivateTargets || isIpLiteral(hostname)) {
      return platformRequest(url, init || {}, limits);
    }
    return pinnedRequest(url, init || {}, lookup, isBlockedAddress, limits);
  };
}
