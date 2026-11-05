/**
 * Default `fetch` for the SDK's HTTP sources.
 *
 * - Redirects are not followed: targets are validated before the request is sent, so a redirect
 *   would move it to a destination that was never validated. A 3xx surfaces as a non-OK status.
 * - Host names are resolved once, at connection time, and the connection is refused when any
 *   resolved address is not globally routable. The address that was validated is the address that
 *   is connected to, so a DNS answer that changes after the check (rebinding) cannot redirect the
 *   request. TLS still verifies the original host name.
 *
 * IP literals and `allowPrivateTargets` use the platform `fetch` (with redirects disabled), since
 * there is nothing to resolve or the caller opted out. Callers that supply their own `fetchFn`
 * own their redirect and DNS policy. Node.js only: it relies on `node:http`, `node:https` and
 * `node:dns`.
 */
import { HttpTargetValidationOptions, isNonGlobalAddress } from './http-security';

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

async function pinnedRequest(
  url: string,
  init: Record<string, unknown>,
  lookup: LookupFn,
  isBlockedAddress: (address: string) => boolean
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

  const headers = Object.fromEntries(
    Object.entries((init.headers as Record<string, string> | undefined) || {}).map(([k, v]) => [k, String(v)])
  );
  const body = init.body === undefined || init.body === null ? undefined : String(init.body);
  if (body !== undefined && !Object.keys(headers).some((k) => k.toLowerCase() === 'content-length')) {
    headers['content-length'] = String(Buffer.byteLength(body));
  }

  return new Promise<SafeFetchResponse>((resolve, reject) => {
    const request = transport.request(
      {
        protocol: parsed.protocol,
        hostname: parsed.hostname.replace(/^\[|\]$/g, ''),
        port: parsed.port || undefined,
        path: `${parsed.pathname}${parsed.search}`,
        method: String(init.method || 'GET').toUpperCase(),
        headers,
        lookup: validatedLookup as never
      },
      (res) => {
        const chunks: Buffer[] = [];
        res.on('data', (chunk: Buffer) => chunks.push(chunk));
        res.on('error', reject);
        res.on('end', () => {
          const status = res.statusCode || 0;
          const text = Buffer.concat(chunks).toString('utf8');
          const responseHeaders = new Headers();
          for (const [key, value] of Object.entries(res.headers)) {
            if (value !== undefined) responseHeaders.set(key, Array.isArray(value) ? value.join(', ') : value);
          }
          resolve({
            ok: status >= 200 && status <= 299,
            status,
            headers: responseHeaders,
            text: async () => text,
            json: async () => JSON.parse(text)
          });
        });
      }
    );
    request.on('error', reject);
    if (body !== undefined) request.write(body);
    request.end();
  });
}

export function createSafeFetch(
  options: HttpTargetValidationOptions = {},
  lookup: LookupFn = defaultLookup,
  isBlockedAddress: (address: string) => boolean = isNonGlobalAddress
): (url: string, init?: AnyInit) => Promise<any> {
  return async (url, init) => {
    const hostname = new URL(url).hostname;
    if (options.allowPrivateTargets || isIpLiteral(hostname)) {
      return globalThis.fetch(url, { ...(init || {}), redirect: 'manual' } as RequestInit);
    }
    return pinnedRequest(url, init || {}, lookup, isBlockedAddress);
  };
}
