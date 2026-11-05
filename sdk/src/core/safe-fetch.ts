/**
 * Default `fetch` for the SDK's HTTP sources.
 *
 * - Redirects are not followed: targets are validated before the request is sent, so a redirect
 *   would move it to a destination that was never validated. A 3xx surfaces as a non-OK status.
 * - Host names are resolved first and rejected when any address is not globally routable, so a
 *   public name that points at a private address is blocked like the literal address would be.
 *
 * Residual risk: the name is resolved again when the connection is made, so a DNS answer that
 * changes between the two lookups (rebinding) is not covered. Deployments that need that
 * guarantee should also filter egress at the network level. Callers that supply their own
 * `fetchFn` own their redirect and DNS policy.
 */
import { HttpTargetValidationOptions, isNonGlobalAddress } from './http-security';

type AnyInit = Record<string, unknown> | undefined;
type LookupFn = (hostname: string) => Promise<Array<{ address: string }>>;

async function defaultLookup(hostname: string): Promise<Array<{ address: string }>> {
  const dns = await import('node:dns');
  return dns.promises.lookup(hostname, { all: true, verbatim: true });
}

function isIpLiteral(hostname: string): boolean {
  return hostname.startsWith('[') || /^[\d.]+$/.test(hostname) || hostname.includes(':');
}

export async function assertResolvedTargetAllowed(
  url: string,
  options: HttpTargetValidationOptions = {},
  lookup: LookupFn = defaultLookup
): Promise<void> {
  if (options.allowPrivateTargets) return;

  const hostname = new URL(url).hostname;
  if (isIpLiteral(hostname)) return; // already classified by validateHttpTarget

  let addresses: Array<{ address: string }>;
  try {
    addresses = await lookup(hostname);
  } catch {
    // Fail closed: an unresolvable name is never fetched.
    throw new Error(`Blocked request: could not resolve ${hostname}`);
  }
  if (addresses.length === 0 || addresses.some(({ address }) => isNonGlobalAddress(address))) {
    throw new Error(`Blocked request to private/reserved address: ${hostname}`);
  }
}

export function createSafeFetch(
  options: HttpTargetValidationOptions = {},
  lookup?: LookupFn
): (url: string, init?: AnyInit) => Promise<any> {
  return async (url, init) => {
    await assertResolvedTargetAllowed(url, options, lookup);
    return globalThis.fetch(url, { ...(init || {}), redirect: 'manual' } as RequestInit);
  };
}
