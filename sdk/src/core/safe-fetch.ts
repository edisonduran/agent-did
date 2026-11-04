/**
 * Default `fetch` for the SDK's HTTP sources.
 *
 * Targets are validated before the request is sent, so a redirect would move
 * the request to a destination that was never validated. The default fetch
 * therefore does not follow redirects: a 3xx response surfaces as a non-OK
 * status. Callers that supply their own `fetchFn` own their redirect policy.
 */
type AnyInit = Record<string, unknown> | undefined;

export function noRedirectFetch(url: string, init?: AnyInit): Promise<any> {
  return globalThis.fetch(url, { ...(init || {}), redirect: 'manual' } as RequestInit);
}
