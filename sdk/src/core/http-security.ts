/**
 * SSRF protection — validates HTTP target URLs before requests.
 */

export interface HttpTargetValidationOptions {
  /** Allow private/loopback/link-local targets (for dev/testing). Default: false */
  allowPrivateTargets?: boolean;
}

/** Default deadline of a request made by the SDK's default HTTP client: 10 s. */
export const DEFAULT_HTTP_TIMEOUT_MS = 10_000;

/** Default maximum response body accepted by the SDK's default HTTP client: 1 MiB. */
export const DEFAULT_MAX_RESPONSE_BYTES = 1024 * 1024;

/**
 * Policy of the SDK's default HTTP client (`createSafeFetch`): target validation plus limits.
 * A caller-supplied `fetchFn` owns its own limits.
 */
export interface HttpSecurityOptions extends HttpTargetValidationOptions {
  /**
   * Deadline for the whole request, from the DNS lookup to the last byte of the body, in
   * milliseconds. A server that sends the body slowly cannot extend it. Default: `DEFAULT_HTTP_TIMEOUT_MS`.
   */
  timeoutMs?: number;
  /**
   * Largest response body accepted, in bytes. The client asks for an unencoded body
   * (`Accept-Encoding: identity`) and rejects a response with any other `Content-Encoding`, so
   * the limit applies to the bytes that are parsed. Default: `DEFAULT_MAX_RESPONSE_BYTES`.
   */
  maxResponseBytes?: number;
}

/** The effective limits of `options`, with the defaults applied. Throws `TypeError` for a value that is not a positive integer. */
export function resolveHttpClientLimits(options: HttpSecurityOptions = {}): { timeoutMs: number; maxResponseBytes: number } {
  const timeoutMs = options.timeoutMs ?? DEFAULT_HTTP_TIMEOUT_MS;
  const maxResponseBytes = options.maxResponseBytes ?? DEFAULT_MAX_RESPONSE_BYTES;
  for (const [name, value] of [['timeoutMs', timeoutMs], ['maxResponseBytes', maxResponseBytes]] as const) {
    if (!Number.isSafeInteger(value) || value <= 0) {
      throw new TypeError(`${name} must be a positive integer`);
    }
  }
  return { timeoutMs, maxResponseBytes };
}

function parseIpv4(host: string): number[] | null {
  const parts = host.split('.');
  if (parts.length !== 4) return null;
  if (!parts.every((p) => /^\d{1,3}$/.test(p))) return null;
  const octets = parts.map(Number);
  if (octets.some((o) => o > 255)) return null;
  return octets;
}

/**
 * True for every IPv4 address that is not globally routable (IANA
 * special-purpose registry): this-network, private, shared (CGNAT), loopback,
 * link-local (cloud metadata), IETF protocol, documentation, benchmarking,
 * multicast and reserved/broadcast.
 */
function isNonGlobalIpv4([a, b, c]: number[]): boolean {
  return a === 0 // 0.0.0.0/8
    || a === 10
    || (a === 100 && b >= 64 && b <= 127) // 100.64.0.0/10
    || a === 127
    || (a === 169 && b === 254)
    || (a === 172 && b >= 16 && b <= 31)
    || (a === 192 && b === 0 && c === 0) // 192.0.0.0/24
    || (a === 192 && b === 0 && c === 2) // 192.0.2.0/24
    || (a === 192 && b === 168)
    || (a === 198 && (b === 18 || b === 19)) // 198.18.0.0/15
    || (a === 198 && b === 51 && c === 100)
    || (a === 203 && b === 0 && c === 113)
    || a >= 224; // multicast + reserved + broadcast
}

/** Parses an IPv6 literal (no brackets, no zone) into 8 16-bit groups. */
function parseIpv6(host: string): number[] | null {
  let text = host.toLowerCase();
  const lastColon = text.lastIndexOf(':');
  if (lastColon === -1) return null;

  const tail = text.slice(lastColon + 1);
  if (tail.includes('.')) {
    const v4 = parseIpv4(tail);
    if (!v4) return null;
    text = `${text.slice(0, lastColon + 1)}${((v4[0] << 8) | v4[1]).toString(16)}:${((v4[2] << 8) | v4[3]).toString(16)}`;
  }

  const halves = text.split('::');
  if (halves.length > 2) return null;
  const toGroups = (part: string): number[] | null => {
    if (part === '') return [];
    const groups = part.split(':');
    if (!groups.every((g) => /^[0-9a-f]{1,4}$/.test(g))) return null;
    return groups.map((g) => Number.parseInt(g, 16));
  };

  const head = toGroups(halves[0]);
  if (!head) return null;
  if (halves.length === 1) return head.length === 8 ? head : null;

  const rest = toGroups(halves[1]);
  if (!rest || head.length + rest.length > 7) return null;
  return [...head, ...new Array<number>(8 - head.length - rest.length).fill(0), ...rest];
}

function embeddedIpv4(g: number[], hi: number, lo: number): number[] {
  return [(g[hi] >> 8) & 0xff, g[hi] & 0xff, (g[lo] >> 8) & 0xff, g[lo] & 0xff];
}

function isNonGlobalIpv6(g: number[]): boolean {
  // IPv4-mapped (::ffff:0:0/96) and NAT64 (64:ff9b::/96) addresses are judged by the IPv4 address they embed.
  const zeroPrefix = g[0] === 0 && g[1] === 0 && g[2] === 0 && g[3] === 0 && g[4] === 0;
  if (zeroPrefix && g[5] === 0xffff) return isNonGlobalIpv4(embeddedIpv4(g, 6, 7));
  if (g[0] === 0x0064 && g[1] === 0xff9b && g[2] === 0 && g[3] === 0 && g[4] === 0 && g[5] === 0) {
    return isNonGlobalIpv4(embeddedIpv4(g, 6, 7));
  }
  // 6to4 (2002::/16) embeds the IPv4 address in bits 16-47.
  if (g[0] === 0x2002) return isNonGlobalIpv4(embeddedIpv4(g, 1, 2));

  // Fail closed: only global unicast space (2000::/3) is allowed. Everything else (unspecified, loopback,
  // IPv4-compatible, discard 100::/64, unique local, link-local, site-local, multicast, unallocated) is not.
  if ((g[0] & 0xe000) !== 0x2000) return true;
  return (g[0] === 0x2001 && g[1] < 0x0200) // 2001::/23 IETF protocol assignments (Teredo, ORCHID, benchmarking, ...)
    || (g[0] === 0x2001 && g[1] === 0x0db8) // 2001:db8::/32 documentation
    || (g[0] === 0x3fff && g[1] < 0x1000); // 3fff::/20 documentation
}

function isPrivateOrReservedHost(hostname: string): boolean {
  const lower = hostname.toLowerCase().replace(/\.$/, '');
  if (lower === 'localhost' || lower.endsWith('.localhost') || lower === 'localhost.localdomain') {
    return true;
  }

  if (lower.startsWith('[') && lower.endsWith(']')) {
    const v6 = parseIpv6(lower.slice(1, -1));
    // An unparseable bracketed literal is never a valid host: fail closed.
    return v6 === null || isNonGlobalIpv6(v6);
  }

  const v4 = parseIpv4(lower);
  return v4 !== null && isNonGlobalIpv4(v4);
}

/**
 * True when `address` (an IPv4 or IPv6 literal, with or without brackets) is not globally routable.
 * Used on the addresses a host name resolves to.
 */
export function isNonGlobalAddress(address: string): boolean {
  const bare = address.replace(/^\[|\]$/g, '');
  return isPrivateOrReservedHost(bare.includes(':') ? `[${bare}]` : bare);
}

/**
 * Validates an HTTP target URL for SSRF safety.
 * Throws if the URL is unsafe (loopback, private, metadata, embedded credentials).
 */
export function validateHttpTarget(url: string, options: HttpTargetValidationOptions = {}): void {
  const { allowPrivateTargets = false } = options;

  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    throw new Error(`Invalid URL: ${url}`);
  }

  // Protocol check
  if (parsed.protocol !== 'https:' && parsed.protocol !== 'http:') {
    throw new Error(`Unsupported protocol: ${parsed.protocol}`);
  }

  // Embedded credentials check
  if (parsed.username || parsed.password) {
    throw new Error('URLs with embedded credentials are not allowed');
  }

  if (allowPrivateTargets) return;

  const hostname = parsed.hostname;

  if (isPrivateOrReservedHost(hostname)) {
    throw new Error(`Blocked request to private/reserved address: ${hostname}`);
  }
}
