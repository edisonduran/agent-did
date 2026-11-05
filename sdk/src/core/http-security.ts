/**
 * SSRF protection — validates HTTP target URLs before requests.
 */

export interface HttpTargetValidationOptions {
  /** Allow private/loopback/link-local targets (for dev/testing). Default: false */
  allowPrivateTargets?: boolean;
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
  // ::/8 covers unspecified, loopback, IPv4-compatible and IPv4-mapped (::ffff:0:0/96).
  if ((g[0] >> 8) === 0) {
    const mapped = g[0] === 0 && g[1] === 0 && g[2] === 0 && g[3] === 0 && g[4] === 0 && g[5] === 0xffff;
    return mapped ? isNonGlobalIpv4(embeddedIpv4(g, 6, 7)) : true;
  }
  return (g[0] & 0xfe00) === 0xfc00 // fc00::/7 unique local
    || (g[0] & 0xffc0) === 0xfe80 // fe80::/10 link-local
    || (g[0] & 0xffc0) === 0xfec0 // fec0::/10 site-local (deprecated)
    || (g[0] & 0xff00) === 0xff00 // ff00::/8 multicast
    || (g[0] === 0x2001 && g[1] === 0x0db8) // documentation
    || (g[0] === 0x0064 && g[1] === 0xff9b && g[2] === 0 && g[3] === 0 && g[4] === 0 && g[5] === 0
      && isNonGlobalIpv4(embeddedIpv4(g, 6, 7))) // NAT64 64:ff9b::/96
    || (g[0] === 0x2002 && isNonGlobalIpv4(embeddedIpv4(g, 1, 2))); // 6to4
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
