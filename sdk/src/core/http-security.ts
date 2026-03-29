/**
 * SSRF protection — validates HTTP target URLs before requests.
 */

export interface HttpTargetValidationOptions {
  /** Allow private/loopback/link-local targets (for dev/testing). Default: false */
  allowPrivateTargets?: boolean;
}

const PRIVATE_IPV4_RANGES = [
  { prefix: [10], mask: 8 },              // 10.0.0.0/8
  { prefix: [172], mask: 12, min2: 16, max2: 31 },  // 172.16.0.0/12
  { prefix: [192, 168], mask: 16 },       // 192.168.0.0/16
];

function parseIpv4(host: string): number[] | null {
  const parts = host.split('.');
  if (parts.length !== 4) return null;
  const octets = parts.map(Number);
  if (octets.some((o) => isNaN(o) || o < 0 || o > 255)) return null;
  return octets;
}

function isLoopbackIpv4(octets: number[]): boolean {
  return octets[0] === 127; // 127.0.0.0/8
}

function isZeroAddress(octets: number[]): boolean {
  return octets.every((o) => o === 0); // 0.0.0.0
}

function isLinkLocalIpv4(octets: number[]): boolean {
  return octets[0] === 169 && octets[1] === 254; // 169.254.0.0/16 (includes metadata endpoint)
}

function isPrivateIpv4(octets: number[]): boolean {
  for (const range of PRIVATE_IPV4_RANGES) {
    if (range.prefix.length === 1 && octets[0] === range.prefix[0]) {
      if (range.min2 !== undefined && range.max2 !== undefined) {
        if (octets[1] >= range.min2 && octets[1] <= range.max2) return true;
      } else {
        return true;
      }
    }
    if (range.prefix.length === 2 && octets[0] === range.prefix[0] && octets[1] === range.prefix[1]) {
      return true;
    }
  }
  return false;
}

function isLoopbackIpv6(host: string): boolean {
  const normalized = host.replace(/^\[/, '').replace(/]$/, '');
  return normalized === '::1' || normalized === '0:0:0:0:0:0:0:1';
}

function isPrivateOrReservedHost(hostname: string): boolean {
  // IPv6 loopback
  if (isLoopbackIpv6(hostname)) return true;

  const ipv4 = parseIpv4(hostname);
  if (ipv4) {
    if (isLoopbackIpv4(ipv4)) return true;
    if (isZeroAddress(ipv4)) return true;
    if (isLinkLocalIpv4(ipv4)) return true;
    if (isPrivateIpv4(ipv4)) return true;
  }

  // Common loopback hostnames
  const lower = hostname.toLowerCase();
  if (lower === 'localhost' || lower === 'localhost.localdomain') return true;

  return false;
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
