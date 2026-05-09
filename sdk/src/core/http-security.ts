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
  const octets = parts.map(Number);
  if (octets.some((o) => Number.isNaN(o) || o < 0 || o > 255)) return null;
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
  const [first, second] = octets;
  return first === 10
    || (first === 172 && second >= 16 && second <= 31)
    || (first === 192 && second === 168);
}

function isLoopbackIpv6(host: string): boolean {
  const normalized = host.replace(/^\[/, '').replace(/]$/, '');
  return normalized === '::1' || normalized === '0:0:0:0:0:0:0:1';
}

function parseIpv4MappedIpv6(host: string): number[] | null {
  const normalized = host.replace(/^\[/, '').replace(/]$/, '').toLowerCase();
  if (!normalized.startsWith('::ffff:')) {
    return null;
  }

  const tail = normalized.slice('::ffff:'.length);
  if (tail.includes('.')) {
    return parseIpv4(tail);
  }

  const groups = tail.split(':');
  if (groups.length !== 2) {
    return null;
  }

  const values = groups.map((group) => Number.parseInt(group, 16));
  if (values.some((value) => Number.isNaN(value) || value < 0 || value > 0xffff)) {
    return null;
  }

  return [
    (values[0] >> 8) & 0xff,
    values[0] & 0xff,
    (values[1] >> 8) & 0xff,
    values[1] & 0xff,
  ];
}

function isPrivateOrReservedIpv4(octets: number[]): boolean {
  return isLoopbackIpv4(octets)
    || isZeroAddress(octets)
    || isLinkLocalIpv4(octets)
    || isPrivateIpv4(octets);
}

function isPrivateOrReservedHost(hostname: string): boolean {
  // IPv6 loopback
  if (isLoopbackIpv6(hostname)) return true;

  const mappedIpv4 = parseIpv4MappedIpv6(hostname);
  if (mappedIpv4 && isPrivateOrReservedIpv4(mappedIpv4)) return true;

  const ipv4 = parseIpv4(hostname);
  if (ipv4 && isPrivateOrReservedIpv4(ipv4)) return true;

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
