/**
 * Sanitization of observability data shared by the SDK's framework integrations.
 *
 * One implementation, used by every integration before an event leaves it (callbacks, loggers, exporters).
 * Python parity: `agent_did_sdk.observability`.
 *
 * - A field whose name is sensitive (`payload`, `body`, `signature`, `privateKey`, `token`…; camelCase, snake_case
 *   and kebab-case spellings alike) is replaced by `{ redacted: true, length: n }` whatever its type.
 * - A `url` keeps scheme, host, port and path; user information, query and fragment are dropped.
 * - `headers` keep their names; sensitive headers (`Authorization`, `Signature`, `Cookie`…) are redacted.
 * - Plain objects, arrays, Maps and Sets are walked recursively. Class instances other than Date become
 *   `"<ClassName>"`, so their content never reaches a log by accident.
 * - The result is JSON-serializable.
 */

/** Sensitive field names, lowercase without `_` / `-` (see `isSensitiveFieldName`). */
export const SENSITIVE_FIELD_NAMES: ReadonlySet<string> = new Set([
  'accesstoken',
  'agentprivatekey',
  'apikey',
  'authorization',
  'body',
  'clientsecret',
  'cookie',
  'mnemonic',
  'password',
  'payload',
  'privatekey',
  'refreshtoken',
  'secret',
  'seed',
  'signature',
  'signatures',
  'signedpayload',
  'token'
]);

/** Sensitive HTTP header names, lowercase. */
export const SENSITIVE_HEADER_NAMES: ReadonlySet<string> = new Set([
  'authorization',
  'cookie',
  'proxy-authorization',
  'set-cookie',
  'signature',
  'signature-input',
  'x-api-key'
]);

export interface RedactedValue {
  redacted: true;
  length: number;
}

const MAX_DEPTH = 32;

/** Whether `name` is a sensitive field name, in any of `privateKey`, `private_key`, `private-key`. */
export function isSensitiveFieldName(name: string): boolean {
  return SENSITIVE_FIELD_NAMES.has(String(name).toLowerCase().replace(/[_-]/g, ''));
}

/** The marker that replaces a sensitive value: `{ redacted: true, length: n }`. */
export function redactValue(value: unknown): RedactedValue {
  let length: number;
  if (value === null || value === undefined) {
    length = 0;
  } else if (typeof value === 'string' || Array.isArray(value)) {
    length = value.length;
  } else if (value instanceof Uint8Array) {
    length = value.byteLength;
  } else if (value instanceof Map || value instanceof Set) {
    length = value.size;
  } else if (typeof value === 'object') {
    length = Object.keys(value as object).length;
  } else {
    length = String(value).length;
  }
  return { redacted: true, length };
}

export function isRedactedMarker(value: unknown): value is RedactedValue {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    return false;
  }
  const record = value as Record<string, unknown>;
  return Object.keys(record).length === 2 && record.redacted === true && Number.isInteger(record.length);
}

/** `url` without user information, query and fragment. A value without scheme and host becomes `"<invalid url>"`. */
export function sanitizeUrl(url: string): string {
  try {
    const parsed = new URL(url);
    if (!parsed.hostname) {
      return '<invalid url>';
    }
    const port = parsed.port ? `:${parsed.port}` : '';
    return `${parsed.protocol}//${parsed.hostname}${port}${parsed.pathname}`;
  } catch {
    return '<invalid url>';
  }
}

/** `headers` with the sensitive ones redacted and the other values sanitized. */
export function sanitizeHeaders(headers: Record<string, unknown> | Map<string, unknown>): Record<string, unknown> {
  const entries = headers instanceof Map ? [...headers.entries()] : Object.entries(headers);
  const sanitized: Record<string, unknown> = {};
  for (const [name, value] of entries) {
    sanitized[String(name)] = SENSITIVE_HEADER_NAMES.has(String(name).toLowerCase())
      ? redactValue(value)
      : sanitize(value, 1, new Set());
  }
  return sanitized;
}

/** Sanitizes `value` (usually an object of event attributes) as described in the module comment. */
export function sanitizeObservabilityAttributes(value: unknown): unknown {
  return sanitize(value, 0, new Set());
}

function isPlainObject(value: object): boolean {
  const proto = Object.getPrototypeOf(value);
  return proto === Object.prototype || proto === null;
}

function sanitize(value: unknown, depth: number, seen: Set<object>): unknown {
  if (value === null || value === undefined || typeof value === 'boolean' || typeof value === 'string') {
    return value ?? null;
  }
  if (typeof value === 'number') {
    return Number.isFinite(value) ? value : String(value);
  }
  if (typeof value === 'bigint') {
    return value.toString();
  }
  if (typeof value !== 'object') {
    return `<${typeof value}>`;
  }
  if (value instanceof Date) {
    return Number.isNaN(value.getTime()) ? '<invalid date>' : value.toISOString();
  }
  if (value instanceof Uint8Array) {
    return redactValue(value);
  }
  if (depth >= MAX_DEPTH) {
    return '<max depth>';
  }
  if (seen.has(value)) {
    return '<cycle>';
  }
  const nextSeen = new Set(seen).add(value);

  if (Array.isArray(value) || value instanceof Set) {
    return [...value].map((item) => sanitize(item, depth + 1, nextSeen));
  }
  let entries: Array<[string, unknown]>;
  if (value instanceof Map) {
    entries = [...value.entries()].map(([key, item]) => [String(key), item]);
  } else if (isPlainObject(value)) {
    entries = Object.entries(value);
  } else {
    return `<${value.constructor?.name ?? 'Object'}>`;
  }
  const sanitized: Record<string, unknown> = {};
  for (const [name, item] of entries) {
    const lowered = name.toLowerCase();
    if (isSensitiveFieldName(name)) {
      sanitized[name] = isRedactedMarker(item) ? item : redactValue(item);
    } else if (lowered === 'url' && typeof item === 'string') {
      sanitized[name] = sanitizeUrl(item);
    } else if (lowered === 'headers' && typeof item === 'object' && item !== null && !Array.isArray(item)) {
      sanitized[name] = sanitizeHeaders(item as Record<string, unknown>);
    } else {
      sanitized[name] = sanitize(item, depth + 1, nextSeen);
    }
  }
  return sanitized;
}
