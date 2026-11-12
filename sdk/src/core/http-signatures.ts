/**
 * HTTP Message Signatures (RFC 9421) primitives: Structured Field (RFC 8941)
 * handling for `Signature-Input` / `Signature` (parsing is delegated to the
 * `structured-headers` library) and the signature base of RFC 9421 §2.5.
 * Agent-DID's request profile is built on top of this in `AgentIdentity`.
 *
 * Python parity: `agent_did_sdk.core.http_signatures`.
 */

import { bytesToBase64 } from '../crypto/base64';
import {
  parseDictionary,
  Token,
  type BareItem,
  type Dictionary,
  type InnerList,
  type Item,
  type Parameters,
} from 'structured-headers';

/** An RFC 8941 bare item as used by signature parameters. */
export type SignatureParamValue = string | number | boolean | { token: string };

export interface SignatureInput {
  /** Covered component identifiers, in order (names only; component parameters are not supported). */
  components: string[];
  /** Signature parameters, in order. */
  params: Array<[string, SignatureParamValue]>;
}

export interface HttpRequestLike {
  method: string;
  url: string;
  /** Header fields; names are matched case-insensitively. */
  headers: Record<string, string | string[] | undefined>;
}

export class HttpSignatureError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'HttpSignatureError';
  }
}

const KEY = /^[a-z*][a-z0-9_\-.*]*$/u;
const TOKEN = /^[A-Za-z*][!#$%&'*+\-.^_`|~0-9A-Za-z:/]*$/u;

// ---------------------------------------------------------------------------
// Serialization (RFC 8941 §4.1)
// ---------------------------------------------------------------------------

function serializeString(value: string): string {
  if (!/^[\x20-\x7e]*$/u.test(value)) {
    throw new HttpSignatureError('Structured Field strings must be printable ASCII');
  }
  return `"${value.replace(/\\/gu, '\\\\').replace(/"/gu, '\\"')}"`;
}

function serializeBareItem(value: SignatureParamValue): string {
  if (typeof value === 'string') {
    return serializeString(value);
  }
  if (typeof value === 'number') {
    if (!Number.isInteger(value) || Math.abs(value) > 999_999_999_999_999) {
      throw new HttpSignatureError('Structured Field integers must be integers of at most 15 digits');
    }
    return String(value);
  }
  if (typeof value === 'boolean') {
    return value ? '?1' : '?0';
  }
  if (!TOKEN.test(value.token)) {
    throw new HttpSignatureError(`Invalid Structured Field token: ${value.token}`);
  }
  return value.token;
}

function serializeParams(params: Array<[string, SignatureParamValue]>): string {
  return params
    .map(([name, value]) => {
      if (!KEY.test(name)) {
        throw new HttpSignatureError(`Invalid Structured Field key: ${name}`);
      }
      return value === true ? `;${name}` : `;${name}=${serializeBareItem(value)}`;
    })
    .join('');
}

/** Serializes a signature's inner list (the `@signature-params` value and the `Signature-Input` member). */
export function serializeSignatureInput(input: SignatureInput): string {
  return `(${input.components.map(serializeString).join(' ')})${serializeParams(input.params)}`;
}

export function serializeSignature(label: string, signature: Uint8Array): string {
  if (!KEY.test(label)) {
    throw new HttpSignatureError(`Invalid signature label: ${label}`);
  }
  return `${label}=:${bytesToBase64(signature)}:`;
}

// ---------------------------------------------------------------------------
// Parsing (RFC 8941 §4.2) by the `structured-headers` library, restricted to
// what Signature-Input / Signature use
// ---------------------------------------------------------------------------

function parseDictionaryStrict(value: string): Dictionary {
  try {
    return parseDictionary(value.trim());
  } catch (error) {
    throw new HttpSignatureError(`Malformed Structured Field: ${error instanceof Error ? error.message : String(error)}`);
  }
}

/**
 * Counts `;` separators outside strings and byte sequences. RFC 8941 lets a
 * repeated parameter silently overwrite the earlier one, and the library does
 * that; a signature parameter list must not contain duplicates (RFC 9421 §2.3),
 * so a count mismatch against the parsed parameters means one was dropped.
 */
function countParameterSeparators(value: string): number {
  let count = 0;
  let inString = false;
  let inBytes = false;
  for (let index = 0; index < value.length; index += 1) {
    const char = value.charAt(index);
    if (inString) {
      if (char === '\\') index += 1;
      else if (char === '"') inString = false;
    } else if (inBytes) {
      if (char === ':') inBytes = false;
    } else if (char === '"') {
      inString = true;
    } else if (char === ':') {
      inBytes = true;
    } else if (char === ';') {
      count += 1;
    }
  }
  return count;
}

function toParamValue(name: string, value: BareItem): SignatureParamValue {
  if (typeof value === 'string' || typeof value === 'boolean') {
    return value;
  }
  if (typeof value === 'number') {
    // Decimals are not used by signature parameters. (A decimal with an integral
    // value such as `1.0` is indistinguishable from `1` in this library; the
    // signature base is rebuilt from the parsed value, so it cannot verify.)
    if (!Number.isInteger(value)) {
      throw new HttpSignatureError(`Invalid integer (decimals are not used by signature parameters): ${name}`);
    }
    return value;
  }
  if (value instanceof Token) {
    return { token: value.toString() };
  }
  throw new HttpSignatureError(`Unsupported value type for signature parameter: ${name}`);
}

function toParams(params: Parameters): Array<[string, SignatureParamValue]> {
  return Array.from(params, ([name, value]): [string, SignatureParamValue] => [name, toParamValue(name, value)]);
}

/** Parses a `Signature-Input` field value into its members (label → inner list). */
export function parseSignatureInputHeader(value: string): Map<string, SignatureInput> {
  const result = new Map<string, SignatureInput>();
  let separators = 0;
  for (const [label, member] of parseDictionaryStrict(value)) {
    if (!Array.isArray(member[0])) {
      throw new HttpSignatureError(`Signature-Input member ${label} is not an inner list`);
    }
    const [items, params] = member as InnerList;
    const components = items.map(([component, componentParams]) => {
      if (typeof component !== 'string') {
        throw new HttpSignatureError('Covered component identifiers must be strings');
      }
      if (componentParams.size > 0) {
        throw new HttpSignatureError('Component identifier parameters are not supported');
      }
      return component;
    });
    separators += params.size;
    result.set(label, { components, params: toParams(params) });
  }
  if (countParameterSeparators(value) !== separators) {
    throw new HttpSignatureError('Duplicate signature parameter');
  }
  return result;
}

/** Parses a `Signature` field value into its members (label → signature bytes). */
export function parseSignatureHeader(value: string): Map<string, Uint8Array> {
  const result = new Map<string, Uint8Array>();
  for (const [label, member] of parseDictionaryStrict(value)) {
    const [bare, params] = member as Item;
    if (!(bare instanceof ArrayBuffer) || params.size > 0) {
      throw new HttpSignatureError(`Signature member ${label} must be a byte sequence without parameters`);
    }
    result.set(label, new Uint8Array(bare));
  }
  return result;
}

export function getSignatureParam(input: SignatureInput, name: string): SignatureParamValue | undefined {
  return input.params.find(([key]) => key === name)?.[1];
}

// ---------------------------------------------------------------------------
// Signature base (RFC 9421 §2.5)
// ---------------------------------------------------------------------------

function headerValue(request: HttpRequestLike, name: string): string {
  const values = Object.entries(request.headers)
    .filter(([key, value]) => key.toLowerCase() === name && value !== undefined)
    .flatMap(([, value]) => (Array.isArray(value) ? value : [value as string]));
  if (values.length === 0) {
    throw new HttpSignatureError(`Covered header field is missing: ${name}`);
  }
  // RFC 9421 §2.1: strip leading/trailing whitespace, join multiple field lines with ", ".
  const combined = values.map((value) => value.replace(/\r?\n[ \t]+/gu, ' ').trim()).join(', ');
  if (/[\r\n]/u.test(combined)) {
    throw new HttpSignatureError(`Header field ${name} contains line breaks`);
  }
  return combined;
}

// The request URL must already be in the form every URL parser derives the same components from (RFC-001 §6.5
// item 4): an http(s) URL with a lowercase scheme and host, no user info and no fragment, a path and query of
// unreserved, sub-delimiter, ':' and '@' characters and percent-encoded octets (no "'" in the query), no dot
// segments, and an IP address host only in canonical form. Anything else is refused, never normalized.
const REQUEST_URL_FORM =
  /^(https?):\/\/([a-z0-9._-]+|\[[0-9a-f:]+\])(?::([1-9][0-9]{0,4}))?((?:\/[A-Za-z0-9\-._~!$&'()*+,;=:@%]*)*)(\?[A-Za-z0-9\-._~!$&()*+,;=:@%/?]*)?$/u;
const DOT_SEGMENTS = new Set(['.', '..', '%2e', '%2e%2e', '.%2e', '%2e.']);
const CANONICAL_IPV4 = /^(?:(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.){3}(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])$/u;
const NUMERIC_LABEL = /^(?:0x[0-9a-f]*|[0-9]+)$/u;

/** Why `url` is not a request URL in normalized form, or `undefined` when it is. */
export function requestUrlFormProblem(url: string): string | undefined {
  if (url.includes('#')) {
    return 'it has a fragment';
  }
  const match = REQUEST_URL_FORM.exec(url);
  if (!match) {
    return 'it is not an http(s) URL with a lowercase scheme and ASCII host, no user info, and only unreserved, '
      + "sub-delimiter, ':', '@' and percent-encoded characters in the path and query";
  }
  const [, , host, port, path, query] = match;
  if (/%(?![0-9A-Fa-f]{2})/u.test(url)) {
    return "it has a '%' that is not followed by two hex digits";
  }
  if (path.split('/').some((segment) => DOT_SEGMENTS.has(segment.toLowerCase()))) {
    return "it has a '.' or '..' path segment";
  }
  if (query === '?') {
    return 'it has an empty query';
  }
  if (port !== undefined && Number(port) > 65535) {
    return 'its port is out of range';
  }
  if (host.startsWith('[')) {
    let canonical: string | undefined;
    try {
      canonical = new URL(`http://${host}/`).hostname;
    } catch {
      canonical = undefined;
    }
    return canonical === host ? undefined : 'its IPv6 host is not in canonical form';
  }
  const labels = host.split('.');
  if (labels.some((label) => label.length === 0)) {
    return 'its host has an empty label';
  }
  if (NUMERIC_LABEL.test(labels[labels.length - 1]) && !CANONICAL_IPV4.test(host)) {
    return 'its IPv4 host is not in canonical dotted-decimal form';
  }
  return undefined;
}

function derivedComponentValue(request: HttpRequestLike, name: string): string {
  const url = new URL(request.url);
  switch (name) {
    case '@method':
      return request.method;
    case '@target-uri':
      return url.href;
    case '@authority':
      return url.host.toLowerCase();
    case '@scheme':
      return url.protocol.slice(0, -1).toLowerCase();
    case '@request-target':
      return `${url.pathname || '/'}${url.search}`;
    case '@path':
      return url.pathname || '/';
    case '@query':
      return url.search || '?';
    default:
      throw new HttpSignatureError(`Unsupported derived component: ${name}`);
  }
}

/** Builds the RFC 9421 signature base for `input` over `request`. */
export function buildSignatureBase(request: HttpRequestLike, input: SignatureInput): string {
  if (input.components.some((component) => component.startsWith('@') && component !== '@method')) {
    const problem = requestUrlFormProblem(request.url);
    if (problem !== undefined) {
      throw new HttpSignatureError(`The request URL is not in normalized form: ${problem}`);
    }
  }
  const seen = new Set<string>();
  const lines: string[] = [];
  for (const component of input.components) {
    if (seen.has(component)) {
      throw new HttpSignatureError(`Duplicate covered component: ${component}`);
    }
    seen.add(component);
    if (component !== component.toLowerCase()) {
      throw new HttpSignatureError(`Component names must be lowercase: ${component}`);
    }
    const value = component.startsWith('@')
      ? derivedComponentValue(request, component)
      : headerValue(request, component);
    lines.push(`${serializeString(component)}: ${value}`);
  }
  lines.push(`"@signature-params": ${serializeSignatureInput(input)}`);
  return lines.join('\n');
}
