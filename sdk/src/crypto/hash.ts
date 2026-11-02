import { sha256 } from '@noble/hashes/sha256';
import { bytesToHex, utf8ToBytes } from '@noble/hashes/utils';

/**
 * Serializes one JSON value following RFC 8785 (JSON Canonicalization Scheme).
 *
 * - Primitives use the ECMAScript `JSON.stringify` serialization, which RFC 8785
 *   adopts verbatim (shortest round-trip numbers, minimal string escaping).
 * - Object members are sorted by the UTF-16 code units of their names, which is
 *   the default `Array.prototype.sort` order for strings.
 * - `undefined`, functions and symbols are omitted from objects and become
 *   `null` inside arrays, matching `JSON.stringify`.
 *
 * Returns `undefined` for values that have no JSON representation.
 */
function serializeJcs(value: unknown): string | undefined {
  if (value === null) {
    return 'null';
  }

  switch (typeof value) {
    case 'boolean':
    case 'string':
      return JSON.stringify(value);
    case 'number':
      if (!Number.isFinite(value)) {
        throw new TypeError(`JCS cannot represent non-finite number: ${value}`);
      }
      return JSON.stringify(value);
    case 'bigint':
      throw new TypeError('JCS cannot represent bigint values; convert them to number or string first');
    case 'undefined':
    case 'function':
    case 'symbol':
      return undefined;
    default:
      break;
  }

  const candidate = value as { toJSON?: () => unknown };
  if (typeof candidate.toJSON === 'function') {
    return serializeJcs(candidate.toJSON());
  }

  if (Array.isArray(value)) {
    return `[${value.map((item) => serializeJcs(item) ?? 'null').join(',')}]`;
  }

  const record = value as Record<string, unknown>;
  const members: string[] = [];
  for (const key of Object.keys(record).sort()) {
    const serialized = serializeJcs(record[key]);
    if (serialized !== undefined) {
      members.push(`${JSON.stringify(key)}:${serialized}`);
    }
  }
  return `{${members.join(',')}}`;
}

/**
 * Generates a deterministic SHA-256 hash of a string payload (UTF-8 encoded).
 * Used to commit to metadata such as system prompts while allowing verification.
 *
 * @param payload The raw string to hash (e.g., "You are a helpful assistant...")
 * @returns A `0x`-prefixed lowercase hex SHA-256 digest
 */
export function hashPayload(payload: string): string {
  if (!payload) {
    throw new Error("Payload cannot be empty");
  }
  return `0x${bytesToHex(sha256(utf8ToBytes(payload)))}`;
}

/**
 * Formats a raw hash into a URI format suitable for the Agent-DID JSON-LD document.
 * Currently supports a simple hash URI scheme, but can be extended to IPFS CIDs.
 *
 * @param hashHex The raw hex hash (e.g., "0x1234...")
 * @returns A formatted URI string (e.g., "hash://sha256/1234...")
 */
export function formatHashUri(hashHex: string): string {
  // Remove the '0x' prefix for the URI format
  const cleanHash = hashHex.startsWith('0x') ? hashHex.slice(2) : hashHex;
  return `hash://sha256/${cleanHash}`;
}

/**
 * Convenience function that hashes a payload and formats it as a URI in one step.
 *
 * @param payload The raw string to hash
 * @returns A formatted URI string
 */
export function generateAgentMetadataHash(payload: string): string {
  const rawHash = hashPayload(payload);
  return formatHashUri(rawHash);
}

/**
 * Returns the RFC 8785 (JCS) canonical JSON serialization of `value`.
 * Values are hashed exactly as given: no field (timestamps included) is
 * rewritten before canonicalization.
 *
 * @throws TypeError for non-finite numbers, bigint, or a top-level value with no JSON representation
 */
export function canonicalizeJson(value: unknown): string {
  const serialized = serializeJcs(value);
  if (serialized === undefined) {
    throw new TypeError('JCS input has no JSON representation');
  }
  return serialized;
}

/**
 * Returns the `hash://sha256/<hex>` reference of a DID document: SHA-256 over the
 * UTF-8 bytes of its RFC 8785 (JCS) canonical form.
 */
export function generateCanonicalDocumentHash(document: unknown): string {
  return generateAgentMetadataHash(canonicalizeJson(document));
}
