import { hmac } from '@noble/hashes/hmac';
import { sha256 } from '@noble/hashes/sha256';
import { bytesToHex, hexToBytes, randomBytes, utf8ToBytes } from '@noble/hashes/utils';

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

const HMAC_SHA256_COMMITMENT_PREFIX = 'hash://hmac-sha256/';
const SHA256_COMMITMENT_PREFIX = 'hash://sha256/';
const COMMITMENT_SALT_BYTES = 32;

function parseCommitmentSalt(saltHex: string): Uint8Array {
  if (typeof saltHex !== 'string' || !/^[0-9a-fA-F]{64}$/.test(saltHex)) {
    throw new Error(`Commitment salt must be ${COMMITMENT_SALT_BYTES} bytes encoded as 64 hex characters`);
  }
  return hexToBytes(saltHex.toLowerCase());
}

function constantTimeEqual(left: string, right: string): boolean {
  if (left.length !== right.length) {
    return false;
  }
  let diff = 0;
  for (let index = 0; index < left.length; index += 1) {
    diff |= left.charCodeAt(index) ^ right.charCodeAt(index);
  }
  return diff === 0;
}

/**
 * Generates a random 32-byte salt (64 lowercase hex characters) for a metadata commitment.
 * The controller keeps the salt private and reveals it only to parties allowed to verify
 * the committed value.
 */
export function generateCommitmentSalt(): string {
  return bytesToHex(randomBytes(COMMITMENT_SALT_BYTES));
}

/**
 * Commits to a metadata value (system prompt, model identifier) without making it guessable:
 * `hash://hmac-sha256/<hex(HMAC-SHA256(key = salt, message = UTF-8(value)))>`.
 *
 * @param value The raw value to commit to. Must not be empty.
 * @param saltHex A 32-byte salt as 64 hex characters, e.g. from `generateCommitmentSalt()`.
 */
export function createMetadataCommitment(value: string, saltHex: string): string {
  if (!value) {
    throw new Error('Commitment value cannot be empty');
  }
  const digest = hmac(sha256, parseCommitmentSalt(saltHex), utf8ToBytes(value));
  return `${HMAC_SHA256_COMMITMENT_PREFIX}${bytesToHex(digest)}`;
}

/**
 * Checks a revealed value (and salt) against a metadata commitment URI.
 *
 * - `hash://hmac-sha256/...` requires the salt used at commitment time.
 * - `hash://sha256/...` (unsalted, produced by `1.0.0-rc.2` and earlier) ignores the salt.
 *
 * Returns `false` for a mismatch, an unknown scheme, or a missing or malformed salt.
 */
export function verifyMetadataCommitment(commitmentUri: string, value: string, saltHex?: string): boolean {
  if (!value || typeof commitmentUri !== 'string') {
    return false;
  }

  const normalizedUri = commitmentUri.toLowerCase();
  let expected: string;
  if (normalizedUri.startsWith(HMAC_SHA256_COMMITMENT_PREFIX)) {
    if (saltHex === undefined) {
      return false;
    }
    try {
      expected = createMetadataCommitment(value, saltHex);
    } catch {
      return false;
    }
  } else if (normalizedUri.startsWith(SHA256_COMMITMENT_PREFIX)) {
    expected = generateAgentMetadataHash(value);
  } else {
    return false;
  }

  return constantTimeEqual(expected, normalizedUri);
}
