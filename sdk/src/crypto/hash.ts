import { ethers } from 'ethers';

function isTimestampKey(key: string | undefined): boolean {
  return key === 'created' || key === 'updated' || key === 'timestamp';
}

function normalizeTimestampValue(value: string): string {
  const timestamp = Date.parse(value);
  return Number.isNaN(timestamp) ? value : new Date(timestamp).toISOString();
}

function canonicalizeJsonValue(value: unknown, key?: string): unknown {
  if (typeof value === 'string' && isTimestampKey(key)) {
    return normalizeTimestampValue(value);
  }

  if (Array.isArray(value)) {
    return value.map((item) => canonicalizeJsonValue(item));
  }

  if (value && typeof value === 'object') {
    const entries = Object.entries(value as Record<string, unknown>)
      .filter(([, entryValue]) => entryValue !== undefined)
      .sort(([left], [right]) => left.localeCompare(right))
      .map(([entryKey, entryValue]) => [entryKey, canonicalizeJsonValue(entryValue, entryKey)]);

    return Object.fromEntries(entries);
  }

  return value;
}

/**
 * Generates a deterministic SHA-256 hash of a string payload.
 * Used to protect intellectual property (like system prompts) while allowing verification.
 * 
 * @param payload The raw string to hash (e.g., "You are a helpful assistant...")
 * @returns A hex string representing the SHA-256 hash (e.g., "0x1234...")
 */
export function hashPayload(payload: string): string {
  if (!payload) {
    throw new Error("Payload cannot be empty");
  }
  // Convert string to UTF-8 bytes, then hash using ethers.js keccak256 or sha256
  // We use sha256 as it's more universally standard outside of EVM, but keccak256 is also fine.
  const bytes = ethers.toUtf8Bytes(payload);
  return ethers.sha256(bytes);
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

export function canonicalizeJson(value: unknown): string {
  return JSON.stringify(canonicalizeJsonValue(value));
}

export function generateCanonicalDocumentHash(document: unknown): string {
  return generateAgentMetadataHash(canonicalizeJson(document));
}
