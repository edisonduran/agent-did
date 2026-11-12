import bs58 from 'bs58';

/**
 * Multicodec prefix for Ed25519 public keys.
 * See: https://github.com/multiformats/multicodec/blob/master/table.csv
 * Ed25519 public key = 0xed (varint encoded as 0xed 0x01)
 */
const ED25519_MULTICODEC_PREFIX = new Uint8Array([0xed, 0x01]);

/**
 * Encodes a raw Ed25519 public key into W3C-compliant publicKeyMultibase format.
 *
 * Format: 'z' + Base58btc(multicodec_prefix + raw_public_key)
 *   - 'z' is the Multibase prefix for Base58btc
 *   - multicodec_prefix is 0xed01 for Ed25519 public keys
 *
 * @param rawPublicKey - 32-byte Ed25519 public key
 * @returns Multibase-encoded string (e.g., "z6Mkf5rGMoatrSj1f...")
 */
export function encodePublicKeyMultibase(rawPublicKey: Uint8Array): string {
  if (rawPublicKey.length !== 32) {
    throw new Error(`Ed25519 public key must be 32 bytes, got ${rawPublicKey.length}`);
  }

  const prefixed = new Uint8Array(ED25519_MULTICODEC_PREFIX.length + rawPublicKey.length);
  prefixed.set(ED25519_MULTICODEC_PREFIX);
  prefixed.set(rawPublicKey, ED25519_MULTICODEC_PREFIX.length);

  return `z${bs58.encode(prefixed)}`;
}

/**
 * Decodes a publicKeyMultibase string back into a raw Ed25519 public key.
 *
 * Accepts only the standard format: 'z' + Base58btc(0xed01 + raw_key) (W3C compliant). The legacy forms of
 * SDK v0.1.0 (`z` + hex, or a raw key without the multicodec prefix) are rejected: a second encoding of the
 * same key is a second way to write a document that other implementations read differently.
 *
 * @param encoded - The publicKeyMultibase string
 * @returns 32-byte raw Ed25519 public key
 */
export function decodePublicKeyMultibase(encoded: string): Uint8Array {
  if (!encoded.startsWith('z')) {
    throw new Error(`Unsupported multibase prefix: '${encoded.slice(0, 1)}'. Only 'z' (Base58btc) is supported.`);
  }

  const value = encoded.slice(1);

  let decoded: Uint8Array | undefined;
  try {
    decoded = bs58.decode(value);
  } catch {
    decoded = undefined;
  }

  if (
    decoded !== undefined &&
    decoded.length === 34 &&
    decoded[0] === ED25519_MULTICODEC_PREFIX[0] &&
    decoded[1] === ED25519_MULTICODEC_PREFIX[1]
  ) {
    return decoded.slice(2);
  }

  throw new Error('Unable to decode publicKeyMultibase: expected z + Base58btc(0xed01 + 32-byte Ed25519 key)');
}

/**
 * Derives the `did:key` identifier of an Ed25519 public key (did:key method, `z6Mk…`).
 * The DID is a pure function of the public key, so it needs no registry or network access.
 */
export function didKeyFromPublicKey(rawPublicKey: Uint8Array): string {
  return `did:key:${encodePublicKeyMultibase(rawPublicKey)}`;
}
