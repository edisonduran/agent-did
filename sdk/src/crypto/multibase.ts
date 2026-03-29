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
 * Accepts both:
 *   - Standard format: 'z' + Base58btc(0xed01 + raw_key)  (W3C compliant)
 *   - Legacy format:   'z' + hex(raw_key)                  (SDK v0.1.0 simplified)
 *
 * @param encoded - The publicKeyMultibase string
 * @returns 32-byte raw Ed25519 public key
 */
export function decodePublicKeyMultibase(encoded: string): Uint8Array {
  if (!encoded.startsWith('z')) {
    throw new Error(`Unsupported multibase prefix: '${encoded[0]}'. Only 'z' (Base58btc) is supported.`);
  }

  const value = encoded.slice(1);

  // Attempt standard Base58btc decode with multicodec prefix
  try {
    const decoded = bs58.decode(value);

    if (
      decoded.length === 34 &&
      decoded[0] === ED25519_MULTICODEC_PREFIX[0] &&
      decoded[1] === ED25519_MULTICODEC_PREFIX[1]
    ) {
      return decoded.slice(2);
    }

    // Base58btc decoded but no multicodec prefix — could be raw 32-byte key
    if (decoded.length === 32) {
      return decoded;
    }
  } catch {
    // Not valid Base58btc — fall through to legacy hex
  }

  // Legacy fallback: 'z' + hex (SDK v0.1.0 format)
  if (/^[0-9a-fA-F]+$/.test(value) && value.length === 64) {
    const bytes = new Uint8Array(32);
    for (let i = 0; i < 32; i++) {
      bytes[i] = parseInt(value.substring(i * 2, i * 2 + 2), 16);
    }
    return bytes;
  }

  throw new Error('Unable to decode publicKeyMultibase: unrecognized format');
}
