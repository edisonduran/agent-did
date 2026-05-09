import bs58 from 'bs58';
import { decodePublicKeyMultibase, encodePublicKeyMultibase } from '../src/crypto/multibase';

describe('multibase helpers', () => {
  const rawPublicKey = Uint8Array.from({ length: 32 }, (_value, index) => index + 1);

  it('should round-trip a standard Ed25519 multibase key', () => {
    const encoded = encodePublicKeyMultibase(rawPublicKey);

    expect(encoded.startsWith('z')).toBe(true);
    expect(decodePublicKeyMultibase(encoded)).toEqual(rawPublicKey);
  });

  it('should reject raw keys that are not 32 bytes long', () => {
    expect(() => encodePublicKeyMultibase(new Uint8Array(31)))
      .toThrow('Ed25519 public key must be 32 bytes, got 31');
  });

  it('should decode base58 multibase values that contain a raw 32-byte key without a multicodec prefix', () => {
    const encoded = `z${bs58.encode(rawPublicKey)}`;

    expect(decodePublicKeyMultibase(encoded)).toEqual(rawPublicKey);
  });

  it('should decode the legacy hex multibase format used by earlier SDK versions', () => {
    const encoded = `z${Buffer.from(rawPublicKey).toString('hex')}`;

    expect(decodePublicKeyMultibase(encoded)).toEqual(rawPublicKey);
  });

  it('should reject unsupported multibase prefixes', () => {
    expect(() => decodePublicKeyMultibase('fabcdef'))
      .toThrow("Unsupported multibase prefix: 'f'. Only 'z' (Base58btc) is supported.");
  });

  it('should reject unrecognized multibase payloads', () => {
    expect(() => decodePublicKeyMultibase('znot-a-valid-key'))
      .toThrow('Unable to decode publicKeyMultibase: unrecognized format');
  });
});