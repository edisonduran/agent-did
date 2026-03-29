import { ed25519 } from '@noble/curves/ed25519';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils';

/**
 * Interface for signing operations. Implement this to integrate with
 * external key management (KMS, HSM, hardware wallets) in production.
 */
export interface AgentSigner {
  /** Sign a message and return the signature as hex string. */
  sign(payload: Uint8Array): Promise<string>;
  /** Return the raw Ed25519 public key (32 bytes). */
  getPublicKey(): Promise<Uint8Array>;
}

/**
 * Default signer that uses a local Ed25519 private key.
 * Suitable for development, testing, and demo scenarios.
 */
export class LocalKeySigner implements AgentSigner {
  private readonly privateKeyBytes: Uint8Array;

  constructor(privateKeyHex: string) {
    this.privateKeyBytes = hexToBytes(privateKeyHex);
  }

  async sign(payload: Uint8Array): Promise<string> {
    const signatureBytes = ed25519.sign(payload, this.privateKeyBytes);
    return bytesToHex(signatureBytes);
  }

  async getPublicKey(): Promise<Uint8Array> {
    return ed25519.getPublicKey(this.privateKeyBytes);
  }

  /** Generate a new LocalKeySigner with a random key. Returns [signer, privateKeyHex]. */
  static generate(): [LocalKeySigner, string] {
    const privateKeyBytes = ed25519.utils.randomPrivateKey();
    const privateKeyHex = bytesToHex(privateKeyBytes);
    return [new LocalKeySigner(privateKeyHex), privateKeyHex];
  }
}
