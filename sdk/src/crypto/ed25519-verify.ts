/**
 * The one Ed25519 verification rule of the SDK (RFC-001 §7), shared by every verification path.
 *
 * Ed25519 implementations disagree on edge cases: `@noble/curves` follows ZIP-215 by default (it accepts
 * non-canonical encodings and checks the cofactored equation), libsodium (PyNaCl) is stricter and cofactorless.
 * A signature must not verify in one SDK and fail in the other, so both apply the same rule before the equation:
 *
 * - the signature is 64 bytes and the public key 32 bytes;
 * - `S` is canonical (`S < L`);
 * - the public key `A` and the signature point `R` are canonical encodings of points of the prime-order
 *   subgroup: not of small order (this includes the identity) and without a torsion component.
 *
 * With `A` and `R` in the prime-order subgroup the cofactored and cofactorless equations agree, so what is accepted
 * does not depend on which one a library implements. Python parity: `sdk-python/src/agent_did_sdk/crypto/ed25519.py`.
 */
import { ed25519 } from '@noble/curves/ed25519';

function isAcceptablePoint(encoded: Uint8Array): boolean {
  try {
    // zip215 = false: a non-canonical encoding of the point is rejected while decoding
    const point = ed25519.ExtendedPoint.fromHex(encoded, false);
    return !point.isSmallOrder() && point.isTorsionFree();
  } catch {
    return false;
  }
}

/** Verifies an Ed25519 signature under the SDK rule above. Never throws; malformed input is `false`. */
export function verifyEd25519(signature: Uint8Array, message: Uint8Array, publicKey: Uint8Array): boolean {
  if (signature.length !== 64 || publicKey.length !== 32) {
    return false;
  }
  if (!isAcceptablePoint(publicKey) || !isAcceptablePoint(signature.subarray(0, 32))) {
    return false;
  }
  try {
    return ed25519.verify(signature, message, publicKey, { zip215: false });
  } catch {
    return false;
  }
}
