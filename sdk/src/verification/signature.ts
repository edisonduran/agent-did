/**
 * Signature verification against an already resolved, active DID document. Resolution,
 * revocation and controller-chain checks stay in `AgentDidClient`.
 */
import { AgentDIDDocument, VerificationRelationship } from '../core/types';
import { decodeSignatureHex, verifyEd25519 } from '../crypto/ed25519-verify';
import { decodePublicKeyMultibase } from '../crypto/multibase';
import { assertKeyPurpose, assertSigningPurpose, getRelationshipKeyIds } from '../core/identity-composition';

/**
 * Verifies against active keys listed under `requiredPurpose` (and `keyId`, when given).
 *
 * Returns `false` for a signature that is not valid hex, an empty `keyId` and a `keyId` of a retired key (one
 * with a `deactivated` time: a rotated-out key is no longer listed in any relationship). Ed25519 edge cases
 * follow the single rule of `verifyEd25519`.
 */
export function verifyWithActiveKeys(
  didDoc: AgentDIDDocument,
  payload: string | Uint8Array,
  signature: string,
  keyId: string | undefined,
  requiredPurpose: VerificationRelationship
): boolean {
  assertSigningPurpose(requiredPurpose, didDoc, keyId || '');
  if (keyId !== undefined) {
    if (keyId === '' || didDoc.verificationMethod.some((method) => method.id === keyId && method.deactivated)) {
      return false;
    }
    assertKeyPurpose(keyId, didDoc, requiredPurpose);
  }

  const messageBytes = typeof payload === 'string' ? new TextEncoder().encode(payload) : payload;
  let signatureBytes: Uint8Array;
  try {
    signatureBytes = decodeSignatureHex(signature);
  } catch {
    return false;
  }

  const activeKeyIds = new Set(getRelationshipKeyIds(didDoc, requiredPurpose));
  const candidateMethods = didDoc.verificationMethod.filter((method) => {
    if (!method.publicKeyMultibase || method.deactivated) {
      return false;
    }
    return keyId !== undefined ? method.id === keyId && activeKeyIds.has(method.id) : activeKeyIds.has(method.id);
  });

  for (const verificationMethod of candidateMethods) {
    const keyValue = verificationMethod.publicKeyMultibase;
    if (!keyValue) continue;
    try {
      if (verifyEd25519(signatureBytes, messageBytes, decodePublicKeyMultibase(keyValue))) {
        return true;
      }
    } catch {
      continue;
    }
  }
  return false;
}
