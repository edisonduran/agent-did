/**
 * Signature verification against an already resolved, active DID document. Resolution,
 * revocation and controller-chain checks stay in `AgentDidClient`.
 */
import { ed25519 } from '@noble/curves/ed25519';
import { hexToBytes } from '@noble/hashes/utils';
import { AgentDIDDocument, VerificationRelationship } from '../core/types';
import { decodePublicKeyMultibase } from '../crypto/multibase';
import { assertKeyPurpose, assertSigningPurpose, getRelationshipKeyIds } from '../core/identity-composition';

/** Verifies against active keys listed under `requiredPurpose` (and `keyId`, when given). */
export function verifyWithActiveKeys(
  didDoc: AgentDIDDocument,
  payload: string,
  signature: string,
  keyId: string | undefined,
  requiredPurpose: VerificationRelationship
): boolean {
  assertSigningPurpose(requiredPurpose, didDoc, keyId || '');
  if (keyId) {
    assertKeyPurpose(keyId, didDoc, requiredPurpose);
  }

  const messageBytes = new TextEncoder().encode(payload);
  const signatureBytes = hexToBytes(signature);

  const activeKeyIds = new Set(getRelationshipKeyIds(didDoc, requiredPurpose));
  const candidateMethods = didDoc.verificationMethod.filter((method) => {
    if (!method.publicKeyMultibase || method.deactivated) {
      return false;
    }
    return keyId ? method.id === keyId && activeKeyIds.has(method.id) : activeKeyIds.has(method.id);
  });

  for (const verificationMethod of candidateMethods) {
    const keyValue = verificationMethod.publicKeyMultibase;
    if (!keyValue) continue;
    try {
      if (ed25519.verify(signatureBytes, messageBytes, decodePublicKeyMultibase(keyValue))) {
        return true;
      }
    } catch {
      continue;
    }
  }
  return false;
}
