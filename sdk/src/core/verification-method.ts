/**
 * Verification method types for Ed25519 keys (ADR-006 D-8b). Documents are written with `Multikey`; documents and
 * did:webvh logs written before rc.5 use `Ed25519VerificationKey2020` with the same `publicKeyMultibase` encoding
 * and stay valid. A method of any other type is never used to verify a signature.
 */
export const VERIFICATION_METHOD_TYPE = 'Multikey';

const ED25519_VERIFICATION_METHOD_TYPES: ReadonlySet<string> = new Set(['Multikey', 'Ed25519VerificationKey2020']);

/** Whether `type` names an Ed25519 verification method this SDK reads. */
export function isEd25519VerificationMethodType(type: unknown): boolean {
  return typeof type === 'string' && ED25519_VERIFICATION_METHOD_TYPES.has(type);
}
