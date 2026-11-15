import type { AgentDidContextEntry, RevokedContextTerm, VerificationMethod } from './types';

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

/** The inline `@context` term for `revoked` (see `RevokedContextTerm`). */
export const REVOKED_CONTEXT_TERM: RevokedContextTerm = Object.freeze({
  revoked: Object.freeze({
    '@id': 'https://w3id.org/security#revoked',
    '@type': 'http://www.w3.org/2001/XMLSchema#dateTime'
  })
}) as RevokedContextTerm;

/** Whether `entry` is the inline `revoked` context term, member for member. */
export function isRevokedContextTerm(entry: unknown): entry is RevokedContextTerm {
  if (typeof entry !== 'object' || entry === null || Array.isArray(entry)) {
    return false;
  }
  const term = (entry as Record<string, unknown>).revoked;
  if (Object.keys(entry).length !== 1 || typeof term !== 'object' || term === null || Array.isArray(term)) {
    return false;
  }
  const members = term as Record<string, unknown>;
  return (
    Object.keys(members).length === 2 &&
    members['@id'] === REVOKED_CONTEXT_TERM.revoked['@id'] &&
    members['@type'] === REVOKED_CONTEXT_TERM.revoked['@type']
  );
}

/** Whether `method` carries `revoked` (an emergency revocation). */
export function isRevokedMethod(method: Pick<VerificationMethod, 'revoked'>): boolean {
  return method.revoked !== undefined && method.revoked !== null;
}

/**
 * `context` with the inline `revoked` term last when `methods` has a revoked key, and without it otherwise. The
 * context URLs keep their order.
 */
export function contextForMethods(
  context: readonly AgentDidContextEntry[],
  methods: readonly VerificationMethod[]
): AgentDidContextEntry[] {
  const urls = context.filter((entry) => !isRevokedContextTerm(entry));
  return methods.some(isRevokedMethod) ? [...urls, REVOKED_CONTEXT_TERM] : urls;
}
