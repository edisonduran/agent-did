import { decodePublicKeyMultibase } from '../crypto/multibase';
import type {
  AgentDidContextEntry,
  DidDocument,
  RevokedContextTerm,
  VerificationMethod,
  VerificationRelationship
} from './types';

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

/** `reference` as an absolute DID URL: a relative reference (`#key-1`) is read against `documentId`. */
export function absoluteMethodId(documentId: string, reference: string): string {
  return reference.startsWith('#') ? `${documentId}${reference}` : reference;
}

/**
 * The verification methods `document` lists under `relationship`, with absolute ids: references (absolute or
 * relative) resolved against `verificationMethod`, and methods embedded in the relationship. A reference to a method
 * the document does not have is skipped.
 */
export function relationshipMethods(document: DidDocument, relationship: VerificationRelationship): VerificationMethod[] {
  const declared = new Map<string, VerificationMethod>();
  for (const method of document.verificationMethod ?? []) {
    declared.set(absoluteMethodId(document.id, method.id), method);
  }
  const methods: VerificationMethod[] = [];
  for (const entry of document[relationship] ?? []) {
    if (typeof entry === 'string') {
      const method = declared.get(absoluteMethodId(document.id, entry));
      if (method !== undefined) {
        methods.push({ ...method, id: absoluteMethodId(document.id, method.id) });
      }
    } else {
      methods.push({ ...entry, id: absoluteMethodId(document.id, entry.id) });
    }
  }
  return methods;
}

/**
 * The raw Ed25519 public key of `method` when it is active (no `deactivated`, no `revoked`) and is an Ed25519
 * `publicKeyMultibase` key; `undefined` otherwise.
 */
export function activeEd25519PublicKey(method: VerificationMethod): Uint8Array | undefined {
  if (
    method.deactivated ||
    isRevokedMethod(method) ||
    !method.publicKeyMultibase ||
    !isEd25519VerificationMethodType(method.type)
  ) {
    return undefined;
  }
  try {
    return decodePublicKeyMultibase(method.publicKeyMultibase);
  } catch {
    return undefined;
  }
}
