import {
  AdditionalVerificationRelationship,
  AgentDIDDocument,
  IdentityCompositionErrorReason,
  IdentityCompositionRejection,
  SignedArtifactKind,
  SigningVerificationPurpose,
  VerificationRelationship
} from './types';

export interface IdentityCompositionErrorDetails {
  did?: string;
  keyId: string;
  requiredPurpose: VerificationRelationship;
  foundIn: VerificationRelationship[];
}

export class IdentityCompositionError extends Error {
  public readonly reason: IdentityCompositionErrorReason;
  public readonly did?: string;
  public readonly keyId: string;
  public readonly requiredPurpose: VerificationRelationship;
  public readonly foundIn: VerificationRelationship[];

  constructor(reason: IdentityCompositionErrorReason, details: IdentityCompositionErrorDetails) {
    super(
      `Verification method ${details.keyId || '<unspecified>'} is not authorized for ${details.requiredPurpose}`
    );
    this.name = 'IdentityCompositionError';
    this.reason = reason;
    this.did = details.did;
    this.keyId = details.keyId;
    this.requiredPurpose = details.requiredPurpose;
    this.foundIn = [...details.foundIn];
  }
}

export const DID_VERIFICATION_RELATIONSHIPS: readonly VerificationRelationship[] = [
  'authentication',
  'assertionMethod',
  'capabilityDelegation',
  'capabilityInvocation',
  'keyAgreement'
];

export const SIGNING_VERIFICATION_PURPOSES: readonly SigningVerificationPurpose[] = [
  'authentication',
  'assertionMethod',
  'capabilityDelegation',
  'capabilityInvocation'
];

/**
 * The relationships `CreateAgentParams.additionalVerificationRelationships` accepts, in the order they are
 * written to a document.
 */
export const ADDITIONAL_VERIFICATION_RELATIONSHIPS: readonly AdditionalVerificationRelationship[] = Object.freeze([
  'capabilityDelegation',
  'capabilityInvocation'
] as const);

/** Every `SignedArtifactKind`, in the order RFC-001 §6.2.1.3 lists them. */
export const SIGNED_ARTIFACT_KINDS: readonly SignedArtifactKind[] = Object.freeze([
  'assertion',
  'http_request',
  'delegation',
  'invocation',
  'authentication'
] as const);

/**
 * The verification relationship a signing key must be listed under for each kind of signed artifact
 * (RFC-001 §6.2.1.3). A key listed only under another relationship is rejected for that artifact with
 * `key_purpose_violation`, even if it is valid for a different one; `keyAgreement` never signs.
 */
export const REQUIRED_RELATIONSHIP_BY_ARTIFACT: Readonly<Record<SignedArtifactKind, SigningVerificationPurpose>> =
  Object.freeze({
    assertion: 'assertionMethod',
    http_request: 'assertionMethod',
    delegation: 'capabilityDelegation',
    invocation: 'capabilityInvocation',
    authentication: 'authentication'
  });

/** Returns the verification relationship required for `artifact`; throws `TypeError` for an unknown kind. */
export function requiredRelationshipFor(artifact: SignedArtifactKind): SigningVerificationPurpose {
  if (!Object.prototype.hasOwnProperty.call(REQUIRED_RELATIONSHIP_BY_ARTIFACT, artifact)) {
    throw new TypeError(`Unknown signed artifact kind: ${String(artifact)}`);
  }
  return REQUIRED_RELATIONSHIP_BY_ARTIFACT[artifact];
}

export function getRelationshipKeyIds(
  didDoc: AgentDIDDocument,
  relationship: VerificationRelationship
): string[] {
  switch (relationship) {
    case 'authentication':
      return didDoc.authentication || [];
    case 'assertionMethod':
      return didDoc.assertionMethod || [];
    case 'capabilityDelegation':
      return didDoc.capabilityDelegation || [];
    case 'capabilityInvocation':
      return didDoc.capabilityInvocation || [];
    case 'keyAgreement':
      return didDoc.keyAgreement || [];
  }
}

export function getKeyRelationships(keyId: string, didDoc: AgentDIDDocument): VerificationRelationship[] {
  return DID_VERIFICATION_RELATIONSHIPS.filter((relationship) =>
    getRelationshipKeyIds(didDoc, relationship).includes(keyId)
  );
}

export function assertKeyPurpose(
  keyId: string,
  didDoc: AgentDIDDocument,
  requiredPurpose: VerificationRelationship
): void {
  const foundIn = getKeyRelationships(keyId, didDoc);
  const keyIdsForPurpose = getRelationshipKeyIds(didDoc, requiredPurpose);

  // Membership-only predicate per RFC-001 §6.2.1; signing-purpose policy lives in assertSigningPurpose.
  if (!keyIdsForPurpose.includes(keyId)) {
    throw new IdentityCompositionError('key_purpose_violation', {
      did: didDoc.id,
      keyId,
      requiredPurpose,
      foundIn
    });
  }
}

export function assertSigningPurpose(
  requiredPurpose: VerificationRelationship,
  didDoc: AgentDIDDocument,
  keyId = ''
): asserts requiredPurpose is SigningVerificationPurpose {
  if (requiredPurpose === 'keyAgreement') {
    throw new IdentityCompositionError('key_purpose_violation', {
      did: didDoc.id,
      keyId,
      requiredPurpose,
      foundIn: keyId ? getKeyRelationships(keyId, didDoc) : []
    });
  }
}

/**
 * Composition contract reason for a signature by `keyId` that did not verify as an `assertionMethod` signature,
 * read from the current DID document (contract §4.1, §5.1): `emergency_revoked` for a key that carries `revoked`,
 * `rotation_window_closed` for another retired key, `key_purpose_violation` for an active key outside
 * `assertionMethod`, and `tampered` otherwise (the key is not a key of the document, or the signature is wrong).
 */
export function compositionReasonForKey(didDoc: AgentDIDDocument, keyId: string): IdentityCompositionRejection {
  const method = didDoc.verificationMethod.find((candidate) => candidate.id === keyId);
  if (!method) {
    return 'tampered';
  }
  if (method.revoked !== undefined && method.revoked !== null) {
    return 'emergency_revoked';
  }
  if (method.deactivated) {
    return 'rotation_window_closed';
  }
  if (!getRelationshipKeyIds(didDoc, REQUIRED_RELATIONSHIP_BY_ARTIFACT.assertion).includes(keyId)) {
    return 'key_purpose_violation';
  }
  return 'tampered';
}
