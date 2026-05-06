import {
  AgentDIDDocument,
  IdentityCompositionErrorReason,
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