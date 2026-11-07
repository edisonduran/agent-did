/**
 * Runs fixtures/verification-relationship-vectors.json (RFC-001 §6.2.1.3). The Python SDK runs the same file
 * in sdk-python/tests/test_verification_relationship_vectors.py.
 */
import * as fs from 'fs';
import * as path from 'path';
import { ed25519 } from '@noble/curves/ed25519';
import { hexToBytes } from '@noble/hashes/utils';
import {
  AgentDIDDocument,
  IdentityCompositionError,
  REQUIRED_RELATIONSHIP_BY_ARTIFACT,
  SIGNED_ARTIFACT_KINDS,
  SignedArtifactKind,
  assertKeyPurpose,
  assertSigningPurpose,
  requiredRelationshipFor
} from '../src';
import { decodePublicKeyMultibase } from '../src/crypto/multibase';

interface RelationshipVector {
  id: string;
  artifact: SignedArtifactKind;
  keyId: string;
  signatureHex: string;
  expected: { ok: true } | { ok: false; reason: string; requiredPurpose: string; foundIn: string[] };
}

const fixture = JSON.parse(
  fs.readFileSync(path.join(__dirname, '..', '..', 'fixtures', 'verification-relationship-vectors.json'), 'utf8')
) as {
  requiredRelationshipByArtifact: Record<string, string>;
  payload: string;
  didDocument: AgentDIDDocument;
  vectors: RelationshipVector[];
};

/** The SDK path for a signed artifact: pick the relationship from the table, then apply §6.2.1. */
function checkKeyForArtifact(doc: AgentDIDDocument, keyId: string, artifact: SignedArtifactKind): void {
  const required = requiredRelationshipFor(artifact);
  assertSigningPurpose(required, doc, keyId);
  assertKeyPurpose(keyId, doc, required);
}

describe('verification relationship vectors (RFC-001 §6.2.1.3)', () => {
  it('exports the same artifact table as the fixture', () => {
    expect({ ...REQUIRED_RELATIONSHIP_BY_ARTIFACT }).toEqual(fixture.requiredRelationshipByArtifact);
    expect([...SIGNED_ARTIFACT_KINDS]).toEqual(Object.keys(fixture.requiredRelationshipByArtifact));
    expect(Object.isFrozen(REQUIRED_RELATIONSHIP_BY_ARTIFACT)).toBe(true);
  });

  it('rejects an unknown artifact kind', () => {
    expect(() => requiredRelationshipFor('receipt' as SignedArtifactKind)).toThrow(TypeError);
    expect(() => requiredRelationshipFor('toString' as SignedArtifactKind)).toThrow(TypeError);
  });

  it.each(fixture.vectors.map((vector) => [vector.id, vector] as const))('%s', (_id, vector) => {
    // The signature is valid for the key, so a rejection can only come from the relationship check.
    const method = fixture.didDocument.verificationMethod.find((candidate) => candidate.id === vector.keyId);
    expect(method?.publicKeyMultibase).toBeDefined();
    expect(
      ed25519.verify(
        hexToBytes(vector.signatureHex),
        new TextEncoder().encode(fixture.payload),
        decodePublicKeyMultibase(method!.publicKeyMultibase!)
      )
    ).toBe(true);

    if (vector.expected.ok) {
      expect(() => checkKeyForArtifact(fixture.didDocument, vector.keyId, vector.artifact)).not.toThrow();
      return;
    }

    let caught: unknown;
    try {
      checkKeyForArtifact(fixture.didDocument, vector.keyId, vector.artifact);
    } catch (error) {
      caught = error;
    }
    expect(caught).toBeInstanceOf(IdentityCompositionError);
    expect(caught).toMatchObject({
      reason: vector.expected.reason,
      keyId: vector.keyId,
      requiredPurpose: vector.expected.requiredPurpose,
      foundIn: vector.expected.foundIn
    });
  });
});
