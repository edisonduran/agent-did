/**
 * A rotated-out key leaves every verification relationship (it stays in `verificationMethod` with a
 * `deactivated` time), and `verifyWithActiveKeys` answers `false` for malformed input instead of throwing.
 * The Python SDK runs the same cases in sdk-python/tests/test_rotation_relationships.py.
 */
import { ed25519 } from '@noble/curves/ed25519';
import { hexToBytes } from '@noble/hashes/utils';
import { AgentDIDDocument, AgentDidClient, AgentIdentity, LocalKeySigner, messageSigningInput } from '../src';
import { decodePublicKeyMultibase, encodePublicKeyMultibase } from '../src/crypto/multibase';
import { buildUpdatedDocument } from '../src/lifecycle/documents';
import { verifyWithActiveKeys } from '../src/verification/signature';

const RELATIONSHIPS = ['authentication', 'assertionMethod', 'capabilityDelegation', 'capabilityInvocation'] as const;

function setup() {
  const client = new AgentDidClient();
  const [controllerSigner] = LocalKeySigner.generate();
  return { client, identity: new AgentIdentity({ controllerSigner, client }) };
}

const params = {
  name: 'RotatingBot',
  coreModel: 'gpt-4o-mini',
  systemPrompt: 'You are a test assistant.',
  additionalVerificationRelationships: ['capabilityDelegation', 'capabilityInvocation'] as Array<
    'capabilityDelegation' | 'capabilityInvocation'
  >
};

function listedKeyIds(document: AgentDIDDocument): string[] {
  return RELATIONSHIPS.flatMap((relationship) => document[relationship] ?? []);
}

/** What a DID Core verifier that does not know `deactivated` does: the key is listed and the signature verifies. */
function coreStyleVerifies(document: AgentDIDDocument, keyId: string, payload: string, signature: string): boolean {
  const method = document.verificationMethod.find((candidate) => candidate.id === keyId);
  if (!method?.publicKeyMultibase || !(document.assertionMethod ?? []).includes(keyId)) {
    return false;
  }
  return ed25519.verify(hexToBytes(signature), messageSigningInput(payload), decodePublicKeyMultibase(method.publicKeyMultibase));
}

describe('rotation and verification relationships', () => {
  it('lists no retired key in any relationship after one or more rotations', async () => {
    const { client, identity } = setup();
    const { document } = await identity.create(params);
    const first = await client.rotateVerificationMethod(document.id);
    const second = await client.rotateVerificationMethod(document.id);

    for (const rotated of [first, second]) {
      const retired = rotated.document.verificationMethod.filter((method) => method.deactivated).map((method) => method.id);
      expect(retired.length).toBeGreaterThan(0);
      expect(listedKeyIds(rotated.document).filter((keyId) => retired.includes(keyId))).toEqual([]);
      expect(rotated.document.authentication).toEqual([rotated.verificationMethodId]);
      expect(rotated.document.assertionMethod).toEqual([rotated.verificationMethodId]);
      expect(rotated.document.capabilityDelegation).toEqual([rotated.verificationMethodId]);
      expect(rotated.document.capabilityInvocation).toEqual([rotated.verificationMethodId]);
    }
    expect(second.document.verificationMethod).toHaveLength(3);
  });

  it('keeps a DID Core style verifier from accepting a signature by the rotated-out key', async () => {
    const { client, identity } = setup();
    const { document, agentPrivateKey } = await identity.create(params);
    const oldKeyId = document.verificationMethod[0].id;
    const signature = await identity.signMessage('approve', agentPrivateKey);
    expect(coreStyleVerifies(document, oldKeyId, 'approve', signature)).toBe(true);

    const { document: rotated } = await client.rotateVerificationMethod(document.id);

    expect(coreStyleVerifies(rotated, oldKeyId, 'approve', signature)).toBe(false);
  });

  it('answers false, without throwing, for the key id of a rotated-out key', async () => {
    const { client, identity } = setup();
    const { document, agentPrivateKey } = await identity.create(params);
    const oldKeyId = document.verificationMethod[0].id;
    const signature = await identity.signMessage('approve', agentPrivateKey);

    await client.rotateVerificationMethod(document.id);

    expect(await client.verifySignature(document.id, 'approve', signature, oldKeyId)).toBe(false);
  });

  it('keeps rejecting a retired key that a document written by an earlier release still lists', async () => {
    const { client, identity } = setup();
    const { document, agentPrivateKey } = await identity.create(params);
    const oldKeyId = document.verificationMethod[0].id;
    const signature = await identity.signMessage('approve', agentPrivateKey);
    const { document: rotated } = await client.rotateVerificationMethod(document.id);
    const legacy: AgentDIDDocument = { ...rotated, assertionMethod: [oldKeyId, ...(rotated.assertionMethod ?? [])] };

    expect(verifyWithActiveKeys(legacy, messageSigningInput('approve'), signature, oldKeyId, 'assertionMethod')).toBe(false);
    expect(verifyWithActiveKeys(legacy, messageSigningInput('approve'), signature, undefined, 'assertionMethod')).toBe(false);
  });

  it('removes the retired keys from the relationships on the next update of such a document', async () => {
    const { client, identity } = setup();
    const { document } = await identity.create(params);
    const oldKeyId = document.verificationMethod[0].id;
    const { document: rotated } = await client.rotateVerificationMethod(document.id);
    const legacy: AgentDIDDocument = {
      ...rotated,
      assertionMethod: [oldKeyId, ...(rotated.assertionMethod ?? [])],
      capabilityDelegation: [oldKeyId, ...(rotated.capabilityDelegation ?? [])]
    };

    const updated = buildUpdatedDocument(legacy, { description: 'republished' }, '2030-01-01T00:00:00.000Z');

    expect(listedKeyIds(updated)).not.toContain(oldKeyId);
    expect(updated.verificationMethod.map((method) => method.id)).toContain(oldKeyId);
  });
});

describe('rotation with a key held elsewhere', () => {
  it('uses the public key of an external signer and never returns a private key', async () => {
    const { client, identity } = setup();
    const { document } = await identity.create(params);
    const [kmsSigner] = LocalKeySigner.generate();

    const rotated = await client.rotateVerificationMethod(document.id, { signer: kmsSigner });

    expect(rotated.agentPrivateKey).toBe('');
    const method = rotated.document.verificationMethod.find((candidate) => candidate.id === rotated.verificationMethodId);
    expect(method?.publicKeyMultibase).toBe(encodePublicKeyMultibase(await kmsSigner.getPublicKey()));
    const signature = await identity.signMessage('approve', kmsSigner);
    expect(await client.verifySignature(document.id, 'approve', signature, rotated.verificationMethodId)).toBe(true);
  });
});

describe('signHttpRequest without a verification method', () => {
  it('requires the verification method id instead of guessing #key-1', async () => {
    const { identity } = setup();
    const { document, agentPrivateKey } = await identity.create({ name: 'NoKeyIdBot', coreModel: 'm', systemPrompt: 'p' });

    await expect(
      identity.signHttpRequest({
        method: 'GET',
        url: 'https://api.example.com/data',
        agentPrivateKey,
        agentDid: document.id
      } as never)
    ).rejects.toThrow('verificationMethodId is required');
  });
});

describe('verifyWithActiveKeys with malformed input', () => {
  it('answers false for a signature that is not hex, and for an empty key id', async () => {
    const { identity } = setup();
    const { document, agentPrivateKey } = await identity.create({ name: 'MalformedBot', coreModel: 'm', systemPrompt: 'p' });
    const signature = await identity.signMessage('approve', agentPrivateKey);
    const keyId = document.verificationMethod[0].id;

    expect(verifyWithActiveKeys(document, messageSigningInput('approve'), signature, keyId, 'assertionMethod')).toBe(true);
    expect(verifyWithActiveKeys(document, 'approve', 'zz-not-hex', keyId, 'assertionMethod')).toBe(false);
    expect(verifyWithActiveKeys(document, 'approve', 'abc', keyId, 'assertionMethod')).toBe(false);
    expect(verifyWithActiveKeys(document, 'approve', signature, '', 'assertionMethod')).toBe(false);
  });
});
