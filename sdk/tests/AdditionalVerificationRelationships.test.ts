/**
 * `CreateAgentParams.additionalVerificationRelationships` (RFC-001 §6.2.1.3): an opt-in that lists the agent
 * key under `capabilityDelegation` / `capabilityInvocation`. The Python SDK runs the same cases in
 * sdk-python/tests/test_additional_verification_relationships.py.
 */
import {
  ADDITIONAL_VERIFICATION_RELATIONSHIPS,
  AdditionalVerificationRelationship,
  AgentDIDDocument,
  AgentDidClient,
  AgentIdentity,
  CreateAgentParams,
  IdentityCompositionError,
  LocalKeySigner,
  REQUIRED_RELATIONSHIP_BY_ARTIFACT,
  assertKeyPurpose,
  requiredRelationshipFor
} from '../src';
import { buildRotatedDocument } from '../src/lifecycle/documents';
import { resolveDidWebvhLog } from '../src/webvh/adapter';

const params: CreateAgentParams = {
  name: 'DelegatingBot',
  coreModel: 'gpt-4o-mini',
  systemPrompt: 'You are a test assistant.'
};

function setup(): { client: AgentDidClient; identity: AgentIdentity } {
  const client = new AgentDidClient();
  const [controllerSigner] = LocalKeySigner.generate();
  return { client, identity: new AgentIdentity({ controllerSigner, client }) };
}

describe('additionalVerificationRelationships (RFC-001 §6.2.1.3)', () => {
  it('exports the accepted relationships in document order', () => {
    expect([...ADDITIONAL_VERIFICATION_RELATIONSHIPS]).toEqual(['capabilityDelegation', 'capabilityInvocation']);
    expect(Object.isFrozen(ADDITIONAL_VERIFICATION_RELATIONSHIPS)).toBe(true);
  });

  it.each([undefined, []])('leaves the document as before when the option is %p', async (requested) => {
    const { identity } = setup();
    const { document } = await identity.create({ ...params, additionalVerificationRelationships: requested });
    expect(Object.keys(document)).not.toContain('capabilityDelegation');
    expect(Object.keys(document)).not.toContain('capabilityInvocation');
    expect(document.authentication).toEqual([`${document.id}#key-1`]);
    expect(document.assertionMethod).toEqual([`${document.id}#key-1`]);
  });

  it('lists the agent key under the requested relationships in a fixed order (did:webvh)', async () => {
    const { client, identity } = setup();
    const { document } = await identity.create({
      ...params,
      additionalVerificationRelationships: ['capabilityInvocation', 'capabilityDelegation', 'capabilityInvocation']
    });
    const keyId = `${document.id}#key-1`;
    expect(document.capabilityDelegation).toEqual([keyId]);
    expect(document.capabilityInvocation).toEqual([keyId]);
    expect(Object.keys(document).filter((key) => key.startsWith('capability'))).toEqual([
      'capabilityDelegation',
      'capabilityInvocation'
    ]);

    // The relationships are part of the signed genesis entry of the log.
    const resolved = await resolveDidWebvhLog(client.exportDidWebvhHistory(document.id));
    expect(resolved.state.capabilityDelegation).toEqual([keyId]);
    expect(resolved.state.capabilityInvocation).toEqual([keyId]);
  });

  it('lets a created agent sign a delegation that a verifier accepts', async () => {
    const { client, identity } = setup();
    const { document, agentPrivateKey } = await identity.create({
      ...params,
      additionalVerificationRelationships: ['capabilityDelegation']
    });
    const signature = await identity.signMessage('delegation', agentPrivateKey);

    expect(await client.verifySignature(document.id, 'delegation', signature, undefined, REQUIRED_RELATIONSHIP_BY_ARTIFACT.delegation)).toBe(true);
    expect(await client.verifySignature(document.id, 'delegation', signature, undefined, REQUIRED_RELATIONSHIP_BY_ARTIFACT.invocation)).toBe(false);
  });

  it('rejects a delegation from an agent created without the option', async () => {
    const { client, identity } = setup();
    const { document, agentPrivateKey } = await identity.create(params);
    const signature = await identity.signMessage('delegation', agentPrivateKey);

    expect(await client.verifySignature(document.id, 'delegation', signature, undefined, REQUIRED_RELATIONSHIP_BY_ARTIFACT.delegation)).toBe(false);
    expect(() => assertKeyPurpose(`${document.id}#key-1`, document, requiredRelationshipFor('delegation'))).toThrow(
      IdentityCompositionError
    );
  });

  it('applies to the legacy did:agent profile', async () => {
    const { identity } = setup();
    const { document } = await identity.create({
      ...params,
      didMethod: 'agent',
      additionalVerificationRelationships: ['capabilityDelegation']
    });
    expect(document.capabilityDelegation).toEqual([`${document.id}#key-1`]);
    expect(document.capabilityInvocation).toBeUndefined();
  });

  it.each([['assertionMethod'], ['keyAgreement'], ['authentication'], ['']])(
    'rejects %p before creating anything',
    async (relationship) => {
      const { client, identity } = setup();
      await expect(
        identity.create({
          ...params,
          additionalVerificationRelationships: [relationship as AdditionalVerificationRelationship]
        })
      ).rejects.toThrow(TypeError);
      const stores = client as unknown as Record<'didWebvhLogStore' | 'bootstrapControllers', Map<string, unknown>>;
      expect(stores.didWebvhLogStore.size).toBe(0);
      expect(stores.bootstrapControllers.size).toBe(0);
    }
  );

  it('rejects a value that is not an array', async () => {
    const { identity } = setup();
    await expect(
      identity.create({
        ...params,
        additionalVerificationRelationships: 'capabilityDelegation' as unknown as AdditionalVerificationRelationship[]
      })
    ).rejects.toThrow(TypeError);
  });

  it('carries the relationships over to the new key on rotation', async () => {
    const { client, identity } = setup();
    const { document } = await identity.create({
      ...params,
      additionalVerificationRelationships: ['capabilityDelegation']
    });
    const rotated = await client.rotateVerificationMethod(document.id);
    const newKeyId = rotated.verificationMethodId;

    expect(rotated.document.capabilityDelegation).toEqual([`${document.id}#key-1`, newKeyId]);
    expect(rotated.document.capabilityInvocation).toBeUndefined();

    const signature = await identity.signMessage('delegation', rotated.agentPrivateKey);
    expect(await client.verifySignature(document.id, 'delegation', signature, newKeyId, REQUIRED_RELATIONSHIP_BY_ARTIFACT.delegation)).toBe(true);
  });

  it('does not add a capability relationship on rotation when the document had none', async () => {
    const { client, identity } = setup();
    const { document } = await identity.create(params);
    const rotated = await client.rotateVerificationMethod(document.id);
    expect(Object.keys(rotated.document)).not.toContain('capabilityDelegation');
    expect(Object.keys(rotated.document)).not.toContain('capabilityInvocation');
  });

  it('does not give the new key a relationship that names only another party key', () => {
    const did = 'did:example:rotation';
    const existing: AgentDIDDocument = {
      '@context': ['https://www.w3.org/ns/did/v1', 'https://agent-did.org/v1'],
      id: did,
      controller: did,
      created: '2026-11-07T00:00:00.000Z',
      updated: '2026-11-07T00:00:00.000Z',
      agentMetadata: {
        name: 'RotationAgent',
        version: '1.0.0',
        coreModelHash: 'hash://sha256/00',
        systemPromptHash: 'hash://sha256/00'
      },
      verificationMethod: [
        { id: `${did}#key-1`, type: 'Ed25519VerificationKey2020', controller: did, publicKeyMultibase: 'z6Mk' }
      ],
      authentication: [`${did}#key-1`],
      assertionMethod: [`${did}#key-1`],
      capabilityDelegation: ['did:example:other#key-1']
    };

    const { document, verificationMethodId } = buildRotatedDocument(did, existing, '2026-11-07T00:00:01.000Z');
    expect(document.capabilityDelegation).toEqual(['did:example:other#key-1']);
    expect(document.capabilityDelegation).not.toContain(verificationMethodId);
  });
});
