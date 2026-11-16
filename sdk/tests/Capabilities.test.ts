/**
 * Capabilities (RFC-001 §6.7, ADR-008 D-12a/b): delegation chains with `eddsa-jcs-2022` proofs by
 * `capabilityDelegation` keys, attenuation, and invocation over HTTP with a `capabilityInvocation` key.
 * Python parity: sdk-python/tests/test_capabilities.py.
 */
import {
  AgentCapability,
  AgentDidClient,
  AgentIdentity,
  CreateAgentParams,
  LocalKeySigner,
  rootCapabilityId
} from '../src';
import { checkCapabilityChain, parseCapabilityHeader, targetWithin } from '../src/core/capability';
import { encodeEddsaProofValue } from '../src/crypto/data-integrity';

const TARGET = 'https://api.example.com/files';
const FAR = '2099-01-01T00:00:00Z';

type Party = { did: string; keyId: string; signer: LocalKeySigner; privateKey: string };

async function setup(): Promise<{
  client: AgentDidClient;
  identity: AgentIdentity;
  owner: Party;
  alice: Party;
  bob: Party;
  plain: Party;
}> {
  const client = new AgentDidClient();
  const [controllerSigner] = LocalKeySigner.generate();
  const identity = new AgentIdentity({ controllerSigner, client });
  const make = async (name: string, relationships: CreateAgentParams['additionalVerificationRelationships']): Promise<Party> => {
    const created = await identity.create({ name, additionalVerificationRelationships: relationships });
    return {
      did: created.document.id,
      keyId: `${created.document.id}#key-1`,
      signer: new LocalKeySigner(created.agentPrivateKey),
      privateKey: created.agentPrivateKey
    };
  };
  return {
    client,
    identity,
    owner: await make('Owner', ['capabilityDelegation']),
    alice: await make('Alice', ['capabilityDelegation', 'capabilityInvocation']),
    bob: await make('Bob', ['capabilityInvocation']),
    plain: await make('Plain', [])
  };
}

function clone<T>(value: T): T {
  return JSON.parse(JSON.stringify(value)) as T;
}

describe('capabilities (RFC-001 §6.7)', () => {
  it('delegates from the root and verifies the chain', async () => {
    const { client, owner, alice } = await setup();
    const capability = await client.createCapability({
      invocationTarget: TARGET,
      controller: alice.did,
      expires: FAR,
      allowedAction: ['GET', 'POST'],
      verificationMethodId: owner.keyId,
      signer: owner.signer
    });
    expect(capability.parentCapability).toBe(rootCapabilityId(TARGET));
    expect(capability.parentCapability).toBe('urn:zcap:root:https%3A%2F%2Fapi.example.com%2Ffiles');
    expect(capability.proof.capabilityChain).toEqual([capability.parentCapability]);
    expect(capability.proof.proofPurpose).toBe('capabilityDelegation');
    expect(capability.id).toMatch(/^urn:uuid:[0-9a-f-]{36}$/u);

    const result = await client.verifyCapabilityChain(capability, { rootControllers: { [TARGET]: [owner.did] } });
    expect(result).toEqual({
      ok: true,
      capability,
      controller: alice.did,
      invocationTarget: TARGET,
      allowedAction: ['GET', 'POST'],
      rootId: capability.parentCapability,
      delegators: [owner.did]
    });
  });

  it('verifies a chain of three with attenuation', async () => {
    const { client, owner, alice, bob } = await setup();
    const first = await client.createCapability({
      invocationTarget: TARGET, controller: alice.did, expires: FAR, verificationMethodId: owner.keyId, signer: owner.signer
    });
    const second = await client.createCapability({
      invocationTarget: `${TARGET}/reports`,
      controller: alice.did,
      expires: '2098-01-01T00:00:00Z',
      allowedAction: ['GET'],
      parentCapability: first,
      verificationMethodId: alice.keyId,
      signer: alice.signer
    });
    const third = await client.createCapability({
      invocationTarget: `${TARGET}/reports/2026`,
      controller: bob.did,
      expires: '2097-01-01T00:00:00Z',
      parentCapability: second,
      verificationMethodId: alice.keyId,
      signer: alice.signer
    });
    expect(third.proof.capabilityChain).toEqual([first.parentCapability, first.id, second]);
    const result = await client.verifyCapabilityChain(third, { rootControllers: { [TARGET]: [owner.did] } });
    expect(result).toMatchObject({ ok: true, controller: bob.did, allowedAction: ['GET'], delegators: [owner.did, alice.did, alice.did] });
    expect((await client.verifyCapabilityChain(third, { rootControllers: { [TARGET]: [owner.did] }, maxChainLength: 2 })))
      .toEqual({ ok: false, reason: 'chain_too_long', capabilityId: third.id });
  });

  it('refuses to create a capability that widens its parent or is signed by someone else', async () => {
    const { client, owner, alice, bob } = await setup();
    const parent = await client.createCapability({
      invocationTarget: TARGET, controller: alice.did, expires: '2098-01-01T00:00:00Z', allowedAction: ['GET'],
      verificationMethodId: owner.keyId, signer: owner.signer
    });
    const base = { controller: bob.did, parentCapability: parent, verificationMethodId: alice.keyId, signer: alice.signer };
    await expect(client.createCapability({ ...base, invocationTarget: 'https://api.example.com/other', expires: '2097-01-01T00:00:00Z' }))
      .rejects.toThrow(/widen/u);
    await expect(client.createCapability({ ...base, invocationTarget: TARGET, expires: FAR })).rejects.toThrow(/widen/u);
    await expect(client.createCapability({ ...base, invocationTarget: TARGET, expires: '2097-01-01T00:00:00Z', allowedAction: ['DELETE'] }))
      .rejects.toThrow(/widen/u);
    await expect(client.createCapability({ ...base, verificationMethodId: owner.keyId, signer: owner.signer, invocationTarget: TARGET, expires: '2097-01-01T00:00:00Z' }))
      .rejects.toThrow(/controller/u);
  });

  it('refuses a delegation key that is not under capabilityDelegation', async () => {
    const { client, alice, bob } = await setup();
    await expect(client.createCapability({
      invocationTarget: TARGET, controller: alice.did, expires: FAR, verificationMethodId: bob.keyId, signer: bob.signer
    })).rejects.toThrow(/capabilityDelegation/u);
  });

  it('rejects a chain whose root controller is not configured or not the signer', async () => {
    const { client, owner, alice, bob } = await setup();
    const capability = await client.createCapability({
      invocationTarget: TARGET, controller: alice.did, expires: FAR, verificationMethodId: owner.keyId, signer: owner.signer
    });
    expect(await client.verifyCapabilityChain(capability, { rootControllers: {} }))
      .toEqual({ ok: false, reason: 'root_controller_unknown', capabilityId: capability.id });
    expect(await client.verifyCapabilityChain(capability, { rootControllers: { [TARGET]: [bob.did] } }))
      .toEqual({ ok: false, reason: 'delegator_mismatch', capabilityId: capability.id });
  });

  it('rejects tampering, expiry and a key moved out of capabilityDelegation', async () => {
    const { client, owner, alice, plain } = await setup();
    const rootControllers = { [TARGET]: [owner.did, plain.did] };
    const capability = await client.createCapability({
      invocationTarget: TARGET, controller: alice.did, expires: '2030-01-01T00:00:00Z', verificationMethodId: owner.keyId, signer: owner.signer
    });
    const tampered = clone(capability);
    tampered.controller = plain.did;
    expect(await client.verifyCapabilityChain(tampered, { rootControllers }))
      .toEqual({ ok: false, reason: 'signature_invalid', capabilityId: capability.id });

    const later = new AgentDidClient({ clock: () => new Date('2031-01-01T00:00:00Z') });
    expect(await later.verifyCapabilityChain(capability, { rootControllers }))
      .toEqual({ ok: false, reason: 'expired', capabilityId: capability.id });

    // Signed by a key that is only under authentication/assertionMethod
    const forged = clone(capability) as unknown as Record<string, unknown> & AgentCapability;
    forged.proof.verificationMethod = plain.keyId;
    expect(await client.verifyCapabilityChain(forged, { rootControllers }))
      .toEqual({ ok: false, reason: 'key_purpose_violation', capabilityId: capability.id });
    forged.proof.verificationMethod = `${plain.did}#key-9`;
    expect(await client.verifyCapabilityChain(forged, { rootControllers }))
      .toEqual({ ok: false, reason: 'key_not_authorized', capabilityId: capability.id });
  });

  it('checks attenuation in a chain it did not create', async () => {
    const { owner, alice, bob } = await setup();
    const rootId = rootCapabilityId(TARGET);
    const proof = (chain: unknown[], keyId: string) => ({
      type: 'DataIntegrityProof', cryptosuite: 'eddsa-jcs-2022', created: '2026-11-15T00:00:00Z',
      verificationMethod: keyId, proofPurpose: 'capabilityDelegation', capabilityChain: chain,
      proofValue: encodeEddsaProofValue(new Uint8Array(64))
    });
    const first = {
      '@context': ['https://w3id.org/zcap/v1'], id: 'urn:uuid:00000000-0000-4000-8000-000000000001',
      parentCapability: rootId, invocationTarget: `${TARGET}/a`, controller: alice.did, allowedAction: ['GET'],
      expires: '2098-01-01T00:00:00Z', proof: proof([rootId], owner.keyId)
    };
    const second = {
      '@context': ['https://w3id.org/zcap/v1'], id: 'urn:uuid:00000000-0000-4000-8000-000000000002',
      parentCapability: first.id, invocationTarget: `${TARGET}/b`, controller: bob.did,
      expires: '2097-01-01T00:00:00Z', proof: proof([rootId, first], alice.keyId)
    };
    const now = Date.parse('2026-11-15T00:00:00Z');
    const roots = { [TARGET]: [owner.did] };
    expect(checkCapabilityChain(second, roots, now)).toEqual({ ok: false, reason: 'attenuation_violation', capabilityId: second.id });
    expect(checkCapabilityChain({ ...second, invocationTarget: `${TARGET}/a/b` }, roots, now)).toMatchObject({ ok: true, value: { allowedAction: ['GET'] } });
    expect(checkCapabilityChain({ ...second, invocationTarget: `${TARGET}/a/b`, allowedAction: ['GET', 'PUT'] }, roots, now))
      .toMatchObject({ ok: false, reason: 'attenuation_violation' });
    expect(checkCapabilityChain({ ...second, invocationTarget: `${TARGET}/a/b`, expires: FAR }, roots, now))
      .toMatchObject({ ok: false, reason: 'attenuation_violation' });
    // The embedded parent must be the one named in parentCapability
    expect(checkCapabilityChain({ ...second, parentCapability: 'urn:uuid:00000000-0000-4000-8000-000000000009' }, roots, now))
      .toMatchObject({ ok: false, reason: 'malformed_capability' });
    // Root not first in the chain
    expect(checkCapabilityChain({ ...first, proof: proof(['urn:uuid:x'], owner.keyId), parentCapability: 'urn:uuid:x' }, roots, now))
      .toMatchObject({ ok: false, reason: 'malformed_capability' });
    // Unknown members and a wrong purpose
    expect(checkCapabilityChain({ ...first, extra: 1 }, roots, now)).toMatchObject({ ok: false, reason: 'malformed_capability' });
    expect(checkCapabilityChain({ ...first, proof: { ...first.proof, proofPurpose: 'assertionMethod' } }, roots, now))
      .toMatchObject({ ok: false, reason: 'unsupported_proof' });
    expect(checkCapabilityChain({ ...first, invocationTarget: `${TARGET}?q=1` }, roots, now))
      .toMatchObject({ ok: false, reason: 'malformed_capability' });
  });

  it('matches targets only on a path boundary', () => {
    expect(targetWithin(TARGET, TARGET)).toBe(true);
    expect(targetWithin(`${TARGET}/x`, TARGET)).toBe(true);
    expect(targetWithin(`${TARGET}x`, TARGET)).toBe(false);
    expect(targetWithin(`${TARGET}/`, TARGET)).toBe(false);
    expect(targetWithin('https://api.example.com/a', 'https://api.example.com/')).toBe(true);
  });
});

describe('capability invocation over HTTP (RFC-001 §6.5, §6.7)', () => {
  async function invocation(method = 'GET', url = `${TARGET}/reports`) {
    const parties = await setup();
    const { client, identity, owner, bob } = parties;
    const capability = await client.createCapability({
      invocationTarget: TARGET, controller: bob.did, expires: FAR, allowedAction: ['GET'],
      verificationMethodId: owner.keyId, signer: owner.signer
    });
    const headers = await identity.signHttpRequest({
      method, url, agentDid: bob.did, agentPrivateKey: bob.privateKey, verificationMethodId: bob.keyId, capability
    });
    return { ...parties, capability, request: { method, url, headers }, rootControllers: { [TARGET]: [owner.did] } };
  }

  it('accepts an invocation by the capability controller and records the nonce', async () => {
    const { client, capability, request, rootControllers, bob, owner } = await invocation();
    expect(request.headers['Signature-Input']).toContain('"agent-did-capability";key="sig1"');
    expect(parseCapabilityHeader(request.headers['Agent-DID-Capability'], 'sig1')).toEqual(capability);
    const result = await client.verifyHttpCapabilityInvocation({ ...request, rootControllers });
    expect(result).toMatchObject({ ok: true, did: bob.did, keyId: bob.keyId, capability, allowedAction: ['GET'], delegators: [owner.did] });
    expect(await client.verifyHttpCapabilityInvocation({ ...request, rootControllers })).toEqual({ ok: false, reason: 'nonce_replayed' });
  });

  it('is also an identity signature for a plain verifier when the key is also under assertionMethod', async () => {
    const { client, request, bob } = await invocation();
    expect(await client.verifyHttpRequestSignatureDetailed(request)).toMatchObject({ ok: true, did: bob.did });
  });

  it('rejects an invocation key that is not under capabilityInvocation', async () => {
    const { client, identity, owner, plain } = await setup();
    const capability = await client.createCapability({
      invocationTarget: TARGET, controller: plain.did, expires: FAR, verificationMethodId: owner.keyId, signer: owner.signer
    });
    const headers = await identity.signHttpRequest({
      method: 'GET', url: TARGET, agentDid: plain.did, agentPrivateKey: plain.privateKey, verificationMethodId: plain.keyId, capability
    });
    expect(await client.verifyHttpCapabilityInvocation({ method: 'GET', url: TARGET, headers, rootControllers: { [TARGET]: [owner.did] } }))
      .toEqual({ ok: false, reason: 'keyid_not_authorized' });
  });

  it('rejects a method outside allowedAction and a URL outside the target', async () => {
    const post = await invocation('POST');
    expect(await post.client.verifyHttpCapabilityInvocation({ ...post.request, rootControllers: post.rootControllers }))
      .toEqual({ ok: false, reason: 'action_not_allowed', capabilityId: post.capability.id });
    const elsewhere = await invocation('GET', 'https://api.example.com/filesystem');
    expect(await elsewhere.client.verifyHttpCapabilityInvocation({ ...elsewhere.request, rootControllers: elsewhere.rootControllers }))
      .toEqual({ ok: false, reason: 'target_mismatch', capabilityId: elsewhere.capability.id });
  });

  it('accepts a query on a URL within the target', async () => {
    const { client, request, rootControllers } = await invocation('GET', `${TARGET}/reports?year=2026`);
    expect(await client.verifyHttpCapabilityInvocation({ ...request, rootControllers })).toMatchObject({ ok: true });
  });

  it('rejects a request without a covered capability, and an invoker that is not the controller', async () => {
    const { client, identity, capability, rootControllers, alice } = await invocation();
    const url = `${TARGET}/reports`;
    const plainHeaders = await identity.signHttpRequest({
      method: 'GET', url, agentDid: alice.did, agentPrivateKey: alice.privateKey, verificationMethodId: alice.keyId
    });
    expect(await client.verifyHttpCapabilityInvocation({ method: 'GET', url, headers: plainHeaders, rootControllers }))
      .toEqual({ ok: false, reason: 'capability_missing' });
    // Alice adds Bob's capability to her own request: not the controller
    await expect(identity.signHttpRequest({
      method: 'GET', url, agentDid: alice.did, agentPrivateKey: alice.privateKey, verificationMethodId: alice.keyId, capability
    })).rejects.toThrow(/held by/u);
    const stolen = { ...plainHeaders, 'Agent-DID-Capability': `sig1=:${Buffer.from(JSON.stringify(capability)).toString('base64')}:` };
    expect(await client.verifyHttpCapabilityInvocation({ method: 'GET', url, headers: stolen, rootControllers }))
      .toEqual({ ok: false, reason: 'capability_missing' });
  });

  it('rejects an oversized or malformed capability field', async () => {
    const { client, request, rootControllers } = await invocation();
    const big = { ...request.headers, 'Agent-DID-Capability': `sig1=:${'A'.repeat(9000)}:` };
    expect(await client.verifyHttpCapabilityInvocation({ ...request, headers: big, rootControllers }))
      .toEqual({ ok: false, reason: 'capability_too_large' });
  });

  it('rejects a capability changed in transit (the field is covered)', async () => {
    const { client, request, rootControllers, capability } = await invocation();
    const changed = clone(capability);
    changed.allowedAction = ['GET', 'DELETE'];
    const { canonicalizeJson } = await import('../src/crypto/hash');
    const headers = { ...request.headers, 'Agent-DID-Capability': `sig1=:${Buffer.from(canonicalizeJson(changed)).toString('base64')}:` };
    expect(await client.verifyHttpCapabilityInvocation({ ...request, headers, rootControllers }))
      .toEqual({ ok: false, reason: 'signature_invalid' });
  });
});
