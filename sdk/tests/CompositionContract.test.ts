/**
 * Composition contract (docs/RFC-001-A2A-Identity-Composition-Contract.md): single-key retirement, emergency
 * revocation, signed Agent Cards and the request-against-card check with the contract reasons.
 * Parity: sdk-python/tests/test_composition_contract.py
 */
import {
  AGENT_DID_A2A_EXTENSION_URI,
  AgentDidClient,
  AgentIdentity,
  InMemoryNonceStore,
  LocalKeySigner,
  REVOKED_CONTEXT_TERM,
  messageSigningInput,
  parseSignedAgentCard,
  signAgentCard
} from '../src';
import { agentDidDocumentProblem } from '../src/core/document-guard';
import { base64UrlToBytes, bytesToBase64Url } from '../src/crypto/base64';

const REQUEST = { method: 'POST', url: 'https://agent.example.com/a2a', body: '{"task":1}' };

async function setup() {
  const client = new AgentDidClient({ nonceStore: new InMemoryNonceStore() });
  const identity = new AgentIdentity({ controllerSigner: LocalKeySigner.generate()[0], client });
  const created = await identity.create({ name: 'CardBot', coreModel: 'test', systemPrompt: 'test' });
  const did = created.document.id;
  const firstKeyId = created.document.assertionMethod![0];
  const firstSigner = new LocalKeySigner(created.agentPrivateKey);
  return { client, identity, did, firstKeyId, firstSigner };
}

function card(did: string, keyIds: string[]) {
  return {
    name: 'CardBot',
    description: 'Test agent',
    version: '1.0.0',
    capabilities: { extensions: [{ uri: AGENT_DID_A2A_EXTENSION_URI, params: { did, keyIds } }] },
    skills: []
  };
}

async function signRequest(identity: AgentIdentity, did: string, keyId: string, signer: LocalKeySigner) {
  const headers = await identity.signHttpRequest({ ...REQUEST, agentDid: did, signer, verificationMethodId: keyId });
  return { ...REQUEST, headers };
}

describe('retireVerificationMethod', () => {
  it('retires one key and keeps the others (planned)', async () => {
    const { client, did, firstKeyId } = await setup();
    const added = await client.addVerificationMethod(did, { relationships: ['authentication', 'assertionMethod'] });
    const document = await client.retireVerificationMethod(did, firstKeyId);
    const method = document.verificationMethod.find((candidate) => candidate.id === firstKeyId)!;
    expect(method.deactivated).toBeDefined();
    expect(method.revoked).toBeUndefined();
    expect(document.assertionMethod).toEqual([added.verificationMethodId]);
    expect(document.authentication).toEqual([added.verificationMethodId]);
    expect(document['@context']).not.toContainEqual(REVOKED_CONTEXT_TERM);
    expect(agentDidDocumentProblem(document)).toBeUndefined();
  });

  it('revokes a key in an emergency and adds the inline context term', async () => {
    const { client, did, firstKeyId } = await setup();
    await client.addVerificationMethod(did, { relationships: ['authentication', 'assertionMethod'] });
    const document = await client.retireVerificationMethod(did, firstKeyId, { emergency: true });
    const method = document.verificationMethod.find((candidate) => candidate.id === firstKeyId)!;
    expect(method.revoked).toBe(method.deactivated);
    expect(document['@context'][document['@context'].length - 1]).toEqual(REVOKED_CONTEXT_TERM);
    expect(agentDidDocumentProblem(document)).toBeUndefined();
  });

  it('revokes a key that was already retired, keeping its deactivated time', async () => {
    const { client, did, firstKeyId } = await setup();
    await client.addVerificationMethod(did, { relationships: ['authentication', 'assertionMethod'] });
    const retired = await client.retireVerificationMethod(did, firstKeyId);
    const deactivated = retired.verificationMethod.find((candidate) => candidate.id === firstKeyId)!.deactivated;
    const revoked = await client.retireVerificationMethod(did, firstKeyId, { emergency: true });
    const method = revoked.verificationMethod.find((candidate) => candidate.id === firstKeyId)!;
    expect(method.deactivated).toBe(deactivated);
    expect(method.revoked).toBeDefined();
    await expect(client.retireVerificationMethod(did, firstKeyId, { emergency: true })).rejects.toThrow(/already revoked/);
  });

  it('refuses the last assertionMethod or authentication key, an unknown key and a retired key', async () => {
    const { client, did, firstKeyId } = await setup();
    await expect(client.retireVerificationMethod(did, firstKeyId)).rejects.toThrow(/last authentication key/);
    await expect(client.retireVerificationMethod(did, `${did}#key-9`)).rejects.toThrow(/not a verification method/);
    await client.addVerificationMethod(did, { relationships: ['authentication', 'assertionMethod'] });
    await client.retireVerificationMethod(did, firstKeyId);
    await expect(client.retireVerificationMethod(did, firstKeyId)).rejects.toThrow(/already retired/);
  });

  it('revokes every old key on an emergency rotation', async () => {
    const { client, did, firstKeyId } = await setup();
    const rotated = await client.rotateVerificationMethod(did, { emergency: true });
    const method = rotated.document.verificationMethod.find((candidate) => candidate.id === firstKeyId)!;
    expect(method.revoked).toBe(method.deactivated);
    expect(agentDidDocumentProblem(rotated.document)).toBeUndefined();
    const planned = await client.rotateVerificationMethod(did);
    // An earlier revocation stays, the key retired by the planned rotation is not revoked.
    const methods = planned.document.verificationMethod;
    expect(methods.find((candidate) => candidate.id === firstKeyId)!.revoked).toBeDefined();
    expect(methods.find((candidate) => candidate.id === rotated.verificationMethodId)!.revoked).toBeUndefined();
  });

  it('makes a revoked key not_authorized at any stated time, even with time evidence', async () => {
    const { client, did, firstKeyId, firstSigner } = await setup();
    const statedTime = new Date(Date.now() - 1000).toISOString();
    const signature = await firstSigner.sign(messageSigningInput('approve'));
    await client.addVerificationMethod(did, { relationships: ['authentication', 'assertionMethod'] });

    await client.retireVerificationMethod(did, firstKeyId);
    const retired = await client.verifySignatureAtTime(did, 'approve', signature, firstKeyId, {
      statedTime: new Date().toISOString()
    });
    expect(retired.status).not.toBe('valid');

    await client.retireVerificationMethod(did, firstKeyId, { emergency: true });
    const revoked = await client.verifySignatureAtTime(did, 'approve', signature, firstKeyId, {
      statedTime,
      trustedTimeNotAfter: statedTime
    });
    expect(revoked).toMatchObject({ status: 'invalid', key: { status: 'not_authorized', reason: 'key_revoked' } });
  });
});

describe('document guard: revoked', () => {
  it('rejects revoked without deactivated, a missing or a stray inline term', async () => {
    const { client, did, firstKeyId } = await setup();
    await client.addVerificationMethod(did, { relationships: ['authentication', 'assertionMethod'] });
    const document = JSON.parse(JSON.stringify(await client.retireVerificationMethod(did, firstKeyId, { emergency: true })));

    const withoutTerm = { ...document, '@context': document['@context'].slice(0, -1) };
    expect(agentDidDocumentProblem(withoutTerm)).toMatch(/must end with the inline revoked term/);

    const notRetired = JSON.parse(JSON.stringify(document));
    delete notRetired.verificationMethod[0].deactivated;
    expect(agentDidDocumentProblem(notRetired)).toMatch(/revoked requires deactivated/);

    const stray = JSON.parse(JSON.stringify(document));
    delete stray.verificationMethod[0].revoked;
    expect(agentDidDocumentProblem(stray)).toMatch(/no key is revoked/);

    const otherTerm = { ...document, '@context': [...document['@context'].slice(0, -1), { revoked: 'x' }] };
    expect(agentDidDocumentProblem(otherTerm)).toMatch(/@context\[\d+\] must be a string/);
  });
});

describe('signed Agent Cards', () => {
  it('signs as an A2A 1.0 JWS over the JCS form without signatures', async () => {
    const { did, firstKeyId, firstSigner } = await setup();
    const signed = await signAgentCard(card(did, [firstKeyId]), firstSigner, firstKeyId);
    expect(signed.signatures).toHaveLength(1);
    const header = JSON.parse(new TextDecoder().decode(base64UrlToBytes(signed.signatures![0].protected)));
    expect(header).toEqual({ alg: 'EdDSA', kid: firstKeyId, typ: 'JOSE' });
    const parsed = parseSignedAgentCard(signed)!;
    expect(parsed.did).toBe(did);
    expect(parsed.publishedKeyIds).toEqual([firstKeyId]);
  });

  it('verifies a signed card and rejects a changed one as tampered', async () => {
    const { client, did, firstKeyId, firstSigner } = await setup();
    const signed = await signAgentCard(card(did, [firstKeyId]), firstSigner, firstKeyId);
    expect(await client.verifyAgentCard(signed)).toEqual({ ok: true, did, publishedKeyIds: [firstKeyId] });
    expect(await client.verifyAgentCard({ ...signed, name: 'Other' })).toEqual({
      ok: false,
      reason: 'tampered',
      keyId: firstKeyId
    });
  });

  it('reports format_drift for unsigned cards and malformed signatures', async () => {
    const { client, did, firstKeyId, firstSigner } = await setup();
    const signed = await signAgentCard(card(did, [firstKeyId]), firstSigner, firstKeyId);
    const header = (members: Record<string, unknown>) =>
      bytesToBase64Url(new TextEncoder().encode(JSON.stringify({ alg: 'EdDSA', kid: firstKeyId, ...members })));
    const cases: unknown[] = [
      card(did, [firstKeyId]),
      [],
      { ...signed, signatures: [] },
      { ...signed, signatures: [{ ...signed.signatures![0], protected: header({ alg: 'ES256' }) }] },
      { ...signed, signatures: [{ ...signed.signatures![0], protected: header({ crit: ['b64'] }) }] },
      { ...signed, signatures: [{ ...signed.signatures![0], protected: header({ kid: did }) }] },
      { ...signed, signatures: [{ ...signed.signatures![0], signature: `${signed.signatures![0].signature}=` }] },
      { ...signed, signatures: [{ ...signed.signatures![0], extra: 1 }] },
      { ...signed, capabilities: { extensions: [{ uri: AGENT_DID_A2A_EXTENSION_URI, params: { did: 'did:webvh:x:y', keyIds: [] } }] } }
    ];
    for (const value of cases) {
      expect(await client.verifyAgentCard(value)).toEqual({ ok: false, reason: 'format_drift' });
    }
  });
});

describe('verifyIdentityComposition (contract §4.1 scenarios, §7 F1-F6)', () => {
  it('F1: accepts the current key published by the card', async () => {
    const { client, identity, did, firstKeyId, firstSigner } = await setup();
    const agentCard = await signAgentCard(card(did, [firstKeyId]), firstSigner, firstKeyId);
    const request = await signRequest(identity, did, firstKeyId, firstSigner);
    expect(await client.verifyIdentityComposition({ ...request, agentCard })).toMatchObject({ ok: true, did, keyId: firstKeyId });
  });

  it('F2: accepts the prior key during a planned overlap', async () => {
    const { client, identity, did, firstKeyId, firstSigner } = await setup();
    const newSigner = LocalKeySigner.generate()[0];
    const added = await client.addVerificationMethod(did, { signer: newSigner, relationships: ['authentication', 'assertionMethod'] });
    const agentCard = await signAgentCard(card(did, [firstKeyId, added.verificationMethodId]), newSigner, added.verificationMethodId);
    const request = await signRequest(identity, did, firstKeyId, firstSigner);
    expect(await client.verifyIdentityComposition({ ...request, agentCard })).toMatchObject({ ok: true, keyId: firstKeyId });
  });

  it('F3: rejects a key the card does not publish', async () => {
    const { client, identity, did, firstKeyId, firstSigner } = await setup();
    const newSigner = LocalKeySigner.generate()[0];
    const added = await client.addVerificationMethod(did, { signer: newSigner, relationships: ['authentication', 'assertionMethod'] });
    const agentCard = await signAgentCard(card(did, [added.verificationMethodId]), newSigner, added.verificationMethodId);
    const request = await signRequest(identity, did, firstKeyId, firstSigner);
    expect(await client.verifyIdentityComposition({ ...request, agentCard })).toEqual({
      ok: false,
      stage: 'request',
      reason: 'card_keyid_mismatch',
      keyId: firstKeyId
    });
  });

  it('F4 / F5: rejects a retired prior key as rotation_window_closed, a revoked one as emergency_revoked', async () => {
    const { client, identity, did, firstKeyId, firstSigner } = await setup();
    const newSigner = LocalKeySigner.generate()[0];
    const added = await client.addVerificationMethod(did, { signer: newSigner, relationships: ['authentication', 'assertionMethod'] });
    const agentCard = await signAgentCard(card(did, [firstKeyId, added.verificationMethodId]), newSigner, added.verificationMethodId);

    await client.retireVerificationMethod(did, firstKeyId);
    const afterRetire = await client.verifyIdentityComposition({ ...(await signRequest(identity, did, firstKeyId, firstSigner)), agentCard });
    expect(afterRetire).toMatchObject({ ok: false, stage: 'request', reason: 'rotation_window_closed', keyId: firstKeyId });

    await client.retireVerificationMethod(did, firstKeyId, { emergency: true });
    const afterRevoke = await client.verifyIdentityComposition({ ...(await signRequest(identity, did, firstKeyId, firstSigner)), agentCard });
    expect(afterRevoke).toMatchObject({ ok: false, stage: 'request', reason: 'emergency_revoked', keyId: firstKeyId });
  });

  it('F5: rejects a card signed by a revoked key', async () => {
    const { client, did, firstKeyId, firstSigner } = await setup();
    const agentCard = await signAgentCard(card(did, [firstKeyId]), firstSigner, firstKeyId);
    await client.rotateVerificationMethod(did, { emergency: true });
    expect(await client.verifyAgentCard(agentCard)).toEqual({ ok: false, reason: 'emergency_revoked', keyId: firstKeyId });
  });

  it('F6: rejects a key that is not an assertionMethod key as key_purpose_violation', async () => {
    const { client, identity, did, firstKeyId, firstSigner } = await setup();
    const invokeSigner = LocalKeySigner.generate()[0];
    const added = await client.addVerificationMethod(did, { signer: invokeSigner, relationships: ['capabilityInvocation'] });
    const agentCard = await signAgentCard(card(did, [firstKeyId, added.verificationMethodId]), firstSigner, firstKeyId);
    const request = await signRequest(identity, did, added.verificationMethodId, invokeSigner);
    expect(await client.verifyIdentityComposition({ ...request, agentCard })).toMatchObject({
      ok: false,
      stage: 'request',
      reason: 'key_purpose_violation',
      httpReason: 'keyid_not_authorized'
    });
  });

  it('reports a request from another agent DID as card_keyid_mismatch and other HTTP failures as request_rejected', async () => {
    const { client, identity, did, firstKeyId, firstSigner } = await setup();
    const agentCard = await signAgentCard(card(did, [firstKeyId]), firstSigner, firstKeyId);
    const other = await identity.create({ name: 'OtherBot', coreModel: 'test', systemPrompt: 'test' });
    const otherKeyId = other.document.assertionMethod![0];
    const foreign = await signRequest(identity, other.document.id, otherKeyId, new LocalKeySigner(other.agentPrivateKey));
    expect(await client.verifyIdentityComposition({ ...foreign, agentCard })).toEqual({
      ok: false,
      stage: 'request',
      reason: 'card_keyid_mismatch',
      keyId: otherKeyId
    });

    const request = await signRequest(identity, did, firstKeyId, firstSigner);
    expect((await client.verifyIdentityComposition({ ...request, agentCard })).ok).toBe(true);
    expect(await client.verifyIdentityComposition({ ...request, agentCard })).toEqual({
      ok: false,
      stage: 'request',
      reason: 'request_rejected',
      httpReason: 'nonce_replayed'
    });
  });

  it('checks the card first, so a bad card does not consume the nonce', async () => {
    const { client, identity, did, firstKeyId, firstSigner } = await setup();
    const agentCard = await signAgentCard(card(did, [firstKeyId]), firstSigner, firstKeyId);
    const request = await signRequest(identity, did, firstKeyId, firstSigner);
    expect(await client.verifyIdentityComposition({ ...request, agentCard: { ...agentCard, name: 'x' } })).toMatchObject({
      ok: false,
      stage: 'agent_card',
      reason: 'tampered'
    });
    expect((await client.verifyIdentityComposition({ ...request, agentCard })).ok).toBe(true);
  });
});
