/**
 * Controller binding (RFC-001 §6.6 item 7): an agent whose document names a controller is bound to it only if the proof of
 * the last entry of its did:webvh log was made by a key that is active now under the controller's `capabilityInvocation`.
 * The Python SDK runs the same cases in sdk-python/tests/test_controller_binding.py.
 */
import { AgentDidClient, AgentIdentity, ControllerBindingError, LocalKeySigner } from '../src';
import { CreateAgentParams } from '../src/core/types';
import { InMemoryDIDResolver } from '../src/resolver/InMemoryDIDResolver';

const base: CreateAgentParams = { name: 'BoundBot', coreModel: 'gpt-4o-mini', systemPrompt: 'You are a test assistant.' };

/** A party with its own client: it creates a bootstrap controller and agents under it. */
async function legitParty() {
  const client = new AgentDidClient();
  const [wallet] = LocalKeySigner.generate();
  const identity = new AgentIdentity({ controllerSigner: wallet, client });
  const created = await identity.create(base);
  const controllerDid = created.document.controller;
  return {
    client,
    identity,
    created,
    controllerDid,
    controllerSigner: new LocalKeySigner(created.controllerPrivateKey as string)
  };
}

/** A verifier that imports the logs it is given, like a service that fetched them. */
async function verifierWith(logs: string[]): Promise<AgentDidClient> {
  const verifier = new AgentDidClient();
  for (const log of logs) {
    await verifier.importDidWebvhHistory(log);
  }
  return verifier;
}

describe('controller binding', () => {
  it('verifies an agent created under its own bootstrap controller, in the creating client and in a verifier', async () => {
    const { client, identity, created, controllerDid } = await legitParty();
    const signature = await identity.signMessage('approve', created.agentPrivateKey);

    expect(await client.verifySignature(created.document.id, 'approve', signature)).toBe(true);

    const verifier = await verifierWith([
      client.exportDidWebvhHistory(controllerDid),
      client.exportDidWebvhHistory(created.document.id)
    ]);
    expect(await verifier.verifySignature(created.document.id, 'approve', signature)).toBe(true);
  });

  it('rejects an agent that names a controller it has no key in', async () => {
    const acme = await legitParty();
    const mallory = new AgentDidClient();
    const [malloryWallet] = LocalKeySigner.generate();
    const [malloryKey] = LocalKeySigner.generate();
    const malloryIdentity = new AgentIdentity({ controllerSigner: malloryWallet, client: mallory });

    const forged = await malloryIdentity.create({
      ...base,
      name: 'ForgedBot',
      webvh: { domain: 'mallory.example', controllerDid: acme.controllerDid, controllerSigner: malloryKey }
    });
    const signature = await malloryIdentity.signMessage('approve', forged.agentPrivateKey);
    expect(forged.document.controller).toBe(acme.controllerDid);

    const verifier = await verifierWith([
      acme.client.exportDidWebvhHistory(acme.controllerDid),
      mallory.exportDidWebvhHistory(forged.document.id)
    ]);
    expect(await verifier.verifySignature(forged.document.id, 'approve', signature)).toBe(false);
    await expect(verifier.resolveControllerChain(forged.document.id)).resolves.toHaveLength(2);
  });

  it('reports controller_not_bound for an HTTP request signed by such an agent', async () => {
    const acme = await legitParty();
    const mallory = new AgentDidClient();
    const [malloryWallet] = LocalKeySigner.generate();
    const [malloryKey] = LocalKeySigner.generate();
    const malloryIdentity = new AgentIdentity({ controllerSigner: malloryWallet, client: mallory });
    const forged = await malloryIdentity.create({
      ...base,
      name: 'ForgedHttpBot',
      webvh: { domain: 'mallory.example', controllerDid: acme.controllerDid, controllerSigner: malloryKey }
    });
    const url = 'https://api.example.com/v1/orders';
    const headers = await malloryIdentity.signHttpRequest({
      method: 'POST',
      url,
      body: '{}',
      agentPrivateKey: forged.agentPrivateKey,
      agentDid: forged.document.id,
      verificationMethodId: forged.document.authentication[0]
    });

    const verifier = await verifierWith([
      acme.client.exportDidWebvhHistory(acme.controllerDid),
      mallory.exportDidWebvhHistory(forged.document.id)
    ]);
    const result = await verifier.verifyHttpRequestSignatureDetailed({ method: 'POST', url, body: '{}', headers });
    expect(result).toEqual({ ok: false, reason: 'controller_not_bound' });
  });

  it('verifies an agent under an explicit controller whose document lists the signing key', async () => {
    const acme = await legitParty();
    const agentOwner = new AgentDidClient();
    const [wallet] = LocalKeySigner.generate();
    const identity = new AgentIdentity({ controllerSigner: wallet, client: agentOwner });
    const agent = await identity.create({
      ...base,
      name: 'SanctionedBot',
      webvh: { domain: 'acme.example', controllerDid: acme.controllerDid, controllerSigner: acme.controllerSigner }
    });
    const signature = await identity.signMessage('approve', agent.agentPrivateKey);

    const verifier = await verifierWith([
      acme.client.exportDidWebvhHistory(acme.controllerDid),
      agentOwner.exportDidWebvhHistory(agent.document.id)
    ]);
    expect(await verifier.verifySignature(agent.document.id, 'approve', signature)).toBe(true);
  });

  it('does not accept a controller that is not resolvable, or an agent whose log is not available', async () => {
    const { client, identity, created, controllerDid } = await legitParty();
    const signature = await identity.signMessage('approve', created.agentPrivateKey);
    const agentLog = client.exportDidWebvhHistory(created.document.id);

    // The verifier does not have the controller's log
    expect(await (await verifierWith([agentLog])).verifySignature(created.document.id, 'approve', signature)).toBe(false);

    // A resolver that holds only documents cannot prove the binding either
    const resolver = new InMemoryDIDResolver();
    resolver.registerDocument(await client.resolve(created.document.id));
    resolver.registerDocument(await client.resolve(controllerDid));
    const documentOnly = new AgentDidClient({ resolver });
    expect(await documentOnly.verifySignature(created.document.id, 'approve', signature)).toBe(false);
  });

  it('unbinds the agents when the controller retires its key before they are re-signed', async () => {
    const { client, identity, created, controllerDid } = await legitParty();
    const signature = await identity.signMessage('approve', created.agentPrivateKey);
    expect(await client.verifySignature(created.document.id, 'approve', signature)).toBe(true);

    await client.rotateVerificationMethod(controllerDid);

    expect(await client.verifySignature(created.document.id, 'approve', signature)).toBe(false);
    await expect(client.resolveDidWebvhState(created.document.id)).resolves.toMatchObject({ provenance: 'local' });
  });

  it('rotates the controller key without a gap: add the new key, re-sign the agents, retire the old key', async () => {
    const { client, identity, created, controllerDid } = await legitParty();
    const signature = await identity.signMessage('approve', created.agentPrivateKey);
    const [newKey] = LocalKeySigner.generate();

    // 1. the controller adds the new key; the old one still endorses
    const added = await client.addVerificationMethod(controllerDid, { signer: newKey });
    expect(added.agentPrivateKey).toBe('');
    expect(added.document.capabilityInvocation).toHaveLength(2);
    expect(await client.verifySignature(created.document.id, 'approve', signature)).toBe(true);

    // 2. the agent gets an entry signed by the new key
    await client.rotateControllerKey(created.document.id, { newControllerSigner: newKey });
    await client.updateDidDocument(created.document.id, { description: 'endorsed by the new key' }, { controllerSigner: newKey });
    expect(await client.verifySignature(created.document.id, 'approve', signature)).toBe(true);

    // 3. the controller retires the old key (rotation that keeps the new key as the active one)
    await client.rotateVerificationMethod(controllerDid, { signer: newKey });
    expect(await client.verifySignature(created.document.id, 'approve', signature)).toBe(true);
  });

  it('applies the binding to a result that would be valid at a stated time', async () => {
    const acme = await legitParty();
    const mallory = new AgentDidClient();
    const [malloryWallet] = LocalKeySigner.generate();
    const [malloryKey] = LocalKeySigner.generate();
    const malloryIdentity = new AgentIdentity({ controllerSigner: malloryWallet, client: mallory });
    const forged = await malloryIdentity.create({
      ...base,
      name: 'ForgedTimedBot',
      webvh: { domain: 'mallory.example', controllerDid: acme.controllerDid, controllerSigner: malloryKey }
    });
    const signature = await malloryIdentity.signMessage('approve', forged.agentPrivateKey);
    const verifier = await verifierWith([
      acme.client.exportDidWebvhHistory(acme.controllerDid),
      mallory.exportDidWebvhHistory(forged.document.id)
    ]);

    const result = await verifier.verifySignatureAtTime(
      forged.document.id,
      'approve',
      signature,
      forged.document.authentication[0],
      { statedTime: new Date().toISOString().replace(/\.\d+Z$/u, 'Z') }
    );
    expect(result).toMatchObject({ status: 'invalid', reason: 'controller_not_bound' });
  });

  it('describes the log behind a DID: signers of the last entry, update keys and provenance', async () => {
    const { client, created, controllerDid } = await legitParty();
    const state = await client.resolveDidWebvhState(created.document.id);

    expect(state?.provenance).toBe('local');
    expect(state?.document.id).toBe(created.document.id);
    expect(state?.lastEntrySignerKeys).toHaveLength(1);
    expect(state?.updateKeys).toEqual(state?.lastEntrySignerKeys);
    const controllerState = await client.resolveDidWebvhState(controllerDid);
    expect(controllerState?.lastEntrySignerKeys).toEqual(state?.lastEntrySignerKeys);

    const verifier = await verifierWith([client.exportDidWebvhHistory(created.document.id)]);
    expect((await verifier.resolveDidWebvhState(created.document.id))?.provenance).toBe('imported');
    expect(await client.resolveDidWebvhState('did:example:123')).toBeUndefined();
  });

  it('exports ControllerBindingError', () => {
    expect(new ControllerBindingError('did:a', 'did:b', 'x').message).toContain('not bound');
  });
});
