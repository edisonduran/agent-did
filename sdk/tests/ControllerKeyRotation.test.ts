import { AgentDidClient } from '../src/core/AgentDidClient';
import { AgentIdentity } from '../src/core/AgentIdentity';
import { LocalKeySigner } from '../src/core/signer';
import { didWebvhUpdateKeyFor } from '../src/webvh/adapter';

// The controller key K0 is compromised; K1, K2 and K3 were committed in advance and kept offline.
const K0 = new LocalKeySigner('1'.repeat(64));
const K1 = new LocalKeySigner('2'.repeat(64));
const K2 = new LocalKeySigner('3'.repeat(64));
const K3 = new LocalKeySigner('4'.repeat(64));
const key = (signer: LocalKeySigner) => didWebvhUpdateKeyFor(signer);

async function createAgent(nextUpdateKeys?: string[]) {
  const client = new AgentDidClient();
  const identity = new AgentIdentity({ client, controllerSigner: K0 });
  const created = await identity.create({
    name: 'RecoverableBot',
    coreModel: 'test-model',
    systemPrompt: 'test prompt',
    didMethod: 'webvh',
    webvh: {
      domain: 'agents.example',
      pathSegments: ['agents', 'recoverable-bot'],
      controllerDid: '{DID}',
      controllerSigner: K0,
      ...(nextUpdateKeys ? { nextUpdateKeys } : {})
    }
  });
  return { client, did: created.document.id };
}

describe('controller key recovery with did:webvh pre-rotation', () => {
  it('commits to the next keys at creation and exposes the commitments', async () => {
    const { client, did } = await createAgent([await key(K1)]);
    const keys = await client.getDidWebvhControllerKeys(did);
    expect(keys.updateKeys).toEqual([await key(K0)]);
    expect(keys.nextKeyHashes).toHaveLength(1);
    expect(client.exportDidWebvhHistory(did)).not.toContain(await key(K1));
  });

  it('keeps the previous behavior without commitments', async () => {
    const { client, did } = await createAgent();
    expect((await client.getDidWebvhControllerKeys(did)).nextKeyHashes).toEqual([]);
    await client.updateDidDocument(did, { description: 'still works with the controller key' });
  });

  it('a compromised controller key cannot change or revoke the DID, the committed key can', async () => {
    const { client, did } = await createAgent([await key(K1)]);

    // The attacker holds K0: every operation signed by it is refused.
    await expect(client.updateDidDocument(did, { description: 'taken over' }, { controllerSigner: K0 })).rejects.toMatchObject({
      code: 'unauthorized'
    });
    await expect(client.revokeDid(did, { controllerSigner: K0 })).rejects.toMatchObject({ code: 'unauthorized' });
    await expect(
      client.rotateControllerKey(did, { newControllerSigner: K0, controllerSigner: K0 })
    ).rejects.toMatchObject({ code: 'unauthorized' });

    // The owner recovers with the committed key and commits to the next one.
    const rotated = await client.rotateControllerKey(did, { newControllerSigner: K1, nextUpdateKeys: [await key(K2)] });
    expect(rotated.updateKeys).toEqual([await key(K1)]);
    expect(rotated.nextKeyHashes).toHaveLength(1);

    // K0 is still refused; K1 is active but must not be reused, K2 is the next committed key.
    await expect(client.updateDidDocument(did, { description: 'taken over' }, { controllerSigner: K0 })).rejects.toMatchObject({
      code: 'unauthorized'
    });
    await expect(client.updateDidDocument(did, { description: 'with K1' }, { controllerSigner: K1 })).rejects.toMatchObject({
      code: 'unauthorized'
    });
    await client.updateDidDocument(did, { description: 'recovered' }, { controllerSigner: K2 });
    expect((await client.resolve(did)).agentMetadata.description).toBe('recovered');
    expect((await client.getDidWebvhControllerKeys(did)).updateKeys).toEqual([await key(K2)]);
  });

  it('retains the new controller signer, so later operations need no explicit signer', async () => {
    const { client, did } = await createAgent([await key(K1)]);
    await client.rotateControllerKey(did, { newControllerSigner: K1, nextUpdateKeys: [] });
    await client.updateDidDocument(did, { description: 'signed by the retained K1' });
    await client.revokeDid(did);
    await expect(client.resolve(did)).rejects.toThrow(/revoked/u);
  });

  it('starts pre-rotation on a DID that had none, signed by the active key', async () => {
    const { client, did } = await createAgent();
    // Rotating to the active key itself is allowed; committing to K1 starts pre-rotation.
    const started = await client.rotateControllerKey(did, { newControllerSigner: K0, nextUpdateKeys: [await key(K1)] });
    expect(started.nextKeyHashes).toHaveLength(1);
    await expect(client.updateDidDocument(did, { description: 'x' }, { controllerSigner: K0 })).rejects.toMatchObject({
      code: 'unauthorized'
    });
    await client.rotateControllerKey(did, { newControllerSigner: K1, nextUpdateKeys: [await key(K3)] });
    expect((await client.getDidWebvhControllerKeys(did)).updateKeys).toEqual([await key(K1)]);
  });

  it('rejects non-webvh DIDs and DIDs with no log in this process', async () => {
    const client = new AgentDidClient();
    await expect(client.rotateControllerKey('did:agent:polygon:0xabc', { newControllerSigner: K1 })).rejects.toThrow(
      /did:webvh/u
    );
    await expect(client.rotateControllerKey('did:webvh:QmX:agents.example', { newControllerSigner: K1 })).rejects.toThrow(
      /No did:webvh log/u
    );
    await expect(client.getDidWebvhControllerKeys('did:webvh:QmX:agents.example')).rejects.toThrow(/No did:webvh log/u);
  });
});
