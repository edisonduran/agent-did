import { LocalKeySigner } from '../src/core/signer';
import {
  createDidWebvhLog,
  deactivateDidWebvhLog,
  DID_WEBVH_PLACEHOLDER,
  didWebvhUpdateKeyFor,
  DidWebvhError,
  resolveDidWebvhLog,
  updateDidWebvhLog,
} from '../src/webvh/adapter';

// Four controller keys: K0 is active at creation, K1..K3 are committed in advance (pre-rotation).
const K0 = new LocalKeySigner('1'.repeat(64));
const K1 = new LocalKeySigner('2'.repeat(64));
const K2 = new LocalKeySigner('3'.repeat(64));
const K3 = new LocalKeySigner('4'.repeat(64));
const AGENT_PUBLIC_KEY = 'z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK';

const key = (signer: LocalKeySigner) => didWebvhUpdateKeyFor(signer);

function agentDocument(description?: string): Record<string, unknown> {
  return {
    '@context': ['https://www.w3.org/ns/did/v1', 'https://agent-did.org/v1'],
    id: DID_WEBVH_PLACEHOLDER,
    controller: 'did:webvh:controller.example.com',
    verificationMethod: [
      {
        id: `${DID_WEBVH_PLACEHOLDER}#key-1`,
        type: 'Multikey',
        controller: DID_WEBVH_PLACEHOLDER,
        publicKeyMultibase: AGENT_PUBLIC_KEY,
      },
    ],
    assertionMethod: [`${DID_WEBVH_PLACEHOLDER}#key-1`],
    agentMetadata: { name: 'pre-rotation-test', version: '1.0.0', ...(description ? { description } : {}) },
  };
}

async function createCommitted(next: LocalKeySigner[] = [K1]) {
  return createDidWebvhLog({
    domain: 'agents.example.com',
    pathSegments: ['fleet', 'agent-1'],
    document: agentDocument(),
    signer: K0,
    nextUpdateKeys: await Promise.all(next.map(key)),
    created: '2026-01-01T00:00:00Z',
  });
}

async function expectCode(promise: Promise<unknown>, code: string): Promise<void> {
  await expect(promise).rejects.toMatchObject({ name: 'DidWebvhError', code });
}

describe('did:webvh pre-rotation (nextKeyHashes)', () => {
  it('writes only the hash of the next key and exposes it in the metadata', async () => {
    const created = await createCommitted();
    expect(created.metadata.nextKeyHashes).toHaveLength(1);
    expect(created.metadata.nextKeyHashes[0]).toMatch(/^Qm/u);
    expect(created.log).not.toContain(await key(K1));
    expect(created.metadata.updateKeys).toEqual([await key(K0)]);
  });

  it('has no commitments unless asked', async () => {
    const created = await createDidWebvhLog({
      domain: 'agents.example.com',
      document: agentDocument(),
      signer: K0,
    });
    expect(created.metadata.nextKeyHashes).toEqual([]);
  });

  it('lets only a committed key sign the next entry, and the active key can no longer sign', async () => {
    const created = await createCommitted();

    await expectCode(updateDidWebvhLog({ log: created.log, signer: K0, document: undefined }), 'unauthorized');
    await expectCode(updateDidWebvhLog({ log: created.log, signer: K2 }), 'unauthorized');

    const rotated = await updateDidWebvhLog({ log: created.log, signer: K1 });
    expect(rotated.metadata.updateKeys).toEqual([await key(K1)]);
    expect(rotated.metadata.versionNumber).toBe(2);
  });

  it('keeps the commitment when the entry does not change it, and commits to the next key when asked', async () => {
    const created = await createCommitted();
    const kept = await updateDidWebvhLog({ log: created.log, signer: K1 });
    expect(kept.metadata.nextKeyHashes).toEqual(created.metadata.nextKeyHashes);

    const chained = await updateDidWebvhLog({ log: kept.log, signer: K1, nextUpdateKeys: [await key(K2)] });
    expect(chained.metadata.nextKeyHashes).toHaveLength(1);
    expect(chained.metadata.nextKeyHashes).not.toEqual(created.metadata.nextKeyHashes);

    // K1 is the active key but no longer committed: K2 must sign now.
    await expectCode(updateDidWebvhLog({ log: chained.log, signer: K1 }), 'unauthorized');
    const next = await updateDidWebvhLog({ log: chained.log, signer: K2, nextUpdateKeys: [await key(K3)] });
    expect(next.metadata.updateKeys).toEqual([await key(K2)]);
    expect((await resolveDidWebvhLog(next.log)).metadata.versionNumber).toBe(4);
  });

  it('ends pre-rotation with an empty commitment, and the signing key is then an ordinary update key', async () => {
    const created = await createCommitted();
    const ended = await updateDidWebvhLog({ log: created.log, signer: K1, nextUpdateKeys: [] });
    expect(ended.metadata.nextKeyHashes).toEqual([]);
    const ordinary = await updateDidWebvhLog({ log: ended.log, signer: K1, document: agentDocumentFor(ended.did) });
    expect(ordinary.metadata.versionNumber).toBe(3);
    await expectCode(updateDidWebvhLog({ log: ended.log, signer: K0 }), 'unauthorized');
  });

  it('can start pre-rotation on a log that had none, signed by the active key', async () => {
    const plain = await createDidWebvhLog({ domain: 'agents.example.com', document: agentDocument(), signer: K0 });
    const started = await updateDidWebvhLog({ log: plain.log, signer: K0, nextUpdateKeys: [await key(K1)] });
    expect(started.metadata.nextKeyHashes).toHaveLength(1);
    await expectCode(updateDidWebvhLog({ log: started.log, signer: K0 }), 'unauthorized');
    await expect(updateDidWebvhLog({ log: started.log, signer: K1 })).resolves.toBeDefined();
  });

  it('refuses commitments to keys that are not new, malformed, or repeated', async () => {
    await expectCode(
      createDidWebvhLog({ domain: 'agents.example.com', document: agentDocument(), signer: K0, nextUpdateKeys: [await key(K0)] }),
      'invalidInput'
    );
    await expectCode(
      createDidWebvhLog({ domain: 'agents.example.com', document: agentDocument(), signer: K0, nextUpdateKeys: ['z6Mk-not-a-key'] }),
      'invalidInput'
    );
    await expectCode(
      createDidWebvhLog({
        domain: 'agents.example.com', document: agentDocument(), signer: K0, nextUpdateKeys: [await key(K1), await key(K1)]
      }),
      'invalidInput'
    );
    const created = await createCommitted();
    // Committing to the key that signs this very entry would make the commitment useless.
    await expectCode(
      updateDidWebvhLog({ log: created.log, signer: K1, nextUpdateKeys: [await key(K1)] }),
      'invalidInput'
    );
  });

  it('refuses updateKeys that were not committed, even when the signer was', async () => {
    const created = await createCommitted();
    await expectCode(
      updateDidWebvhLog({ log: created.log, signer: K1, updateKeys: [await key(K1), await key(K2)] }),
      'unauthorized'
    );
    await expectCode(updateDidWebvhLog({ log: created.log, signer: K1, updateKeys: [await key(K2)] }), 'invalidInput');
  });

  it('deactivates only with a committed key while pre-rotation is active', async () => {
    const created = await createCommitted();
    await expectCode(deactivateDidWebvhLog({ log: created.log, signer: K0 }), 'unauthorized');
    const deactivated = await deactivateDidWebvhLog({ log: created.log, signer: K1 });
    expect(deactivated.metadata.deactivated).toBe(true);
    expect(deactivated.metadata.nextKeyHashes).toEqual([]);
    expect((await resolveDidWebvhLog(deactivated.log)).metadata.deactivated).toBe(true);
  });

  it('refuses to sign with the active key once it has committed to a successor', async () => {
    const plain = await createDidWebvhLog({ domain: 'agents.example.com', document: agentDocument(), signer: K0 });
    const committed = await updateDidWebvhLog({ log: plain.log, signer: K0, nextUpdateKeys: [await key(K1)] });
    await expectCode(
      updateDidWebvhLog({ log: committed.log, signer: K0, document: agentDocumentFor(plain.did, 'forged') }),
      'unauthorized'
    );
  });

  it('rejects, on resolution, a pre-rotated entry whose updateKeys were swapped for the old key', async () => {
    const created = await createCommitted();
    const rotated = await updateDidWebvhLog({ log: created.log, signer: K1 });
    const lines = rotated.log.trimEnd().split('\n');
    const last = JSON.parse(lines[lines.length - 1]);
    last.parameters.updateKeys = [await key(K0)];
    lines[lines.length - 1] = JSON.stringify(last);
    await expectCode(resolveDidWebvhLog(lines.join('\n') + '\n'), 'invalidDid');
  });

  it('exposes DidWebvhError for callers', () => {
    expect(new DidWebvhError('unauthorized', 'x')).toBeInstanceOf(Error);
  });
});

function agentDocumentFor(did: string, description?: string): Record<string, unknown> {
  const template = JSON.stringify(agentDocument(description)).split(DID_WEBVH_PLACEHOLDER).join(did);
  return JSON.parse(template) as Record<string, unknown>;
}
