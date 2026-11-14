import { ed25519 } from '@noble/curves/ed25519';
import { hexToBytes } from '@noble/hashes/utils';
import { LocalKeySigner } from '../src/core/signer';
import { AgentDidClient, AgentIdentity } from '../src';
import { decodePublicKeyMultibase } from '../src/crypto/multibase';

// Parity: sdk-python/tests/test_concurrent_lifecycle.py
async function createAgent() {
  const client = new AgentDidClient();
  const identity = new AgentIdentity({ controllerSigner: LocalKeySigner.generate()[0], client });
  const { document } = await identity.create({ name: 'RaceBot', coreModel: 'test', systemPrompt: 'test' });
  return { client, did: document.id };
}

const entries = (log: string) => log.split('\n').filter((line) => line.trim()).length;

describe('concurrent lifecycle operations on one DID', () => {
  it('keeps every concurrent update in the log', async () => {
    const { client, did } = await createAgent();

    await Promise.all([
      client.updateDidDocument(did, { description: 'first' }),
      client.updateDidDocument(did, { description: 'second' })
    ]);

    expect(entries(client.exportDidWebvhHistory(did))).toBe(3);
    expect(client.getDocumentHistory(did)).toHaveLength(3);
  });

  it('returns a rotated key that is in the resolved document when an update races the rotation', async () => {
    const { client, did } = await createAgent();

    const [rotated] = await Promise.all([
      client.rotateVerificationMethod(did),
      client.updateDidDocument(did, { description: 'racing' })
    ]);

    const document = await client.resolve(did);
    const method = document.verificationMethod.find((vm) => vm.id === rotated.verificationMethodId);
    expect(method).toBeDefined();
    expect(decodePublicKeyMultibase(method?.publicKeyMultibase as string)).toEqual(
      ed25519.getPublicKey(hexToBytes(rotated.agentPrivateKey))
    );
    expect(entries(client.exportDidWebvhHistory(did))).toBe(3);
  });
});
