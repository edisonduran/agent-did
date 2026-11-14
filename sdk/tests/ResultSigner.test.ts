import { LocalKeySigner } from '../src/core/signer';
import { AgentDidClient, AgentIdentity } from '../src';

// Parity: sdk-python/tests/test_result_signer.py
describe('the external signer of an agent key in create / rotate results', () => {
  it('is carried by the result without being serialized or spread', async () => {
    const client = new AgentDidClient();
    const identity = new AgentIdentity({ controllerSigner: LocalKeySigner.generate()[0], client });
    const [external] = LocalKeySigner.generate();
    const created = await identity.create({ name: 'KmsBot', coreModel: 'test', systemPrompt: 'test', signer: external });

    expect(created.signer).toBe(external);
    expect(created.agentPrivateKey).toBe('');
    expect(JSON.stringify(created)).not.toContain('signer');
    expect({ ...created }.signer).toBeUndefined();

    const [next] = LocalKeySigner.generate();
    const rotated = await client.rotateVerificationMethod(created.document.id, { signer: next });
    expect(rotated.signer).toBe(next);
    expect(rotated.agentPrivateKey).toBe('');

    const local = await client.rotateVerificationMethod(created.document.id);
    expect(local.signer).toBeUndefined();
    expect(local.agentPrivateKey).toHaveLength(64);
  });

  it('LocalKeySigner never serializes its private key', () => {
    const [signer, privateKeyHex] = LocalKeySigner.generate();
    expect(JSON.stringify({ signer })).toBe('{"signer":{"type":"LocalKeySigner"}}');
    expect(JSON.stringify(signer)).not.toContain(privateKeyHex);
  });
});
