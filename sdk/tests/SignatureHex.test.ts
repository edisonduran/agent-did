import { LocalKeySigner } from '../src/core/signer';
import { AgentDidClient, AgentIdentity } from '../src';
import { decodeSignatureHex } from '../src/crypto/ed25519-verify';

// Parity: sdk-python/tests/test_signature_hex.py
describe('payload signatures written as hex', () => {
  it('accept exactly 128 hex digits, in either case, and nothing else', async () => {
    const client = new AgentDidClient();
    const identity = new AgentIdentity({ controllerSigner: LocalKeySigner.generate()[0], client });
    const { document, agentPrivateKey } = await identity.create({ name: 'HexBot', coreModel: 'test', systemPrompt: 'test' });
    const signature = await identity.signMessage('hello', agentPrivateKey);
    const keyId = `${document.id}#key-1`;

    expect(await client.verifySignature(document.id, 'hello', signature, keyId)).toBe(true);
    expect(await client.verifySignature(document.id, 'hello', signature.toUpperCase(), keyId)).toBe(true);
    for (const variant of [signature.replace(/(..)/gu, '$1 ').trim(), `0x${signature}`, ` ${signature}`, `${signature}\n`, signature.slice(2)]) {
      expect(await client.verifySignature(document.id, 'hello', variant, keyId)).toBe(false);
    }
  });

  it('decodes only the strict form', () => {
    expect(decodeSignatureHex('ab'.repeat(64))).toHaveLength(64);
    expect(() => decodeSignatureHex('ab '.repeat(64))).toThrow(TypeError);
    expect(() => decodeSignatureHex('ab'.repeat(63))).toThrow(TypeError);
  });
});
