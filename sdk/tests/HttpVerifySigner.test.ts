import { LocalKeySigner } from '../src/core/signer';
import { AgentDidClient, AgentIdentity, InMemoryNonceStore } from '../src';

// Parity: sdk-python/tests/test_http_verify_signer.py
async function signedRequest() {
  const client = new AgentDidClient();
  const identity = new AgentIdentity({ controllerSigner: LocalKeySigner.generate()[0], client });
  const { document, agentPrivateKey } = await identity.create({ name: 'SignerBot', coreModel: 'test', systemPrompt: 'test' });
  const request = { method: 'POST', url: 'https://api.example.com/v1/tasks?x=1', body: '{"task":1}' };
  const headers = await identity.signHttpRequest({
    ...request,
    agentDid: document.id,
    agentPrivateKey,
    verificationMethodId: `${document.id}#key-1`
  });
  return { client, document, request: { ...request, headers } };
}

describe('verifyHttpRequestSignatureDetailed: who signed and whom to accept', () => {
  it('returns the signer DID, the key and the controller chain', async () => {
    const { client, document, request } = await signedRequest();

    const result = await client.verifyHttpRequestSignatureDetailed({ ...request, nonceStore: new InMemoryNonceStore() });

    expect(result).toEqual({
      ok: true,
      did: document.id,
      keyId: `${document.id}#key-1`,
      controllers: [document.controller]
    });
  });

  it('rejects a DID outside allowedDids before resolving it', async () => {
    const { client, document, request } = await signedRequest();
    const resolve = jest.spyOn(client, 'resolve');

    const refused = await client.verifyHttpRequestSignatureDetailed({
      ...request,
      allowedDids: ['did:webvh:QmOther:example.com:agents:other'],
      nonceStore: new InMemoryNonceStore()
    });
    expect(refused).toEqual({ ok: false, reason: 'did_not_allowed' });
    expect(resolve).not.toHaveBeenCalled();

    const accepted = await client.verifyHttpRequestSignatureDetailed({
      ...request,
      allowedDids: [document.id],
      nonceStore: new InMemoryNonceStore()
    });
    expect(accepted.ok).toBe(true);
  });

  it('accepts only agents whose controller chain includes an allowed controller, without burning the nonce', async () => {
    const { client, document, request } = await signedRequest();
    const nonceStore = new InMemoryNonceStore();

    const refused = await client.verifyHttpRequestSignatureDetailed({
      ...request,
      allowedControllers: ['did:webvh:QmOther:example.com:organizations:other'],
      nonceStore
    });
    expect(refused).toEqual({ ok: false, reason: 'controller_not_allowed' });

    const accepted = await client.verifyHttpRequestSignatureDetailed({
      ...request,
      allowedControllers: [document.controller as string],
      nonceStore
    });
    expect(accepted.ok).toBe(true);
  });

  it('applies both lists when both are set', async () => {
    const { client, document, request } = await signedRequest();

    const result = await client.verifyHttpRequestSignatureDetailed({
      ...request,
      allowedDids: [document.id],
      allowedControllers: ['did:webvh:QmOther:example.com:organizations:other'],
      nonceStore: new InMemoryNonceStore()
    });

    expect(result).toEqual({ ok: false, reason: 'controller_not_allowed' });
  });
});
