import { LocalKeySigner } from '../src/core/signer';
/**
 * Cross-checks the Agent-DID RFC 9421 profile against an independent
 * implementation (`http-message-signatures`, dev dependency).
 */
import crypto from 'crypto';
import { httpbis, createSigner, createVerifier } from 'http-message-signatures';
import { AgentIdentity, AGENT_DID_HTTP_SIGNATURE_COMPONENTS } from '../src/core/AgentIdentity';
import { decodePublicKeyMultibase } from '../src/crypto/multibase';
import { InMemoryAgentRegistry } from '../src/registry/InMemoryAgentRegistry';
import { InMemoryDIDResolver } from '../src/resolver/InMemoryDIDResolver';
import { InMemoryNonceStore } from '../src/core/nonce-store';

const PKCS8_ED25519_PREFIX = Buffer.from('302e020100300506032b657004220420', 'hex');
const SPKI_ED25519_PREFIX = Buffer.from('302a300506032b6570032100', 'hex');

function privateKeyObject(hex: string): crypto.KeyObject {
  return crypto.createPrivateKey({ key: Buffer.concat([PKCS8_ED25519_PREFIX, Buffer.from(hex, 'hex')]), format: 'der', type: 'pkcs8' });
}

function publicKeyObject(raw: Uint8Array): crypto.KeyObject {
  return crypto.createPublicKey({ key: Buffer.concat([SPKI_ED25519_PREFIX, Buffer.from(raw)]), format: 'der', type: 'spki' });
}

describe('RFC 9421 interoperability with http-message-signatures', () => {
  const identity = new AgentIdentity({ controllerSigner: LocalKeySigner.generate()[0] });
  const request = { method: 'POST', url: 'https://api.example.com/v1/orders?id=42', body: '{"qty":1}' };

  beforeEach(() => {
    AgentIdentity.setResolver(new InMemoryDIDResolver());
    AgentIdentity.setRegistry(new InMemoryAgentRegistry());
  });

  it('signatures produced by the SDK verify with the independent implementation', async () => {
    const { document, agentPrivateKey } = await identity.create({ name: 'InteropOut', coreModel: 'm', systemPrompt: 'p' });
    const headers = await identity.signHttpRequest({ ...request, agentPrivateKey, agentDid: document.id, verificationMethodId: `${document.id}#key-1` });
    const publicKey = publicKeyObject(decodePublicKeyMultibase(document.verificationMethod[0].publicKeyMultibase!));

    const verified = await httpbis.verifyMessage(
      {
        keyLookup: async (params) =>
          params.keyid === `${document.id}#key-1` ? { id: params.keyid as string, algs: ['ed25519'], verify: createVerifier(publicKey, 'ed25519') } : null,
        requiredFields: [...AGENT_DID_HTTP_SIGNATURE_COMPONENTS],
        requiredParams: ['created', 'expires', 'nonce', 'keyid', 'alg', 'tag'],
      },
      { method: request.method, url: request.url, headers }
    );
    expect(verified).toBe(true);
  });

  it('signatures produced by the independent implementation verify with the SDK', async () => {
    const { document, agentPrivateKey } = await identity.create({ name: 'InteropIn', coreModel: 'm', systemPrompt: 'p' });
    const keyid = `${document.id}#key-1`;
    const created = new Date(Math.floor(Date.now() / 1000) * 1000);
    const headers: Record<string, string> = {
      'Signature-Agent': document.id,
      'Date': created.toUTCString(),
      'Content-Digest': `sha-256=:${crypto.createHash('sha256').update(request.body).digest('base64')}:`,
    };

    const signed = await httpbis.signMessage(
      {
        key: createSigner(privateKeyObject(agentPrivateKey), 'ed25519', keyid),
        name: 'sig1',
        fields: [...AGENT_DID_HTTP_SIGNATURE_COMPONENTS],
        params: ['created', 'expires', 'nonce', 'keyid', 'alg', 'tag'],
        paramValues: { created, expires: new Date(created.getTime() + 30_000), nonce: crypto.randomBytes(16).toString('hex'), tag: 'agent-did' },
      },
      { method: request.method, url: request.url, headers }
    );

    const signedHeaders = Object.fromEntries(
      Object.entries(signed.headers).map(([name, value]) => [name, Array.isArray(value) ? value.join(', ') : value])
    );
    await expect(
      AgentIdentity.verifyHttpRequestSignature({ ...request, headers: signedHeaders, nonceStore: new InMemoryNonceStore() })
    ).resolves.toBe(true);
    await expect(
      AgentIdentity.verifyHttpRequestSignature({ ...request, body: '{"qty":9}', headers: signedHeaders, nonceStore: new InMemoryNonceStore() })
    ).resolves.toBe(false);
  });
});
