/**
 * Payload signatures (`signMessage`) cover a domain prefix (RFC-001 §7), so they are never valid as the
 * RFC 9421 signature of an HTTP request made with the same key. The Python SDK runs the same cases in
 * sdk-python/tests/test_message_signing_domain.py.
 */
import { ed25519 } from '@noble/curves/ed25519';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils';
import {
  AGENT_DID_MESSAGE_SIGNING_PREFIX,
  AgentDidClient,
  AgentIdentity,
  LocalKeySigner,
  messageSigningInput
} from '../src';
import {
  AGENT_DID_HTTP_SIGNATURE_COMPONENTS,
  AGENT_DID_HTTP_SIGNATURE_TAG
} from '../src/core/AgentIdentity';
import { buildSignatureBase, serializeSignatureInput } from '../src/core/http-signatures';

function setup() {
  const client = new AgentDidClient();
  const [controllerSigner] = LocalKeySigner.generate();
  return { client, identity: new AgentIdentity({ controllerSigner, client }) };
}

const params = { name: 'DomainBot', coreModel: 'gpt-4o-mini', systemPrompt: 'You are a test assistant.' };

describe('payload signature domain separation', () => {
  it('signs the domain prefix followed by the payload', async () => {
    const { identity } = setup();
    const { agentPrivateKey } = await identity.create(params);
    const signature = await identity.signMessage('hello', agentPrivateKey);

    expect(AGENT_DID_MESSAGE_SIGNING_PREFIX).toBe('agent-did/v1/message\n');
    const privateKey = hexToBytes(agentPrivateKey);
    expect(bytesToHex(ed25519.sign(messageSigningInput('hello'), privateKey))).toBe(signature);
    expect(bytesToHex(ed25519.sign(new TextEncoder().encode('hello'), privateKey))).not.toBe(signature);
  });

  it('verifies payload signatures and rejects a raw signature over the same payload', async () => {
    const { client, identity } = setup();
    const { document, agentPrivateKey } = await identity.create(params);
    const signature = await identity.signMessage('approve', agentPrivateKey);
    const raw = bytesToHex(ed25519.sign(new TextEncoder().encode('approve'), hexToBytes(agentPrivateKey)));

    expect(await client.verifySignature(document.id, 'approve', signature)).toBe(true);
    expect(await client.verifySignature(document.id, 'approve', raw)).toBe(false);
  });

  it('does not let a payload signature stand in for the signature of an HTTP request', async () => {
    const { client, identity } = setup();
    const { document, agentPrivateKey } = await identity.create(params);
    const keyId = document.authentication[0];
    const url = 'https://api.example.com/v1/transfer';
    const body = '{"amount":1}';
    const signed = await identity.signHttpRequest({
      method: 'POST',
      url,
      body,
      agentPrivateKey,
      agentDid: document.id,
      verificationMethodId: keyId
    });

    // Rebuild the signature base of a request and have signMessage sign it, as a tool that signs caller text would
    const created = Math.floor(Date.now() / 1000);
    const headers: Record<string, string> = {
      'Signature-Agent': document.id,
      Date: signed.Date,
      'Content-Digest': signed['Content-Digest']
    };
    const input = {
      components: [...AGENT_DID_HTTP_SIGNATURE_COMPONENTS],
      params: [
        ['created', created],
        ['expires', created + 30],
        ['nonce', 'a'.repeat(32)],
        ['keyid', keyId],
        ['alg', 'ed25519'],
        ['tag', AGENT_DID_HTTP_SIGNATURE_TAG]
      ] as Array<[string, string | number]>
    };
    const base = buildSignatureBase({ method: 'POST', url, headers }, input);
    const viaSignMessage = await identity.signMessage(base, agentPrivateKey);
    const forged = {
      ...headers,
      'Signature-Input': `sig1=${serializeSignatureInput(input)}`,
      Signature: `sig1=:${Buffer.from(hexToBytes(viaSignMessage)).toString('base64')}:`
    };

    const forgedResult = await client.verifyHttpRequestSignatureDetailed({ method: 'POST', url, body, headers: forged });
    expect(forgedResult.ok).toBe(false);

    // The genuine request still verifies
    const genuine = await client.verifyHttpRequestSignatureDetailed({ method: 'POST', url, body, headers: signed });
    expect(genuine.ok).toBe(true);
  });
});
