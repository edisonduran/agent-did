/**
 * Controller documents (RFC-001 §4.2.1): a did:webvh controller may be any DID Core document. Only the agent's own
 * document must be an Agent-DID document; the binding rule (§6.6 item 7) is unchanged.
 * The Python SDK runs the same cases in sdk-python/tests/test_controller_documents.py.
 */
import { AgentDidClient, AgentIdentity, InMemoryAgentRegistry, LocalKeySigner } from '../src';
import { encodePublicKeyMultibase } from '../src/crypto/multibase';
import { createDidWebvhLog, deriveDidWebvhLogUrl, DID_WEBVH_PLACEHOLDER } from '../src/webvh/adapter';

const D = DID_WEBVH_PLACEHOLDER;
const DID_CORE_CONTEXT = ['https://www.w3.org/ns/did/v1', 'https://w3id.org/security/multikey/v1'];

/** A plain DID Core controller document: no `agentMetadata`, `created`, `updated` or `controller`. */
async function plainControllerDocument(signer: LocalKeySigner): Promise<Record<string, unknown>> {
  const publicKeyMultibase = encodePublicKeyMultibase(await signer.getPublicKey());
  return {
    '@context': DID_CORE_CONTEXT,
    id: D,
    verificationMethod: [{ id: `${D}#key-1`, type: 'Multikey', controller: D, publicKeyMultibase }],
    authentication: ['#key-1'],
    assertionMethod: ['#key-1'],
    capabilityInvocation: ['#key-1']
  };
}

/**
 * A controller published as a plain DID Core did:webvh log, an agent under it created by an owner client, and a log
 * host that serves both logs. `controllerDocument` builds the controller's document from its key.
 */
async function setUp(
  controllerDocument: (signer: LocalKeySigner) => Promise<Record<string, unknown>> = plainControllerDocument
) {
  const [controllerSigner] = LocalKeySigner.generate();
  const controller = await createDidWebvhLog({
    domain: 'org.example',
    pathSegments: ['controllers', 'acme'],
    document: await controllerDocument(controllerSigner),
    signer: controllerSigner
  });
  const controllerDid = controller.did;
  const logs = new Map<string, string>([[deriveDidWebvhLogUrl(controllerDid), controller.log]]);
  const host = {
    getByReference: async () => null,
    getDidLogByReference: async (url: string): Promise<string | null> => logs.get(url) ?? null
  };
  const withHost = (client: AgentDidClient): AgentDidClient => {
    client.useProductionResolver({
      registry: new InMemoryAgentRegistry(),
      documentSource: { getByReference: async () => null },
      webvhDocumentSource: host
    });
    return client;
  };

  const owner = withHost(new AgentDidClient());
  const [wallet] = LocalKeySigner.generate();
  const identity = new AgentIdentity({ controllerSigner: wallet, client: owner });
  const agent = await identity.create({
    name: 'PlainControllerBot',
    webvh: { domain: 'org.example', pathSegments: ['agents', 'bot'], controllerDid, controllerSigner }
  });
  logs.set(deriveDidWebvhLogUrl(agent.document.id), owner.exportDidWebvhHistory(agent.document.id));
  const signature = await identity.signMessage('approve', agent.agentPrivateKey);
  return {
    controllerDid,
    controllerSigner,
    owner,
    identity,
    agent,
    signature,
    verifier: () => withHost(new AgentDidClient())
  };
}

describe('controller documents (RFC-001 §4.2.1)', () => {
  it('verifies an agent whose controller is a plain DID Core document, in the owner and in a verifier', async () => {
    const { owner, agent, signature, verifier } = await setUp();

    expect(await owner.verifySignature(agent.document.id, 'approve', signature)).toBe(true);
    expect(await verifier().verifySignature(agent.document.id, 'approve', signature)).toBe(true);
  });

  it('resolves the controller with resolveDocument and in the chain, but not with resolve', async () => {
    const { controllerDid, agent, verifier } = await setUp();
    const client = verifier();

    const controller = await client.resolveDocument(controllerDid);
    expect(controller.id).toBe(controllerDid);
    expect(controller).not.toHaveProperty('agentMetadata');
    const chain = await client.resolveControllerChain(agent.document.id);
    expect(chain.map((document) => document.id)).toEqual([agent.document.id, controllerDid]);
    await expect(client.resolve(controllerDid)).rejects.toThrow('is not an Agent-DID document');
  });

  it('never verifies a signature for a DID whose document is not an Agent-DID document', async () => {
    const { controllerDid, signature, verifier } = await setUp();
    const client = verifier();
    const keyId = `${controllerDid}#key-1`;

    expect(await client.verifySignature(controllerDid, 'approve', signature, keyId)).toBe(false);
    const atTime = await client.verifySignatureAtTime(controllerDid, 'approve', signature, keyId, {
      statedTime: new Date().toISOString()
    });
    expect(atTime).toEqual({ status: 'invalid', reason: 'did_resolution_failed' });
  });

  it('accepts a key embedded in capabilityInvocation', async () => {
    const { agent, signature, verifier } = await setUp(async (signer) => ({
      '@context': DID_CORE_CONTEXT,
      id: D,
      capabilityInvocation: [
        {
          id: '#invoke',
          type: 'Multikey',
          controller: D,
          publicKeyMultibase: encodePublicKeyMultibase(await signer.getPublicKey())
        }
      ]
    }));

    expect(await verifier().verifySignature(agent.document.id, 'approve', signature)).toBe(true);
  });

  it('rejects the agent when the controller lists its key only outside capabilityInvocation', async () => {
    const { agent, signature, verifier } = await setUp(async (signer) => {
      const document = await plainControllerDocument(signer);
      delete document.capabilityInvocation;
      return document;
    });
    const client = verifier();

    expect(await client.verifySignature(agent.document.id, 'approve', signature)).toBe(false);
    await expect(
      client.verifySignatureAtTime(agent.document.id, 'approve', signature, agent.document.authentication[0], {
        statedTime: new Date().toISOString()
      })
    ).resolves.toMatchObject({ status: 'invalid', reason: 'controller_not_bound' });
  });

  it('fails closed on a controller whose controller is a list', async () => {
    const { agent, signature, verifier } = await setUp(async (signer) => ({
      ...(await plainControllerDocument(signer)),
      controller: ['did:webvh:QmA:org.example:a', 'did:webvh:QmB:org.example:b']
    }));
    const client = verifier();

    expect(await client.verifySignature(agent.document.id, 'approve', signature)).toBe(false);
    await expect(client.resolveControllerChain(agent.document.id)).rejects.toThrow('a list of controllers');
  });

  it('rejects a controller log whose state is not a DID document', async () => {
    const { agent, signature, verifier } = await setUp(async (signer) => ({
      ...(await plainControllerDocument(signer)),
      capabilityInvocation: [42]
    }));
    const client = verifier();

    expect(await client.verifySignature(agent.document.id, 'approve', signature)).toBe(false);
    await expect(client.resolveControllerChain(agent.document.id)).rejects.toThrow('is not a DID document');
  });

  it('issues and verifies an AgentMetadataCredential with a relative assertionMethod key of a plain controller', async () => {
    const { controllerDid, controllerSigner, owner, agent, verifier } = await setUp();

    const credential = await owner.issueAgentMetadataCredential({
      agentDid: agent.document.id,
      signer: controllerSigner,
      verificationMethodId: `${controllerDid}#key-1`
    });
    const result = await verifier().verifyAgentMetadataCredential(credential);

    expect(result).toMatchObject({ ok: true, issuer: controllerDid, controllers: [controllerDid] });
  });

  it('rejects the agent when the key of the plain controller carries deactivated', async () => {
    const { agent, signature, verifier } = await setUp(async (signer) => {
      const document = await plainControllerDocument(signer);
      (document.verificationMethod as Array<Record<string, unknown>>)[0].deactivated = '2026-01-01T00:00:00Z';
      return document;
    });

    await expect(verifier().resolveControllerChain(agent.document.id)).resolves.toHaveLength(2);
    expect(await verifier().verifySignature(agent.document.id, 'approve', signature)).toBe(false);
  });
});
