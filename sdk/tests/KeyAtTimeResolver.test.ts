import { LocalKeySigner } from '../src/core/signer';
import { AgentDidClient, AgentIdentity, InMemoryAgentRegistry } from '../src';
import { deriveDidWebvhLogUrl } from '../src/webvh/adapter';

// The resolver cache reads `Date.now()`: moving it forward expires cache entries without waiting.
const realNow = Date.now.bind(Date);
let clockOffsetMs = 0;
const advanceClock = (ms: number) => {
  clockOffsetMs += ms;
};
beforeEach(() => {
  clockOffsetMs = 0;
  jest.spyOn(Date, 'now').mockImplementation(() => realNow() + clockOffsetMs);
});
afterEach(() => {
  jest.restoreAllMocks();
});

const firstVersionTime = (log: string): string =>
  (JSON.parse(log.split('\n').find((line) => line.trim()) as string) as { versionTime: string }).versionTime;

/** An owner client that creates an agent and signs, and a log host that serves the owner's current logs. */
async function setUp() {
  const owner = new AgentDidClient();
  const [wallet] = LocalKeySigner.generate();
  const identity = new AgentIdentity({ controllerSigner: wallet, client: owner });
  const { document, agentPrivateKey } = await identity.create({
    name: 'AtTimeBot',
    coreModel: 'test',
    systemPrompt: 'test'
  });
  const did = document.id;
  const keyId = `${did}#key-1`;
  const signature = await identity.signMessage('approve', agentPrivateKey);
  const statedTime = firstVersionTime(owner.exportDidWebvhHistory(did));
  let reachable = true;
  const host = {
    getByReference: async () => null,
    getDidLogByReference: async (url: string): Promise<string | null> => {
      if (!reachable) {
        throw new Error('connect ETIMEDOUT');
      }
      for (const served of [did, document.controller as string]) {
        if (deriveDidWebvhLogUrl(served) === url) {
          return owner.exportDidWebvhHistory(served);
        }
      }
      return null;
    }
  };
  const verifier = () => {
    const client = new AgentDidClient();
    client.useProductionResolver({
      registry: new InMemoryAgentRegistry(),
      documentSource: { getByReference: async () => null },
      webvhDocumentSource: host,
      cacheTtlMs: 60_000
    });
    return client;
  };
  return {
    owner,
    document,
    did,
    keyId,
    signature,
    statedTime,
    verifier,
    setReachable: (value: boolean) => {
      reachable = value;
    }
  };
}

describe('verifySignatureAtTime with a resolver that fetches did:webvh logs', () => {
  it('checks a DID this client never imported against the log the resolver fetches', async () => {
    const { did, keyId, signature, statedTime, verifier } = await setUp();

    const result = await verifier().verifySignatureAtTime(did, 'approve', signature, keyId, { statedTime });

    expect(result.status).toBe('valid');
  });

  it('sees a key rotation published after the log was imported once the cache entry expires', async () => {
    const { owner, document, did, keyId, signature, statedTime, verifier } = await setUp();
    const client = verifier();
    await client.importDidWebvhHistory(owner.exportDidWebvhHistory(document.controller as string));
    await client.importDidWebvhHistory(owner.exportDidWebvhHistory(did));
    expect((await client.verifySignatureAtTime(did, 'approve', signature, keyId, { statedTime })).status).toBe('valid');

    await owner.rotateVerificationMethod(did);
    advanceClock(120_000);

    const result = await client.verifySignatureAtTime(did, 'approve', signature, keyId, { statedTime });
    expect(result.status).toBe('indeterminate');
    expect(result.key).toMatchObject({ status: 'indeterminate', reason: 'key_retired_after_stated_time' });
  });

  it('returns a status for a deactivated DID instead of throwing', async () => {
    const { owner, did, keyId, signature, statedTime, verifier } = await setUp();
    await owner.revokeDid(did);
    const client = verifier();

    const result = await client.verifySignatureAtTime(did, 'approve', signature, keyId, { statedTime });
    expect(result.status).toBe('indeterminate');
    expect(result.key).toMatchObject({ reason: 'did_deactivated_after_stated_time' });

    // Trusted evidence earlier than the deactivation makes the signature valid; the DID itself stays unresolvable
    const withEvidence = await client.verifySignatureAtTime(did, 'approve', signature, keyId, {
      statedTime,
      trustedTimeNotAfter: statedTime
    });
    expect(withEvidence.status).toBe('valid');
    await expect(client.resolve(did)).rejects.toThrow(/deactivated|revoked/u);
  });

  it('fails closed when the log host cannot be reached and nothing was imported', async () => {
    const { did, keyId, signature, statedTime, verifier, setReachable } = await setUp();
    setReachable(false);

    const result = await verifier().verifySignatureAtTime(did, 'approve', signature, keyId, { statedTime });

    expect(result).toEqual({ status: 'invalid', reason: 'did_resolution_failed' });
  });

  it('keeps answering from the imported log while the resolver does not fetch logs', async () => {
    const { owner, document, did, keyId, signature, statedTime } = await setUp();
    const client = new AgentDidClient();
    await client.importDidWebvhHistory(owner.exportDidWebvhHistory(document.controller as string));
    await client.importDidWebvhHistory(owner.exportDidWebvhHistory(did));

    expect((await client.verifySignatureAtTime(did, 'approve', signature, keyId, { statedTime })).status).toBe('valid');
  });
});
