import { LocalKeySigner } from '../src/core/signer';
import { AgentDidClient, AgentIdentity, InMemoryAgentRegistry } from '../src';
import { CreateAgentParams } from '../src/core/types';
import { DidWebvhError } from '../src/webvh/adapter';
import { ResolverResolutionEvent } from '../src/resolver/types';

const params: CreateAgentParams = {
  name: 'LogStateBot',
  description: 'Agent used to test how a client keeps did:webvh logs',
  coreModel: 'gpt-4o-mini',
  systemPrompt: 'You are a test assistant.'
};

const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

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

async function createAgent(client: AgentDidClient) {
  const [wallet] = LocalKeySigner.generate();
  const identity = new AgentIdentity({ controllerSigner: wallet, client });
  const { document, agentPrivateKey } = await identity.create(params);
  const signature = await identity.signMessage('hello', agentPrivateKey);
  return { identity, document, signature };
}

describe('did:webvh log held by a client', () => {
  describe('importing a log', () => {
    it('rejects an older prefix of the stored log, so a revoked DID stays revoked', async () => {
      const client = new AgentDidClient();
      const { document, signature } = await createAgent(client);
      const beforeRevocation = client.exportDidWebvhHistory(document.id);
      await client.revokeDid(document.id);
      expect(await client.verifySignature(document.id, 'hello', signature)).toBe(false);

      await expect(client.importDidWebvhHistory(beforeRevocation)).rejects.toBeInstanceOf(DidWebvhError);

      expect(await client.verifySignature(document.id, 'hello', signature)).toBe(false);
      await expect(client.resolve(document.id)).rejects.toThrow(/revoked/u);
    });

    it('rejects a log that diverges from the stored one', async () => {
      const client = new AgentDidClient();
      const { document } = await createAgent(client);
      const stored = client.exportDidWebvhHistory(document.id);
      const other = new AgentDidClient();
      await other.importDidWebvhHistory(stored);
      // `other` holds no controller signer, so the diverging branch is signed with the original one
      const signer = (client as any).didWebvhSignerStore.get(document.id);
      await client.updateDidDocument(document.id, { description: 'branch A' });
      const branchA = client.exportDidWebvhHistory(document.id);
      await other.updateDidDocument(document.id, { description: 'branch B' }, { controllerSigner: signer });
      const branchB = other.exportDidWebvhHistory(document.id);

      await expect(client.importDidWebvhHistory(branchB)).rejects.toBeInstanceOf(DidWebvhError);
      expect(client.exportDidWebvhHistory(document.id)).toBe(branchA);
    });

    it('treats the same log as a no-op that keeps the retained controller signer', async () => {
      const client = new AgentDidClient();
      const { document } = await createAgent(client);
      const stored = client.exportDidWebvhHistory(document.id);

      await client.importDidWebvhHistory(stored);

      expect(client.exportDidWebvhHistory(document.id)).toBe(stored);
      // The controller signer was kept: the DID can still be changed without passing one
      await expect(client.updateDidDocument(document.id, { description: 'still mine' })).resolves.toBeDefined();
    });

    it('accepts a log that extends the stored one and keeps the signer while its key is an updateKey', async () => {
      const client = new AgentDidClient();
      const { document } = await createAgent(client);
      const verifier = new AgentDidClient();
      await verifier.importDidWebvhHistory(client.exportDidWebvhHistory(document.id));
      await client.updateDidDocument(document.id, { description: 'newer' });

      const imported = await verifier.importDidWebvhHistory(client.exportDidWebvhHistory(document.id));

      expect(imported.agentMetadata.description).toBe('newer');
      // The creator's own signer is still an updateKey of the log, so it keeps control after re-importing it
      await client.importDidWebvhHistory(client.exportDidWebvhHistory(document.id));
      await expect(client.updateDidDocument(document.id, { description: 'newest' })).resolves.toBeDefined();
    });
  });

  describe('resolving with a production resolver', () => {
    const events: ResolverResolutionEvent[] = [];
    const unreachableHost = {
      getByReference: async () => null,
      getDidLogByReference: async (): Promise<string | null> => {
        throw new Error('connect ETIMEDOUT');
      }
    };
    const productionClient = (cacheTtlMs: number) => {
      const client = new AgentDidClient();
      client.useProductionResolver({
        registry: new InMemoryAgentRegistry(),
        documentSource: { getByReference: async () => null },
        webvhDocumentSource: unreachableHost,
        cacheTtlMs,
        onResolutionEvent: (event) => events.push(event)
      });
      return client;
    };

    beforeEach(() => {
      events.length = 0;
    });

    it('keeps resolving an agent created in this client after the resolver cache expires', async () => {
      const client = productionClient(60_000);
      const { document, signature } = await createAgent(client);
      expect(await client.verifySignature(document.id, 'hello', signature)).toBe(true);

      advanceClock(120_000);

      expect(await client.verifySignature(document.id, 'hello', signature)).toBe(true);
    });

    it('fails closed for an imported DID whose log cannot be refreshed after the cache expires', async () => {
      const creator = new AgentDidClient();
      const { document, signature } = await createAgent(creator);
      const verifier = productionClient(60_000);
      await verifier.importDidWebvhHistory(creator.exportDidWebvhHistory(document.controller));
      await verifier.importDidWebvhHistory(creator.exportDidWebvhHistory(document.id));
      expect(await verifier.verifySignature(document.id, 'hello', signature)).toBe(true);

      advanceClock(120_000);

      expect(await verifier.verifySignature(document.id, 'hello', signature)).toBe(false);
    });

    it('does not serve a revoked DID from an older copy when its host is down', async () => {
      const creator = new AgentDidClient();
      const { document, signature } = await createAgent(creator);
      const beforeRevocation = creator.exportDidWebvhHistory(document.id);
      await creator.revokeDid(document.id);
      const verifier = new AgentDidClient();
      await verifier.importDidWebvhHistory(creator.exportDidWebvhHistory(document.controller));
      await verifier.importDidWebvhHistory(beforeRevocation);
      verifier.useProductionResolver({
        registry: new InMemoryAgentRegistry(),
        documentSource: { getByReference: async () => null },
        webvhDocumentSource: unreachableHost,
        cacheTtlMs: 60_000
      });
      advanceClock(120_000);

      expect(await verifier.verifySignature(document.id, 'hello', signature)).toBe(false);
    });

    it('reports a failed remote write of a document instead of swallowing it', async () => {
      const client = new AgentDidClient();
      client.useProductionResolver({
        registry: new InMemoryAgentRegistry(),
        documentSource: {
          getByReference: async () => null,
          storeByReference: async () => {
            throw new Error('storage unavailable');
          }
        },
        webvhDocumentSource: unreachableHost,
        onResolutionEvent: (event) => events.push(event)
      });

      await createAgent(client);
      await sleep(10);

      expect(events).toContainEqual(
        expect.objectContaining({ stage: 'error', message: expect.stringMatching(/storeByReference failed: storage unavailable/u) })
      );
    });
  });
});
