import { LocalKeySigner } from '../src/core/signer';
import { AgentDidClient, AgentIdentity, InMemoryAgentRegistry } from '../src';
import { deriveDidWebvhLogUrl } from '../src/webvh/adapter';

// Parity: sdk-python/tests/test_evict_resolution.py
describe('evictCachedResolution', () => {
  it('makes the next resolution fetch again, and keeps documents a non-caching resolver holds', async () => {
    const owner = new AgentDidClient();
    const identity = new AgentIdentity({ controllerSigner: LocalKeySigner.generate()[0], client: owner });
    const { document } = await identity.create({ name: 'EvictBot', coreModel: 'test', systemPrompt: 'test' });
    const fetches = jest.fn(async (url: string) =>
      url === deriveDidWebvhLogUrl(document.id) ? owner.exportDidWebvhHistory(document.id) : null
    );
    const verifier = new AgentDidClient();
    verifier.useProductionResolver({
      registry: new InMemoryAgentRegistry(),
      documentSource: { getByReference: async () => null },
      webvhDocumentSource: { getByReference: async () => null, getDidLogByReference: fetches }
    });

    await verifier.resolve(document.id);
    await verifier.resolve(document.id);
    expect(fetches).toHaveBeenCalledTimes(1);

    verifier.evictCachedResolution(document.id);
    await verifier.resolve(document.id);
    expect(fetches).toHaveBeenCalledTimes(2);

    // The default in-memory resolver is a store, not a cache: nothing is dropped
    owner.evictCachedResolution(document.id);
    await expect(owner.resolve(document.id)).resolves.toMatchObject({ id: document.id });
  });
});
