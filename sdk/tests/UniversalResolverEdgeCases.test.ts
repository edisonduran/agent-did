import { InMemoryAgentRegistry, LocalKeySigner, UniversalResolverClient, createDidWebvhWitnessProof } from '../src';
import { encodePublicKeyMultibase } from '../src/crypto/multibase';
import { InMemoryDIDResolver } from '../src/resolver/InMemoryDIDResolver';
import type { DIDDocumentSource, UniversalResolverConfig } from '../src/resolver/types';
import { createDidWebvhLog, DID_WEBVH_PLACEHOLDER } from '../src/webvh/adapter';
import type { AgentDIDDocument } from '../src';

// Failure paths of the universal resolver that the resolution tests do not reach (C-QA-2).

const D = DID_WEBVH_PLACEHOLDER;

async function controllerLog(witness?: LocalKeySigner) {
  const [signer] = LocalKeySigner.generate();
  const witnessDid = witness ? `did:key:${encodePublicKeyMultibase(await witness.getPublicKey())}` : undefined;
  return createDidWebvhLog({
    domain: 'edge.example',
    document: {
      '@context': ['https://www.w3.org/ns/did/v1', 'https://w3id.org/security/multikey/v1'],
      id: D,
      verificationMethod: [
        { id: `${D}#key-1`, type: 'Multikey', controller: D, publicKeyMultibase: encodePublicKeyMultibase(await signer.getPublicKey()) }
      ],
      assertionMethod: [`${D}#key-1`]
    },
    signer,
    ...(witness && witnessDid
      ? {
          witness: { threshold: 1, witnesses: [witnessDid] },
          collectWitnessProofs: async (request: Parameters<NonNullable<Parameters<typeof createDidWebvhLog>[0]['collectWitnessProofs']>>[0]) => [
            await createDidWebvhWitnessProof({ log: request.log, witnessFile: request.witnessFile, signer: witness })
          ]
        }
      : {})
  });
}

function resolverWith(webvh: DIDDocumentSource, extra: Partial<UniversalResolverConfig> = {}) {
  return new UniversalResolverClient({
    registry: new InMemoryAgentRegistry(),
    documentSource: { getByReference: async () => null },
    webvhDocumentSource: webvh,
    ...extra
  });
}

describe('UniversalResolverClient: methods other than did:webvh', () => {
  it('resolveDocument defers to resolve and resolveDidWebvhLog has nothing to say', async () => {
    const fallback = new InMemoryDIDResolver();
    const document = { id: 'did:example:edge', verificationMethod: [] } as unknown as AgentDIDDocument;
    fallback.registerDocument(document);
    const resolver = resolverWith({ getByReference: async () => null }, { fallbackResolver: fallback });

    await expect(resolver.resolveDocument('did:example:edge')).resolves.toMatchObject({ id: 'did:example:edge' });
    await expect(resolver.resolveDidWebvhLog('did:example:edge')).resolves.toBeUndefined();
  });
});

describe('UniversalResolverClient: did:webvh failures', () => {
  it('refuses a verified log whose state is not an Agent-DID document', async () => {
    const created = await controllerLog();
    const resolver = resolverWith({ getByReference: async () => null, getDidLogByReference: async () => created.log });

    await expect(resolver.resolve(created.did)).rejects.toThrow('is not an Agent-DID document');
    await expect(resolver.resolveDocument(created.did)).resolves.toMatchObject({ id: created.did });
  });

  it('treats a log that is not JSON as an integrity failure', async () => {
    const resolver = resolverWith({ getByReference: async () => null, getDidLogByReference: async () => 'not json' });
    await expect(resolver.resolveDocument('did:webvh:QmScid:edge.example')).rejects.toThrow('log verification failed');
  });

  it('reports a witness file that cannot be fetched', async () => {
    const [witness] = LocalKeySigner.generate();
    const created = await controllerLog(witness);
    const resolver = resolverWith({
      getByReference: async () => null,
      getDidLogByReference: async () => created.log,
      getDidWitnessFileByReference: async () => {
        throw new Error('connection reset');
      }
    });

    await expect(resolver.resolveDocument(created.did)).rejects.toThrow('witness file could not be fetched');
  });

  it('fails closed when the local log cannot be compared or does not verify', async () => {
    const created = await controllerLog();
    const source = { getByReference: async () => null, getDidLogByReference: async () => created.log };

    const empty = resolverWith(source, { didWebvhLocalLog: () => '' });
    await expect(empty.resolveDocument(created.did)).rejects.toThrow('log comparison failed');

    // A local log that extends the fetched one with an entry that does not verify
    const forged = resolverWith(source, { didWebvhLocalLog: () => `${created.log.trimEnd()}\n{"versionId":"2-forged"}\n` });
    await expect(forged.resolveDocument(created.did)).rejects.toThrow('log verification failed');
  });
});

describe('UniversalResolverClient: resolution limits', () => {
  it('keeps the negative cache within maxCacheEntries', async () => {
    const getDidLogByReference = jest.fn().mockRejectedValue(new Error('connect ETIMEDOUT'));
    const resolver = resolverWith({ getByReference: async () => null, getDidLogByReference }, { maxCacheEntries: 1 });
    const first = 'did:webvh:QmScid:one.example';
    const second = 'did:webvh:QmScid:two.example';

    await expect(resolver.resolve(first)).rejects.toThrow();
    await expect(resolver.resolve(second)).rejects.toThrow();
    await expect(resolver.resolve(first)).rejects.toThrow();
    // `first` was evicted by `second`, so it is fetched again
    expect(getDidLogByReference).toHaveBeenCalledTimes(3);
  });

  it('lets an invalid DID fail in the fetch when allowedHosts is set', async () => {
    const resolver = resolverWith(
      { getByReference: async () => null, getDidLogByReference: async () => null },
      { resolutionLimits: { allowedHosts: ['edge.example'] } }
    );
    await expect(resolver.resolve('did:webvh:')).rejects.toThrow();
  });
});
