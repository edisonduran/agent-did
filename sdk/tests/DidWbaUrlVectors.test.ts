import * as fs from 'fs';
import * as path from 'path';
import { InMemoryAgentRegistry, UniversalResolverClient } from '../src';
import { AgentDIDDocument } from '../src/core/types';

// did:wba DID -> document URL vectors (fixtures/did-wba-url-vectors.json; parity: sdk-python/tests/test_did_wba_url_vectors.py)
interface DidWbaUrlVector {
  did: string;
  url?: string;
  invalid?: boolean;
  note?: string;
}

const fixture = JSON.parse(
  fs.readFileSync(path.join(__dirname, '..', '..', 'fixtures', 'did-wba-url-vectors.json'), 'utf8')
) as { vectors: DidWbaUrlVector[] };

const document = (id: string) =>
  ({
    '@context': ['https://www.w3.org/ns/did/v1'],
    id,
    controller: id,
    created: '2026-01-01T00:00:00Z',
    updated: '2026-01-01T00:00:00Z',
    agentMetadata: { name: 'bot', version: '1', coreModelHash: 'h', systemPromptHash: 'h' },
    verificationMethod: [],
    authentication: []
  }) as AgentDIDDocument;

function resolverRecording(did: string): { resolver: UniversalResolverClient; urls: string[] } {
  const urls: string[] = [];
  const resolver = new UniversalResolverClient({
    registry: new InMemoryAgentRegistry(),
    documentSource: { getByReference: async () => null },
    wbaDocumentSource: {
      getByReference: async (url: string) => {
        urls.push(url);
        return document(did);
      }
    }
  });
  return { resolver, urls };
}

describe('did:wba document URL — shared vectors (fixtures/did-wba-url-vectors.json)', () => {
  const positives = fixture.vectors.filter((v) => v.url !== undefined);
  const negatives = fixture.vectors.filter((v) => v.invalid === true);

  it('has positive and negative vectors', () => {
    expect(positives.length).toBeGreaterThan(0);
    expect(negatives.length).toBeGreaterThanOrEqual(20);
  });

  it.each(positives.map((v) => [v.did, v.url as string]))('derives %s', async (did, url) => {
    const { resolver, urls } = resolverRecording(did);
    const resolved = await resolver.resolve(did);
    expect(resolved.id).toBe(did);
    expect(urls).toEqual([url]);
  });

  it.each(negatives.map((v) => [v.did]))('rejects %s before any fetch', async (did) => {
    const { resolver, urls } = resolverRecording(did);
    await expect(resolver.resolve(did)).rejects.toThrow(/Invalid did:wba/);
    expect(urls).toEqual([]);
  });
});
