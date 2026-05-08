import { WebvhDIDDocumentSource } from '../src/resolver/WebvhDIDDocumentSource';

describe('WebvhDIDDocumentSource', () => {
  const sampleDocument = {
    '@context': ['https://www.w3.org/ns/did/v1', 'https://agent-did.org/v1'],
    id: 'did:webvh:QmExampleScid:example.com:agents:webvh-bot',
    controller: 'did:webvh:QmExampleScid:example.com:organizations:acme-support',
    created: '2026-05-06T00:00:00.000Z',
    updated: '2026-05-06T00:00:00.000Z',
    agentMetadata: {
      name: 'WebvhResolverBot',
      version: '1.0.0',
      coreModelHash: 'hash://sha256/model',
      systemPromptHash: 'hash://sha256/prompt'
    },
    verificationMethod: [
      {
        id: 'did:webvh:QmExampleScid:example.com:agents:webvh-bot#key-1',
        type: 'Ed25519VerificationKey2020',
        controller: 'did:webvh:QmExampleScid:example.com:organizations:acme-support',
        publicKeyMultibase: 'zabc'
      }
    ],
    authentication: ['did:webvh:QmExampleScid:example.com:agents:webvh-bot#key-1'],
    assertionMethod: ['did:webvh:QmExampleScid:example.com:agents:webvh-bot#key-1']
  };

  it('should parse the latest state from a did:webvh DID log', async () => {
    const fetchFn = jest.fn().mockResolvedValue({
      ok: true,
      status: 200,
      json: async () => ({}),
      text: async () => [
        JSON.stringify({ versionId: '1-QmExampleScid', state: { ...sampleDocument, updated: '2026-05-05T00:00:00.000Z' } }),
        JSON.stringify({ versionId: '2-QmExampleScid', state: sampleDocument })
      ].join('\n')
    });

    const source = new WebvhDIDDocumentSource({ fetchFn });
    const result = await source.getByReference('https://example.com/agents/webvh-bot/did.jsonl');

    expect(result?.id).toEqual(sampleDocument.id);
    expect(result?.updated).toEqual(sampleDocument.updated);
  });

  it('should return null on 404', async () => {
    const fetchFn = jest.fn().mockResolvedValue({
      ok: false,
      status: 404,
      json: async () => ({}),
      text: async () => ''
    });

    const source = new WebvhDIDDocumentSource({ fetchFn });
    const result = await source.getByReference('https://example.com/.well-known/did.jsonl');

    expect(result).toBeNull();
  });

  it('should try candidate did:webvh URLs until one succeeds', async () => {
    const candidateUrls = [
      'https://primary.example/agents/webvh-bot/did.jsonl',
      'https://secondary.example/agents/webvh-bot/did.jsonl',
      'https://tertiary.example/agents/webvh-bot/did.jsonl'
    ];
    const fetchFn = jest.fn(async (url: string) => {
      if (url === candidateUrls[0]) {
        return {
          ok: false,
          status: 503,
          json: async () => ({}),
          text: async () => ''
        };
      }

      if (url === candidateUrls[1]) {
        return {
          ok: false,
          status: 404,
          json: async () => ({}),
          text: async () => ''
        };
      }

      return {
        ok: true,
        status: 200,
        json: async () => ({}),
        text: async () => JSON.stringify({ versionId: '2-QmExampleScid', state: sampleDocument })
      };
    });

    const source = new WebvhDIDDocumentSource({
      fetchFn,
      referenceToUrls: () => candidateUrls
    });
    const result = await source.getByReference('https://example.com/agents/webvh-bot/did.jsonl');

    expect(result?.id).toEqual(sampleDocument.id);
    expect(fetchFn).toHaveBeenCalledTimes(3);
    expect(fetchFn.mock.calls.map(([url]) => url)).toEqual(candidateUrls);
  });
});