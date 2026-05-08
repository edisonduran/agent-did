import { BearerTokenHttpDIDDocumentSource } from '../src/resolver/BearerTokenHttpDIDDocumentSource';

describe('BearerTokenHttpDIDDocumentSource', () => {
  const sampleDocument = {
    '@context': ['https://www.w3.org/ns/did/v1', 'https://agent-did.org/v1'],
    id: 'did:webvh:QmBearerScid:example.com:agents:bearer-bot',
    controller: 'did:webvh:QmBearerScid:example.com:organizations:ops-root',
    created: '2026-05-07T00:00:00.000Z',
    updated: '2026-05-07T00:00:00.000Z',
    agentMetadata: {
      name: 'BearerResolverBot',
      version: '1.0.0',
      coreModelHash: 'hash://sha256/model',
      systemPromptHash: 'hash://sha256/prompt'
    },
    verificationMethod: [
      {
        id: 'did:webvh:QmBearerScid:example.com:agents:bearer-bot#key-1',
        type: 'Ed25519VerificationKey2020',
        controller: 'did:webvh:QmBearerScid:example.com:organizations:ops-root',
        publicKeyMultibase: 'zabc'
      }
    ],
    authentication: ['did:webvh:QmBearerScid:example.com:agents:bearer-bot#key-1'],
    assertionMethod: ['did:webvh:QmBearerScid:example.com:agents:bearer-bot#key-1']
  };

  it('should inject bearer authorization on document reads', async () => {
    const fetchFn = jest.fn().mockResolvedValue({
      ok: true,
      status: 200,
      json: async () => sampleDocument
    });
    const source = new BearerTokenHttpDIDDocumentSource({
      token: 'secret-token',
      fetchFn,
      referenceToUrl: (ref) => `https://secured.example/${encodeURIComponent(ref)}.json`
    });

    const loaded = await source.getByReference('hash://sha256/bearer-doc');

    expect(loaded?.id).toEqual(sampleDocument.id);
    expect(fetchFn).toHaveBeenCalledWith(
      'https://secured.example/hash%3A%2F%2Fsha256%2Fbearer-doc.json',
      {
        headers: {
          authorization: 'Bearer secret-token'
        }
      }
    );
  });

  it('should inject auth on did-log writes and merge content-type headers', async () => {
    const fetchFn = jest.fn().mockResolvedValue({
      ok: true,
      status: 200,
      json: async () => ({})
    });
    const getToken = jest.fn().mockResolvedValue('refreshed-token');
    const didLog = JSON.stringify({ versionId: '1-QmBearerScid', state: sampleDocument });
    const source = new BearerTokenHttpDIDDocumentSource({
      getToken,
      fetchFn,
      referenceToUrl: (ref) => `https://secured.example/${encodeURIComponent(ref)}.jsonl`,
      didLogStoreMethod: 'POST'
    });

    await source.storeDidLogByReference('history://bearer/bot', didLog);

    expect(getToken).toHaveBeenCalledTimes(1);
    expect(fetchFn).toHaveBeenCalledWith(
      'https://secured.example/history%3A%2F%2Fbearer%2Fbot.jsonl',
      {
        method: 'POST',
        headers: {
          'content-type': 'application/jsonl; charset=utf-8',
          authorization: 'Bearer refreshed-token'
        },
        body: didLog
      }
    );
  });
});