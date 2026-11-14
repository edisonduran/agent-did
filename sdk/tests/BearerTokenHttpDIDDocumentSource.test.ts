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
      allowedOrigins: ['https://secured.example'],
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
      allowedOrigins: ['https://secured.example'],
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

  it('refuses to send the credential to an origin outside allowedOrigins, before resolving the token', async () => {
    const fetchFn = jest.fn().mockResolvedValue({ ok: true, status: 200, json: async () => sampleDocument });
    const getToken = jest.fn().mockResolvedValue('secret-token');
    const source = new BearerTokenHttpDIDDocumentSource({
      allowedOrigins: ['https://Secured.Example:443/ignored-path'],
      getToken,
      fetchFn
    });

    await expect(source.getDidLogByReference('https://attacker.example/agents/bot/did.jsonl')).rejects.toThrow(
      /refuses to send credentials to https:\/\/attacker\.example/u
    );
    await expect(source.getByReference('https://secured.example:8443/doc.json')).rejects.toThrow(/not in allowedOrigins/u);
    expect(getToken).not.toHaveBeenCalled();
    expect(fetchFn).not.toHaveBeenCalled();

    await source.getByReference('https://secured.example/doc.json');
    expect(fetchFn).toHaveBeenCalledWith('https://secured.example/doc.json', { headers: { authorization: 'Bearer secret-token' } });
  });

  it('requires a non-empty list of http(s) origins', () => {
    expect(() => new BearerTokenHttpDIDDocumentSource({ token: 't' } as never)).toThrow(/requires allowedOrigins/u);
    expect(() => new BearerTokenHttpDIDDocumentSource({ token: 't', allowedOrigins: [] })).toThrow(/requires allowedOrigins/u);
    expect(() => new BearerTokenHttpDIDDocumentSource({ token: 't', allowedOrigins: ['ftp://x.example'] })).toThrow(
      /not an http\(s\) origin/u
    );
  });
});
