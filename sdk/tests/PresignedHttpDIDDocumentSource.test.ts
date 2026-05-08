import { PresignedHttpDIDDocumentSource } from '../src/resolver/PresignedHttpDIDDocumentSource';

describe('PresignedHttpDIDDocumentSource', () => {
  const sampleDocument = {
    '@context': ['https://www.w3.org/ns/did/v1', 'https://agent-did.org/v1'],
    id: 'did:webvh:QmPresignedScid:example.com:agents:presigned-bot',
    controller: 'did:webvh:QmPresignedScid:example.com:organizations:ops-root',
    created: '2026-05-06T00:00:00.000Z',
    updated: '2026-05-06T00:00:00.000Z',
    agentMetadata: {
      name: 'PresignedResolverBot',
      version: '1.0.0',
      coreModelHash: 'hash://sha256/model',
      systemPromptHash: 'hash://sha256/prompt'
    },
    verificationMethod: [
      {
        id: 'did:webvh:QmPresignedScid:example.com:agents:presigned-bot#key-1',
        type: 'Ed25519VerificationKey2020',
        controller: 'did:webvh:QmPresignedScid:example.com:organizations:ops-root',
        publicKeyMultibase: 'zabc'
      }
    ],
    authentication: ['did:webvh:QmPresignedScid:example.com:agents:presigned-bot#key-1'],
    assertionMethod: ['did:webvh:QmPresignedScid:example.com:agents:presigned-bot#key-1']
  };

  it('should resolve through public read URLs', async () => {
    const fetchFn = jest.fn().mockResolvedValue({
      ok: true,
      status: 200,
      json: async () => sampleDocument
    });
    const source = new PresignedHttpDIDDocumentSource({
      fetchFn,
      referenceToReadUrl: (ref) => `https://cdn.example/${encodeURIComponent(ref)}.json`
    });

    const loaded = await source.getByReference('hash://sha256/presigned-doc');

    expect(loaded?.id).toEqual(sampleDocument.id);
    expect(fetchFn).toHaveBeenCalledWith('https://cdn.example/hash%3A%2F%2Fsha256%2Fpresigned-doc.json');
  });

  it('should write documents through a dedicated upload URL', async () => {
    const fetchFn = jest.fn().mockResolvedValue({
      ok: true,
      status: 204,
      json: async () => ({})
    });
    const source = new PresignedHttpDIDDocumentSource({
      fetchFn,
      referenceToReadUrl: (ref) => `https://cdn.example/${encodeURIComponent(ref)}.json`,
      referenceToWriteUrl: (ref) => `https://upload.example/${encodeURIComponent(ref)}?signature=document`
    });

    await source.storeByReference('hash://sha256/presigned-doc', sampleDocument);

    expect(fetchFn).toHaveBeenCalledWith(
      'https://upload.example/hash%3A%2F%2Fsha256%2Fpresigned-doc?signature=document',
      {
        method: 'PUT',
        headers: {
          'content-type': 'application/json; charset=utf-8'
        },
        body: JSON.stringify(sampleDocument)
      }
    );
  });

  it('should write did logs through a dedicated upload URL', async () => {
    const fetchFn = jest.fn().mockResolvedValue({
      ok: true,
      status: 201,
      json: async () => ({})
    });
    const source = new PresignedHttpDIDDocumentSource({
      fetchFn,
      referenceToReadUrl: (ref) => `https://cdn.example/${encodeURIComponent(ref)}.jsonl`,
      referenceToWriteUrl: (ref) => `https://upload.example/${encodeURIComponent(ref)}?signature=document`,
      didLogReferenceToWriteUrl: (ref) => `https://upload.example/${encodeURIComponent(ref)}?signature=history`,
      didLogStoreMethod: 'POST'
    });
    const didLog = JSON.stringify({ versionId: '1-QmPresignedScid', state: sampleDocument });

    await source.storeDidLogByReference('history://presigned/bot', didLog);

    expect(fetchFn).toHaveBeenCalledWith(
      'https://upload.example/history%3A%2F%2Fpresigned%2Fbot?signature=history',
      {
        method: 'POST',
        headers: {
          'content-type': 'application/jsonl; charset=utf-8'
        },
        body: didLog
      }
    );
  });

  it('should fetch raw did logs through public read URLs with failover', async () => {
    const didLog = JSON.stringify({ versionId: '1-QmPresignedScid', state: sampleDocument });
    const fetchFn = jest
      .fn()
      .mockResolvedValueOnce({ ok: false, status: 503, text: async () => '' })
      .mockResolvedValueOnce({ ok: true, status: 200, text: async () => didLog });
    const source = new PresignedHttpDIDDocumentSource({
      fetchFn,
      didLogReferenceToReadUrls: (ref) => [
        `https://cdn-a.example/${encodeURIComponent(ref)}.jsonl`,
        `https://cdn-b.example/${encodeURIComponent(ref)}.jsonl`
      ]
    });

    const loaded = await source.getDidLogByReference('history://presigned/bot');

    expect(loaded).toEqual(didLog);
    expect(fetchFn).toHaveBeenCalledTimes(2);
  });

  it('should read documents and did logs from separate public URLs', async () => {
    const didLog = JSON.stringify({ versionId: '1-QmPresignedScid', state: sampleDocument });
    const fetchFn = jest
      .fn()
      .mockResolvedValueOnce({ ok: true, status: 200, json: async () => sampleDocument })
      .mockResolvedValueOnce({ ok: true, status: 200, text: async () => didLog });
    const source = new PresignedHttpDIDDocumentSource({
      fetchFn,
      referenceToReadUrl: (ref) => `https://cdn-docs.example/${encodeURIComponent(ref)}.json`,
      didLogReferenceToReadUrl: (ref) => `https://cdn-logs.example/${encodeURIComponent(ref)}.jsonl`
    });

    const loadedDocument = await source.getByReference('hash://sha256/presigned-doc');
    const loadedDidLog = await source.getDidLogByReference('history://presigned/bot');

    expect(loadedDocument?.id).toEqual(sampleDocument.id);
    expect(loadedDidLog).toEqual(didLog);
    expect(fetchFn).toHaveBeenNthCalledWith(1, 'https://cdn-docs.example/hash%3A%2F%2Fsha256%2Fpresigned-doc.json');
    expect(fetchFn).toHaveBeenNthCalledWith(2, 'https://cdn-logs.example/history%3A%2F%2Fpresigned%2Fbot.jsonl');
  });
});