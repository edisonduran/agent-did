import { S3CompatibleDIDDocumentSource } from '../src/resolver/S3CompatibleDIDDocumentSource';

describe('S3CompatibleDIDDocumentSource', () => {
  const sampleDocument = {
    '@context': ['https://www.w3.org/ns/did/v1', 'https://agent-did.org/v1'],
    id: 'did:webvh:QmS3Scid:example.com:agents:s3-bot',
    controller: 'did:webvh:QmS3Scid:example.com:organizations:ops-root',
    created: '2026-05-07T00:00:00.000Z',
    updated: '2026-05-07T00:00:00.000Z',
    agentMetadata: {
      name: 'S3ResolverBot',
      version: '1.0.0',
      coreModelHash: 'hash://sha256/model',
      systemPromptHash: 'hash://sha256/prompt'
    },
    verificationMethod: [
      {
        id: 'did:webvh:QmS3Scid:example.com:agents:s3-bot#key-1',
        type: 'Ed25519VerificationKey2020',
        controller: 'did:webvh:QmS3Scid:example.com:organizations:ops-root',
        publicKeyMultibase: 'zabc'
      }
    ],
    authentication: ['did:webvh:QmS3Scid:example.com:agents:s3-bot#key-1'],
    assertionMethod: ['did:webvh:QmS3Scid:example.com:agents:s3-bot#key-1']
  };

  it('should resolve documents from a bucket-backed public URL', async () => {
    const fetchFn = jest.fn().mockResolvedValue({
      ok: true,
      status: 200,
      json: async () => sampleDocument
    });
    const source = new S3CompatibleDIDDocumentSource({
      bucket: 'agent-did-history',
      endpoint: 'https://objects.example.com',
      fetchFn
    });

    const loaded = await source.getByReference('hash://sha256/s3-doc');

    expect(loaded?.id).toEqual(sampleDocument.id);
    expect(fetchFn).toHaveBeenCalledWith(
      'https://objects.example.com/agent-did-history/documents/hash%3A%2F%2Fsha256%2Fs3-doc.json'
    );
  });

  it('should write documents through a presigned upload URL while keeping public reads bucket-backed', async () => {
    const fetchFn = jest.fn().mockResolvedValue({
      ok: true,
      status: 200,
      json: async () => ({})
    });
    const source = new S3CompatibleDIDDocumentSource({
      bucket: 'agent-did-history',
      endpoint: 'https://objects.example.com',
      fetchFn,
      referenceToWriteUrl: (_documentRef, objectKey) => `https://upload.example.com/${objectKey}?signature=document`
    });

    await source.storeByReference('hash://sha256/s3-doc', sampleDocument);

    expect(fetchFn).toHaveBeenCalledWith(
      'https://upload.example.com/documents/hash%3A%2F%2Fsha256%2Fs3-doc.json?signature=document',
      {
        method: 'PUT',
        headers: {
          'content-type': 'application/json; charset=utf-8'
        },
        body: JSON.stringify(sampleDocument)
      }
    );
  });

  it('should resolve and write did logs using did-log specific prefixes and URLs', async () => {
    const didLog = JSON.stringify({ versionId: '1-QmS3Scid', state: sampleDocument });
    const fetchFn = jest
      .fn()
      .mockResolvedValueOnce({ ok: true, status: 200, text: async () => didLog })
      .mockResolvedValueOnce({ ok: true, status: 201, json: async () => ({}) });
    const source = new S3CompatibleDIDDocumentSource({
      bucket: 'agent-did-history',
      endpoint: 'https://objects.example.com',
      fetchFn,
      didLogKeyPrefix: 'histories',
      didLogPublicBaseUrl: 'https://cdn.example.com/agent-did-history',
      didLogReferenceToWriteUrl: (_documentRef, objectKey) => `https://upload.example.com/${objectKey}?signature=history`,
      didLogStoreMethod: 'POST'
    });

    const loadedDidLog = await source.getDidLogByReference('history://s3/bot');
    await source.storeDidLogByReference('history://s3/bot', didLog);

    expect(loadedDidLog).toEqual(didLog);
    expect(fetchFn).toHaveBeenNthCalledWith(1, 'https://cdn.example.com/agent-did-history/histories/history%3A%2F%2Fs3%2Fbot.jsonl');
    expect(fetchFn).toHaveBeenNthCalledWith(
      2,
      'https://upload.example.com/histories/history%3A%2F%2Fs3%2Fbot.jsonl?signature=history',
      {
        method: 'POST',
        headers: {
          'content-type': 'application/jsonl; charset=utf-8'
        },
        body: didLog
      }
    );
  });
});