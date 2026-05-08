import { ethers } from 'ethers';
import { AwsSigV4S3DIDDocumentSource } from '../src/resolver/AwsSigV4S3DIDDocumentSource';

describe('AwsSigV4S3DIDDocumentSource', () => {
  const sampleDocument = {
    '@context': ['https://www.w3.org/ns/did/v1', 'https://agent-did.org/v1'],
    id: 'did:webvh:QmAwsScid:example.com:agents:aws-bot',
    controller: 'did:webvh:QmAwsScid:example.com:organizations:ops-root',
    created: '2026-05-07T00:00:00.000Z',
    updated: '2026-05-07T00:00:00.000Z',
    agentMetadata: {
      name: 'AwsResolverBot',
      version: '1.0.0',
      coreModelHash: 'hash://sha256/model',
      systemPromptHash: 'hash://sha256/prompt'
    },
    verificationMethod: [
      {
        id: 'did:webvh:QmAwsScid:example.com:agents:aws-bot#key-1',
        type: 'Ed25519VerificationKey2020',
        controller: 'did:webvh:QmAwsScid:example.com:organizations:ops-root',
        publicKeyMultibase: 'zabc'
      }
    ],
    authentication: ['did:webvh:QmAwsScid:example.com:agents:aws-bot#key-1'],
    assertionMethod: ['did:webvh:QmAwsScid:example.com:agents:aws-bot#key-1']
  };
  const fixedDate = new Date('2026-05-07T12:34:56.000Z');

  it('should sign GET requests with AWS SigV4 headers', async () => {
    const fetchFn = jest.fn().mockResolvedValue({
      ok: true,
      status: 200,
      json: async () => sampleDocument
    });
    const source = new AwsSigV4S3DIDDocumentSource({
      bucket: 'agent-did-history',
      endpoint: 'https://s3.us-east-1.amazonaws.com',
      region: 'us-east-1',
      accessKeyId: 'AKIDEXAMPLE',
      secretAccessKey: 'wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY',
      now: () => fixedDate,
      fetchFn
    });

    const loaded = await source.getByReference('hash://sha256/aws-doc');
    const [, init] = fetchFn.mock.calls[0];

    expect(loaded?.id).toEqual(sampleDocument.id);
    expect(fetchFn).toHaveBeenCalledWith(
      'https://s3.us-east-1.amazonaws.com/agent-did-history/documents/hash%3A%2F%2Fsha256%2Faws-doc.json',
      expect.objectContaining({
        method: 'GET',
        headers: expect.objectContaining({
          host: 's3.us-east-1.amazonaws.com',
          'x-amz-date': '20260507T123456Z',
          'x-amz-content-sha256': ethers.sha256(ethers.toUtf8Bytes('')).slice(2),
          authorization: expect.stringContaining('Credential=AKIDEXAMPLE/20260507/us-east-1/s3/aws4_request')
        })
      })
    );
    expect(init.headers.authorization).toContain('SignedHeaders=host;x-amz-content-sha256;x-amz-date');
  });

  it('should sign did-log writes and include session token when present', async () => {
    const fetchFn = jest.fn().mockResolvedValue({
      ok: true,
      status: 200,
      json: async () => ({})
    });
    const didLog = JSON.stringify({ versionId: '1-QmAwsScid', state: sampleDocument });
    const source = new AwsSigV4S3DIDDocumentSource({
      bucket: 'agent-did-history',
      endpoint: 'https://s3.us-east-1.amazonaws.com',
      region: 'us-east-1',
      accessKeyId: 'AKIDEXAMPLE',
      secretAccessKey: 'wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY',
      sessionToken: 'session-token-example',
      didLogStoreMethod: 'POST',
      now: () => fixedDate,
      fetchFn
    });

    await source.storeDidLogByReference('history://aws/bot', didLog);

    expect(fetchFn).toHaveBeenCalledWith(
      'https://s3.us-east-1.amazonaws.com/agent-did-history/did-logs/history%3A%2F%2Faws%2Fbot.jsonl',
      expect.objectContaining({
        method: 'POST',
        headers: expect.objectContaining({
          'content-type': 'application/jsonl; charset=utf-8',
          'x-amz-date': '20260507T123456Z',
          'x-amz-security-token': 'session-token-example',
          'x-amz-content-sha256': ethers.sha256(ethers.toUtf8Bytes(didLog)).slice(2),
          authorization: expect.stringContaining('SignedHeaders=content-type;host;x-amz-content-sha256;x-amz-date;x-amz-security-token')
        }),
        body: didLog
      })
    );
  });
});