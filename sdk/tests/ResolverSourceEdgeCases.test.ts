import http from 'node:http';
import type { AddressInfo } from 'node:net';
import { AwsSigV4S3DIDDocumentSource } from '../src/resolver/AwsSigV4S3DIDDocumentSource';
import { BearerTokenHttpDIDDocumentSource } from '../src/resolver/BearerTokenHttpDIDDocumentSource';
import { HttpDIDDocumentSource } from '../src/resolver/HttpDIDDocumentSource';
import { InMemoryDIDResolver } from '../src/resolver/InMemoryDIDResolver';
import { JsonRpcDIDDocumentSource } from '../src/resolver/JsonRpcDIDDocumentSource';
import { S3CompatibleDIDDocumentSource } from '../src/resolver/S3CompatibleDIDDocumentSource';
import type { AgentDIDDocument } from '../src';

// Edge cases of the DID document sources that the resolver tests do not reach (C-QA-2).

const DID = 'did:webvh:QmEdgeScid:example.com:agents:edge-bot';
const document = {
  '@context': ['https://www.w3.org/ns/did/v1', 'https://agent-did.org/v1'],
  id: DID,
  controller: 'did:webvh:QmEdgeScid:example.com:organizations:ops-root',
  created: '2026-05-06T00:00:00.000Z',
  updated: '2026-05-06T00:00:00.000Z',
  agentMetadata: { name: 'EdgeBot', version: '1.0.0' },
  verificationMethod: [
    { id: `${DID}#key-1`, type: 'Multikey', controller: `${DID}`, publicKeyMultibase: 'zabc' }
  ],
  authentication: [`${DID}#key-1`],
  assertionMethod: [`${DID}#key-1`]
} as unknown as AgentDIDDocument;

describe('InMemoryDIDResolver', () => {
  it('forgets a removed document', async () => {
    const resolver = new InMemoryDIDResolver();
    resolver.registerDocument(document);
    resolver.remove(DID);
    await expect(resolver.resolve(DID)).rejects.toThrow('DID not found');
  });
});

describe('HttpDIDDocumentSource', () => {
  const url = 'https://dids.example/doc.json';

  it('returns null when every did:webvh log endpoint answers 404', async () => {
    const source = new HttpDIDDocumentSource({ fetchFn: jest.fn().mockResolvedValue({ ok: false, status: 404 }) });
    await expect(source.getDidLogByReference(url)).resolves.toBeNull();
  });

  it('refuses to store without a target, to a blocked target, or when the server refuses', async () => {
    const noTarget = new HttpDIDDocumentSource({ fetchFn: jest.fn(), referenceToUrls: () => [] });
    await expect(noTarget.storeByReference(url, document)).rejects.toThrow('No HTTP target candidates');

    const blocked = new HttpDIDDocumentSource({ fetchFn: jest.fn() });
    await expect(blocked.storeDidLogByReference('http://127.0.0.1/did.jsonl', 'log')).rejects.toThrow('blocked by SSRF policy');

    const refused = new HttpDIDDocumentSource({ fetchFn: jest.fn().mockResolvedValue({ ok: false, status: 403 }) });
    await expect(refused.storeByReference(url, document)).rejects.toThrow('HTTP 403');
  });

  it('reads a log exposed only as JSON text and rejects bodies it cannot read', async () => {
    const asJson = new HttpDIDDocumentSource({
      fetchFn: jest.fn().mockResolvedValue({ ok: true, status: 200, json: async () => 'log text' })
    });
    await expect(asJson.getDidLogByReference(url)).resolves.toBe('log text');

    const unreadableLog = new HttpDIDDocumentSource({
      fetchFn: jest.fn().mockResolvedValue({ ok: true, status: 200, json: async () => ({}) })
    });
    await expect(unreadableLog.getDidLogByReference(url)).rejects.toThrow('readable text body');

    const noJson = new HttpDIDDocumentSource({
      fetchFn: jest.fn().mockResolvedValue({ ok: true, status: 200, text: async () => '{}' })
    });
    await expect(noJson.getByReference(url)).rejects.toThrow('readable JSON body');
  });
});

describe('JsonRpcDIDDocumentSource', () => {
  it('needs an endpoint', () => {
    expect(() => new JsonRpcDIDDocumentSource({})).toThrow('at least one endpoint');
  });

  it('treats an empty result as not found', async () => {
    const source = new JsonRpcDIDDocumentSource({
      endpoint: 'https://rpc.example',
      transport: async () => ({ ok: true, status: 200, json: async () => ({ jsonrpc: '2.0', id: 1, result: null }) })
    });
    await expect(source.getByReference('ref')).resolves.toBeNull();
  });

  it('posts through the SSRF-safe fetch by default', async () => {
    let received: { method?: string; body: string } = { body: '' };
    const server = http.createServer((request, response) => {
      let body = '';
      request.on('data', (chunk) => (body += chunk));
      request.on('end', () => {
        received = { method: request.method, body };
        response.setHeader('content-type', 'application/json');
        response.end(JSON.stringify({ jsonrpc: '2.0', id: 1, result: document }));
      });
    });
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
    try {
      const { port } = server.address() as AddressInfo;
      const source = new JsonRpcDIDDocumentSource({
        endpoint: `http://127.0.0.1:${port}/rpc`,
        httpSecurity: { allowPrivateTargets: true }
      });
      await expect(source.getByReference('ref')).resolves.toMatchObject({ id: DID });
      expect(received.method).toBe('POST');
      expect(JSON.parse(received.body)).toMatchObject({ method: 'agent_resolveDocumentRef', params: ['ref'] });
    } finally {
      await new Promise((resolve) => server.close(resolve));
    }
  });
});

describe('S3CompatibleDIDDocumentSource', () => {
  it('builds virtual-hosted URLs and writes to the read URL when no write mapping is given', async () => {
    const fetchFn = jest.fn().mockResolvedValue({ ok: true, status: 200, json: async () => ({}) });
    const source = new S3CompatibleDIDDocumentSource({
      bucket: 'agents',
      endpoint: 'https://s3.example.com/base?x=1#f',
      forcePathStyle: false,
      fetchFn
    });

    await source.storeByReference('ref', document);

    expect(fetchFn).toHaveBeenCalledWith('https://agents.s3.example.com/base/documents/ref.json', expect.anything());
  });
});

describe('BearerTokenHttpDIDDocumentSource', () => {
  const ok = () => jest.fn().mockResolvedValue({ ok: true, status: 200, json: async () => ({}), text: async () => '' });

  it('rejects an allowedOrigins entry that is not a URL', () => {
    expect(() => new BearerTokenHttpDIDDocumentSource({ allowedOrigins: ['not a url'], token: 't' })).toThrow('not an http(s) origin');
  });

  it('sends the credential on writes too', async () => {
    const fetchFn = ok();
    const source = new BearerTokenHttpDIDDocumentSource({ allowedOrigins: ['https://dids.example'], token: 't', fetchFn });
    await source.storeByReference('https://dids.example/doc.json', document);
    expect(fetchFn.mock.calls[0][1].headers.authorization).toBe('Bearer t');
  });

  it('refuses to send an empty token or no token at all', async () => {
    const empty = new BearerTokenHttpDIDDocumentSource({ allowedOrigins: ['https://dids.example'], getToken: async () => '', fetchFn: ok() });
    await expect(empty.storeByReference('https://dids.example/doc.json', document)).rejects.toThrow('empty token');

    const none = new BearerTokenHttpDIDDocumentSource({ allowedOrigins: ['https://dids.example'], fetchFn: ok() });
    await expect(none.storeByReference('https://dids.example/doc.json', document)).rejects.toThrow('requires token or getToken');
  });
});

describe('AwsSigV4S3DIDDocumentSource', () => {
  it('signs writes and log reads, encoding the characters encodeURIComponent leaves', async () => {
    const fetchFn = jest.fn().mockResolvedValue({ ok: true, status: 200, json: async () => ({}), text: async () => 'log' });
    const source = new AwsSigV4S3DIDDocumentSource({
      bucket: 'agent-did-history',
      endpoint: 'https://s3.us-east-1.amazonaws.com',
      region: 'us-east-1',
      accessKeyId: 'AKIDEXAMPLE',
      secretAccessKey: 'wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY',
      now: () => new Date('2026-05-07T12:34:56.000Z'),
      fetchFn
    });

    await source.storeByReference("ref(1)!'*", document);
    await expect(source.getDidLogByReference('ref')).resolves.toBe('log');

    const [writeUrl, writeInit] = fetchFn.mock.calls[0];
    expect(writeUrl).toContain('ref(1)!');
    expect(writeInit.headers.authorization).toMatch(/^AWS4-HMAC-SHA256 /u);
    expect(fetchFn.mock.calls[1][1].headers.authorization).toMatch(/^AWS4-HMAC-SHA256 /u);
  });
});
