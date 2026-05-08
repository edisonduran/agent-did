import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { FilesystemDIDDocumentSource } from '../src/resolver/FilesystemDIDDocumentSource';

describe('FilesystemDIDDocumentSource', () => {
  const sampleDocument = {
    '@context': ['https://www.w3.org/ns/did/v1', 'https://agent-did.org/v1'],
    id: 'did:webvh:QmFilesystemScid:example.com:agents:file-bot',
    controller: 'did:webvh:QmFilesystemScid:example.com:organizations:ops-root',
    created: '2026-05-06T00:00:00.000Z',
    updated: '2026-05-06T00:00:00.000Z',
    agentMetadata: {
      name: 'FilesystemResolverBot',
      version: '1.0.0',
      coreModelHash: 'hash://sha256/model',
      systemPromptHash: 'hash://sha256/prompt'
    },
    verificationMethod: [
      {
        id: 'did:webvh:QmFilesystemScid:example.com:agents:file-bot#key-1',
        type: 'Ed25519VerificationKey2020',
        controller: 'did:webvh:QmFilesystemScid:example.com:organizations:ops-root',
        publicKeyMultibase: 'zabc'
      }
    ],
    authentication: ['did:webvh:QmFilesystemScid:example.com:agents:file-bot#key-1'],
    assertionMethod: ['did:webvh:QmFilesystemScid:example.com:agents:file-bot#key-1']
  };

  let tempDir: string;

  beforeEach(async () => {
    tempDir = await fs.mkdtemp(path.join(os.tmpdir(), 'agentdid-fs-source-'));
  });

  afterEach(async () => {
    await fs.rm(tempDir, { recursive: true, force: true });
  });

  it('should store and load a DID document by reference', async () => {
    const source = new FilesystemDIDDocumentSource({
      referenceToPath: (documentRef) => path.join(tempDir, `${encodeURIComponent(documentRef)}.json`)
    });

    await source.storeByReference('hash://sha256/fs-doc', sampleDocument);
    const loaded = await source.getByReference('hash://sha256/fs-doc');

    expect(loaded?.id).toEqual(sampleDocument.id);
    expect(loaded?.updated).toEqual(sampleDocument.updated);
  });

  it('should return null when no filesystem candidate exists', async () => {
    const source = new FilesystemDIDDocumentSource({
      referenceToPath: (documentRef) => path.join(tempDir, `${encodeURIComponent(documentRef)}.json`)
    });

    const loaded = await source.getByReference('hash://sha256/missing');
    expect(loaded).toBeNull();
  });

  it('should store and load a did:webvh DID log by reference', async () => {
    const source = new FilesystemDIDDocumentSource({
      referenceToPath: (documentRef) => path.join(tempDir, `${encodeURIComponent(documentRef)}.jsonl`)
    });
    const didLog = JSON.stringify({ versionId: '1-QmFilesystemScid', state: sampleDocument });

    await source.storeDidLogByReference('history://fs-log', didLog);
    const loaded = await source.getDidLogByReference('history://fs-log');

    expect(loaded).toEqual(didLog);
  });

  it('should fail over across filesystem candidates until one succeeds', async () => {
    const candidatePaths = [
      path.join(tempDir, 'missing.json'),
      path.join(tempDir, 'valid.json')
    ];
    await fs.writeFile(candidatePaths[1], JSON.stringify(sampleDocument, null, 2), 'utf8');

    const source = new FilesystemDIDDocumentSource({
      referenceToPaths: () => candidatePaths
    });
    const loaded = await source.getByReference('hash://sha256/fs-failover');

    expect(loaded?.id).toEqual(sampleDocument.id);
  });
});