import { WebvhDIDDocumentSource } from '../src/resolver/WebvhDIDDocumentSource';
import { DocumentIntegrityError } from '../src/resolver/types';
import { LocalKeySigner } from '../src/core/signer';
import { updateDidWebvhLog } from '../src/webvh/adapter';
import { createAgentWebvhLog, tamperLastState, TEST_CONTROLLER_KEY, textResponse } from './helpers/webvhAgentLog';

describe('WebvhDIDDocumentSource', () => {
  const url = 'https://example.com/agents/webvh-bot/did.jsonl';

  it('should verify the log and return the latest state', async () => {
    const created = await createAgentWebvhLog('example.com', ['agents', 'webvh-bot']);
    const updated = await updateDidWebvhLog({
      log: created.log,
      signer: new LocalKeySigner(TEST_CONTROLLER_KEY),
      document: { ...created.state, updated: '2026-01-02T00:00:00Z' },
      updated: '2026-01-02T00:00:00Z'
    });
    const fetchFn = jest.fn().mockResolvedValue(textResponse(updated.log));

    const source = new WebvhDIDDocumentSource({ fetchFn });
    const result = await source.getByReference(url);

    expect(result?.id).toEqual(created.did);
    expect(result?.updated).toEqual('2026-01-02T00:00:00Z');
    // The signed state is returned, without the resolver's implicit services.
    expect((result as unknown as { service?: unknown }).service).toBeUndefined();
  });

  it('should reject a log that fails verification instead of returning its state', async () => {
    const created = await createAgentWebvhLog('example.com', ['agents', 'webvh-bot']);
    const tampered = tamperLastState(created.log, (state) => {
      state.controller = 'did:webvh:QmAttacker:attacker.example';
    });
    const source = new WebvhDIDDocumentSource({ fetchFn: jest.fn().mockResolvedValue(textResponse(tampered)) });

    await expect(source.getByReference(url)).rejects.toBeInstanceOf(DocumentIntegrityError);
  });

  it('should reject a log in the pre-v1.0 Agent-DID format', async () => {
    const created = await createAgentWebvhLog('example.com', ['agents', 'webvh-bot']);
    const legacyLog = JSON.stringify({ versionId: `1-${created.metadata.scid}`, state: created.state });
    const source = new WebvhDIDDocumentSource({ fetchFn: jest.fn().mockResolvedValue(textResponse(legacyLog)) });

    await expect(source.getByReference(url)).rejects.toBeInstanceOf(DocumentIntegrityError);
  });

  it('should return the raw log text from getDidLogByReference', async () => {
    const created = await createAgentWebvhLog('example.com', ['agents', 'webvh-bot']);
    const source = new WebvhDIDDocumentSource({ fetchFn: jest.fn().mockResolvedValue(textResponse(created.log)) });

    await expect(source.getDidLogByReference(url)).resolves.toEqual(created.log);
  });

  it('should return null on 404', async () => {
    const source = new WebvhDIDDocumentSource({ fetchFn: jest.fn().mockResolvedValue(textResponse('', 404)) });

    await expect(source.getByReference('https://example.com/.well-known/did.jsonl')).resolves.toBeNull();
    await expect(source.getDidLogByReference('https://example.com/.well-known/did.jsonl')).resolves.toBeNull();
  });

  it('should try candidate did:webvh URLs until one succeeds', async () => {
    const created = await createAgentWebvhLog('example.com', ['agents', 'webvh-bot']);
    const candidateUrls = [
      'https://primary.example/agents/webvh-bot/did.jsonl',
      'https://secondary.example/agents/webvh-bot/did.jsonl',
      'https://tertiary.example/agents/webvh-bot/did.jsonl'
    ];
    const fetchFn = jest.fn(async (candidate: string) => {
      if (candidate === candidateUrls[0]) return textResponse('', 503);
      if (candidate === candidateUrls[1]) return textResponse('', 404);
      return textResponse(created.log);
    });

    const source = new WebvhDIDDocumentSource({ fetchFn, referenceToUrls: () => candidateUrls });
    const result = await source.getByReference(url);

    expect(result?.id).toEqual(created.did);
    expect(fetchFn.mock.calls.map(([candidate]) => candidate)).toEqual(candidateUrls);
  });

  it('should throw when every endpoint fails with a non-404 error', async () => {
    const source = new WebvhDIDDocumentSource({ fetchFn: jest.fn().mockResolvedValue(textResponse('', 503)) });

    await expect(source.getDidLogByReference(url)).rejects.toThrow(/HTTP 503/u);
  });
});
