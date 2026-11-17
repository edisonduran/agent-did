import { WebvhDIDDocumentSource } from '../src/resolver/WebvhDIDDocumentSource';
import { DocumentIntegrityError } from '../src/resolver/types';
import { LocalKeySigner } from '../src/core/signer';
import { createDidWebvhLog, DID_WEBVH_PLACEHOLDER, updateDidWebvhLog } from '../src/webvh/adapter';
import { createDidWebvhWitnessProof } from '../src';
import { encodePublicKeyMultibase } from '../src/crypto/multibase';
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

describe('WebvhDIDDocumentSource: witnesses, fetch failures and response bodies', () => {
  const url = 'https://example.com/agents/webvh-bot/did.jsonl';
  const logUrl = 'https://witness.example/did.jsonl';

  async function witnessedControllerLog() {
    const [signer] = LocalKeySigner.generate();
    const [witness] = LocalKeySigner.generate();
    const witnessDid = `did:key:${encodePublicKeyMultibase(await witness.getPublicKey())}`;
    const D = DID_WEBVH_PLACEHOLDER;
    return createDidWebvhLog({
      domain: 'witness.example',
      document: {
        '@context': ['https://www.w3.org/ns/did/v1', 'https://w3id.org/security/multikey/v1'],
        id: D,
        verificationMethod: [
          { id: `${D}#key-1`, type: 'Multikey', controller: D, publicKeyMultibase: encodePublicKeyMultibase(await signer.getPublicKey()) }
        ],
        assertionMethod: [`${D}#key-1`]
      },
      signer,
      witness: { threshold: 1, witnesses: [witnessDid] },
      collectWitnessProofs: async (request) => [
        await createDidWebvhWitnessProof({ log: request.log, witnessFile: request.witnessFile, signer: witness })
      ]
    });
  }

  it('fetches did-witness.json next to a witnessed log and still applies the Agent-DID document guard', async () => {
    const created = await witnessedControllerLog();
    const files: Record<string, string> = {
      [logUrl]: created.log,
      'https://witness.example/did-witness.json': created.witnessFile as string
    };
    const fetchFn = jest.fn(async (url: string) => (files[url] ? textResponse(files[url]) : textResponse('', 404)));
    const source = new WebvhDIDDocumentSource({ fetchFn });

    // The witnessed log verifies; its state is a plain controller document, not an Agent-DID document
    await expect(source.getByReference(logUrl)).rejects.toThrow('is not an Agent-DID document');
    expect(fetchFn).toHaveBeenCalledWith('https://witness.example/did-witness.json');
    await expect(source.getDidWitnessFileByReference('https://witness.example/did-witness.json')).resolves.toBe(
      created.witnessFile
    );
  });

  it('fails closed when a witnessed log has no did-witness.json or no did.jsonl name to locate it', async () => {
    const created = await witnessedControllerLog();
    const onlyLog = new WebvhDIDDocumentSource({
      fetchFn: jest.fn(async (url: string) => (url === logUrl ? textResponse(created.log) : textResponse('', 404)))
    });
    await expect(onlyLog.getByReference(logUrl)).rejects.toThrow('no did-witness.json');

    const elsewhere = new WebvhDIDDocumentSource({ fetchFn: jest.fn().mockResolvedValue(textResponse(created.log)) });
    await expect(elsewhere.getByReference('https://witness.example/log')).rejects.toThrow('cannot be located');
  });

  it('reports SSRF-blocked targets and network errors instead of "not found"', async () => {
    const blocked = new WebvhDIDDocumentSource({ fetchFn: jest.fn() });
    await expect(blocked.getDidLogByReference('http://127.0.0.1/did.jsonl')).rejects.toThrow('blocked by SSRF policy');

    const failing = new WebvhDIDDocumentSource({ fetchFn: jest.fn().mockRejectedValue('socket hang up') });
    await expect(failing.getDidLogByReference(url)).rejects.toThrow('socket hang up');
  });

  it('reads a body exposed only as JSON text and rejects a body it cannot read', async () => {
    const asJson = new WebvhDIDDocumentSource({
      fetchFn: jest.fn().mockResolvedValue({ ok: true, status: 200, json: async () => 'log text' })
    });
    await expect(asJson.getDidLogByReference(url)).resolves.toBe('log text');

    const unreadable = new WebvhDIDDocumentSource({
      fetchFn: jest.fn().mockResolvedValue({ ok: true, status: 200, json: async () => ({}) })
    });
    await expect(unreadable.getDidLogByReference(url)).rejects.toThrow('readable text body');
  });
});
