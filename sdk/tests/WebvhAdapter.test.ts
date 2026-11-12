import bs58 from 'bs58';
import { hexToBytes } from '@noble/hashes/utils';
import { prepareDataForSigning } from 'didwebvh-ts';
import { LocalKeySigner } from '../src/core/signer';
import {
  createDidWebvhLog,
  deactivateDidWebvhLog,
  DID_WEBVH_PLACEHOLDER,
  didWebvhUpdateKeyFor,
  DidWebvhError,
  deriveDidWebvhLogUrl,
  resolveDidWebvhLog,
  updateDidWebvhLog,
} from '../src/webvh/adapter';

const CONTROLLER_KEY = '1'.repeat(64);
const OTHER_KEY = '2'.repeat(64);
const AGENT_PUBLIC_KEY = 'z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK';

function agentDocument(controller: string): Record<string, unknown> {
  return {
    '@context': ['https://www.w3.org/ns/did/v1', 'https://agent-did.org/v1'],
    id: DID_WEBVH_PLACEHOLDER,
    controller,
    verificationMethod: [
      {
        id: `${DID_WEBVH_PLACEHOLDER}#key-1`,
        type: 'Multikey',
        controller: DID_WEBVH_PLACEHOLDER,
        publicKeyMultibase: AGENT_PUBLIC_KEY,
      },
    ],
    assertionMethod: [`${DID_WEBVH_PLACEHOLDER}#key-1`],
    agentMetadata: { name: 'adapter-test', version: '1.0.0' },
  };
}

async function createLog(created = '2026-01-01T00:00:00Z') {
  return createDidWebvhLog({
    domain: 'agents.example.com',
    pathSegments: ['fleet', 'agent-1'],
    document: agentDocument('did:webvh:controller.example.com'),
    signer: new LocalKeySigner(CONTROLLER_KEY),
    created,
  });
}

function rewriteLastLine(log: string, mutate: (entry: Record<string, any>) => void): string {
  const lines = log.trimEnd().split('\n');
  const entry = JSON.parse(lines[lines.length - 1]);
  mutate(entry);
  lines[lines.length - 1] = JSON.stringify(entry);
  return lines.join('\n') + '\n';
}

describe('did:webvh adapter', () => {
  it('creates a v1.0 log with a self-certifying SCID and the controller as update key', async () => {
    const result = await createLog();
    const controllerKey = await didWebvhUpdateKeyFor(new LocalKeySigner(CONTROLLER_KEY));

    expect(result.did).toBe(`did:webvh:${result.metadata.scid}:agents.example.com:fleet:agent-1`);
    expect(result.document.id).toBe(result.did);
    expect(result.metadata.versionId).toMatch(/^1-Qm/u);
    expect(result.versionNumber).toBe(1);
    expect(result.metadata.updateKeys).toEqual([controllerKey]);
    expect(result.metadata.deactivated).toBe(false);
    expect(result.metadata.ttl).toBe('3600');
    expect((result.document.agentMetadata as { name: string }).name).toBe('adapter-test');

    const [entry] = result.log.trimEnd().split('\n').map((line) => JSON.parse(line));
    expect(entry.parameters.method).toBe('did:webvh:1.0');
    expect(entry.proof[0].cryptosuite).toBe('eddsa-jcs-2022');
    expect(entry.proof[0].verificationMethod).toBe(`did:key:${controllerKey}#${controllerKey}`);
  });

  it('is deterministic for a fixed key and timestamp', async () => {
    const first = await createLog();
    const second = await createLog();
    expect(second.log).toBe(first.log);
  });

  it('appends controller-signed updates and resolves earlier versions', async () => {
    const created = await createLog();
    const nextDocument = { ...created.document, agentMetadata: { name: 'adapter-test', version: '1.1.0' } };
    const updated = await updateDidWebvhLog({
      log: created.log,
      signer: new LocalKeySigner(CONTROLLER_KEY),
      document: nextDocument,
      updated: '2026-01-02T00:00:00Z',
    });

    expect(updated.did).toBe(created.did);
    expect(updated.versionNumber).toBe(2);
    expect(updated.metadata.created).toBe('2026-01-01T00:00:00Z');
    expect(updated.metadata.updated).toBe('2026-01-02T00:00:00Z');
    expect((updated.document.agentMetadata as { version: string }).version).toBe('1.1.0');

    const first = await resolveDidWebvhLog(updated.log, { versionNumber: 1 });
    expect((first.document.agentMetadata as { version: string }).version).toBe('1.0.0');
    expect(first.metadata.updated).toBe('2026-01-01T00:00:00Z');
    expect(first.metadata.updateKeys).toEqual(updated.metadata.updateKeys);
    const byId = await resolveDidWebvhLog(updated.log, { versionId: created.metadata.versionId });
    expect(byId.metadata.versionId).toBe(created.metadata.versionId);
  });

  it('rotates updateKeys so only the new controller key can sign afterwards', async () => {
    const created = await createLog();
    const newSigner = new LocalKeySigner(OTHER_KEY);
    const newKey = await didWebvhUpdateKeyFor(newSigner);

    const rotated = await updateDidWebvhLog({
      log: created.log,
      signer: new LocalKeySigner(CONTROLLER_KEY),
      updateKeys: [newKey],
      updated: '2026-01-02T00:00:00Z',
    });
    expect(rotated.metadata.updateKeys).toEqual([newKey]);

    await expect(
      updateDidWebvhLog({ log: rotated.log, signer: new LocalKeySigner(CONTROLLER_KEY) })
    ).rejects.toMatchObject({ code: 'unauthorized' });

    const next = await updateDidWebvhLog({
      log: rotated.log,
      signer: newSigner,
      document: { ...rotated.document, controller: 'did:webvh:new-controller.example.com' },
    });
    expect(next.versionNumber).toBe(3);
  });

  it('deactivates and refuses further updates', async () => {
    const created = await createLog();
    const deactivated = await deactivateDidWebvhLog({ log: created.log, signer: new LocalKeySigner(CONTROLLER_KEY) });

    expect(deactivated.metadata.deactivated).toBe(true);
    // did:webvh v1.0: a deactivated DID lists no key that could authorize a later entry.
    expect(deactivated.metadata.updateKeys).toEqual([]);
    const resolved = await resolveDidWebvhLog(deactivated.log);
    expect(resolved.metadata.deactivated).toBe(true);
    expect(resolved.document.id).toBe(created.did);
    expect(resolved.versionNumber).toBe(2);

    await expect(
      updateDidWebvhLog({ log: deactivated.log, signer: new LocalKeySigner(CONTROLLER_KEY) })
    ).rejects.toMatchObject({ code: 'invalidInput' });
  });

  it('rejects updates and deactivations from a key outside updateKeys', async () => {
    const created = await createLog();
    await expect(
      updateDidWebvhLog({ log: created.log, signer: new LocalKeySigner(OTHER_KEY), document: created.document })
    ).rejects.toMatchObject({ code: 'unauthorized' });
    await expect(
      deactivateDidWebvhLog({ log: created.log, signer: new LocalKeySigner(OTHER_KEY) })
    ).rejects.toMatchObject({ code: 'unauthorized' });
  });

  it('rejects a log whose state was edited without re-signing', async () => {
    const created = await createLog();
    const tampered = rewriteLastLine(created.log, (entry) => {
      entry.state.controller = 'did:webvh:attacker.example.com';
    });
    await expect(resolveDidWebvhLog(tampered)).rejects.toMatchObject({ code: 'invalidDid' });
  });

  it('rejects an entry re-signed by a key outside updateKeys', async () => {
    const created = await createLog();
    const updated = await updateDidWebvhLog({
      log: created.log,
      signer: new LocalKeySigner(CONTROLLER_KEY),
      document: { ...created.document, controller: 'did:webvh:attacker.example.com' },
      updated: '2026-01-02T00:00:00Z',
    });
    const attacker = new LocalKeySigner(OTHER_KEY);
    const attackerKey = await didWebvhUpdateKeyFor(attacker);

    const forged = await (async () => {
      const lines = updated.log.trimEnd().split('\n');
      const entry = JSON.parse(lines[1]);
      const { proofValue: _ignored, ...template } = entry.proof[0];
      template.verificationMethod = `did:key:${attackerKey}#${attackerKey}`;
      const { proof: _proof, ...unsigned } = entry;
      const data = await prepareDataForSigning(unsigned, template);
      const signature = hexToBytes(await attacker.sign(data));
      entry.proof = [{ ...template, proofValue: `z${bs58.encode(signature)}` }];
      lines[1] = JSON.stringify(entry);
      return lines.join('\n') + '\n';
    })();

    await expect(resolveDidWebvhLog(forged)).rejects.toMatchObject({ code: 'invalidDid' });
  });

  it('rejects a log that does not belong to the expected DID', async () => {
    const created = await createLog();
    await expect(
      resolveDidWebvhLog(created.log, { did: 'did:webvh:QmOther:agents.example.com' })
    ).rejects.toMatchObject({ code: 'invalidDid' });
  });

  it('rejects malformed log text', async () => {
    await expect(resolveDidWebvhLog('')).rejects.toMatchObject({ code: 'notFound' });
    await expect(resolveDidWebvhLog('{not json}\n')).rejects.toMatchObject({ code: 'invalidDid' });
    await expect(resolveDidWebvhLog('[1,2]\n')).rejects.toMatchObject({ code: 'invalidDid' });
    await expect(resolveDidWebvhLog('{"versionId":"1-x"}\n')).rejects.toMatchObject({ code: 'invalidDid' });
  });

  it('rejects invalid resolution options', async () => {
    const created = await createLog();
    await expect(resolveDidWebvhLog(created.log, { versionTime: 'not-a-date' })).rejects.toMatchObject({
      code: 'invalidOptions',
    });
    await expect(resolveDidWebvhLog(created.log, { versionNumber: 5 })).rejects.toBeInstanceOf(DidWebvhError);
  });

  it.each([
    ['', 'empty'],
    ['127.0.0.1', 'IPv4 literal'],
    ['localhost', 'single label'],
    ['Agents.Example.com', 'uppercase'],
    ['agents_example.com', 'underscore'],
    ['agents.example.com:0', 'port zero'],
    ['agents.example.com:70000', 'port out of range'],
    ['münchen.example', 'non-ASCII'],
    ['a.example.com', 'one-character label'],
    ['agents.1example.com', 'label starting with a digit'],
  ])('rejects domain %p (%s)', async (domain) => {
    await expect(
      createDidWebvhLog({ domain, document: agentDocument('x'), signer: new LocalKeySigner(CONTROLLER_KEY) })
    ).rejects.toMatchObject({ code: 'invalidInput' });
  });

  it.each([['..'], ['.'], ['a/b'], ['a:b'], ['']])('rejects path segment %p', async (segment) => {
    await expect(
      createDidWebvhLog({
        domain: 'agents.example.com',
        pathSegments: [segment],
        document: agentDocument('x'),
        signer: new LocalKeySigner(CONTROLLER_KEY),
      })
    ).rejects.toMatchObject({ code: 'invalidInput' });
  });

  it('accepts a host with a port', async () => {
    const result = await createDidWebvhLog({
      domain: 'agents.example.com:8443',
      document: agentDocument('x'),
      signer: new LocalKeySigner(CONTROLLER_KEY),
      created: '2026-01-01T00:00:00Z',
    });
    expect(result.did).toBe(`did:webvh:${result.metadata.scid}:agents.example.com%3A8443`);
  });

  it.each([
    ['2026-01-01', 'date only'],
    ['2026-01-01T00:00:00.123Z', 'fractional seconds'],
    ['2026-01-01T00:00:00+01:00', 'non-UTC offset'],
    ['2026-02-30T00:00:00Z', 'invalid calendar date'],
    ['2999-01-01T00:00:00Z', 'future'],
  ])('rejects created %p (%s)', async (created) => {
    await expect(
      createDidWebvhLog({
        domain: 'agents.example.com',
        document: agentDocument('x'),
        signer: new LocalKeySigner(CONTROLLER_KEY),
        created,
      })
    ).rejects.toMatchObject({ code: 'invalidInput' });
  });

  it('rejects an update timestamp too far in the future', async () => {
    const created = await createLog();
    await expect(
      updateDidWebvhLog({ log: created.log, signer: new LocalKeySigner(CONTROLLER_KEY), updated: '2999-01-01T00:00:00Z' })
    ).rejects.toMatchObject({ code: 'invalidInput' });
  });

  it('rejects invalid replacement updateKeys', async () => {
    const created = await createLog();
    const signer = new LocalKeySigner(CONTROLLER_KEY);
    await expect(updateDidWebvhLog({ log: created.log, signer, updateKeys: [] })).rejects.toMatchObject({
      code: 'invalidInput',
    });
    await expect(updateDidWebvhLog({ log: created.log, signer, updateKeys: ['z123'] })).rejects.toMatchObject({
      code: 'invalidInput',
    });
  });

  it('wraps library failures as DidWebvhError', async () => {
    await expect(
      createDidWebvhLog({
        domain: 'agents.example.com',
        document: { id: 'did:example:not-a-placeholder' },
        signer: new LocalKeySigner(CONTROLLER_KEY),
      })
    ).rejects.toMatchObject({ code: 'invalidInput' });
  });

  it('returns the signed state separately from the resolved document', async () => {
    const created = await createLog();
    expect(created.state.service).toBeUndefined();
    expect(Array.isArray(created.document.service)).toBe(true);
    expect({ ...created.document, service: undefined }).toEqual({ ...created.state, service: undefined });
  });

  describe('deriveDidWebvhLogUrl', () => {
    const scid = 'QmUy89VrfryQ254CeHZzQfmcKqByPoKNGqYykP3SeXuegQ';

    it.each([
      [`did:webvh:${scid}:example.com`, 'https://example.com/.well-known/did.jsonl'],
      [`did:webvh:${scid}:example.com:fleet:agent-1`, 'https://example.com/fleet/agent-1/did.jsonl'],
      [`did:webvh:${scid}:agents.example.com%3A8443`, 'https://agents.example.com:8443/.well-known/did.jsonl'],
      [`did:webvh:${scid}:agents.example.com%3A8443:a:b`, 'https://agents.example.com:8443/a/b/did.jsonl'],
    ])('maps %s', (did, url) => {
      expect(deriveDidWebvhLogUrl(did)).toBe(url);
    });

    it('maps DIDs created by the adapter', async () => {
      const created = await createLog();
      expect(deriveDidWebvhLogUrl(created.did)).toBe('https://agents.example.com/fleet/agent-1/did.jsonl');
    });

    it.each([
      ['not webvh', `did:web:example.com`],
      ['empty SCID', 'did:webvh::example.com'],
      ['non-base58 SCID', 'did:webvh:Qm0000:example.com'],
      ['missing host', `did:webvh:${scid}`],
      ['IPv4 host', `did:webvh:${scid}:127.0.0.1`],
      ['encoded IPv4 host', `did:webvh:${scid}:127%2E0%2E0%2E1`],
      ['lowercase port escape', `did:webvh:${scid}:example.com%3a8443`],
      ['port zero', `did:webvh:${scid}:example.com%3A0`],
      ['uppercase host', `did:webvh:${scid}:Example.com`],
      ['single-label host', `did:webvh:${scid}:localhost`],
      ['dot-dot segment', `did:webvh:${scid}:example.com:..:admin`],
      ['encoded dot-dot segment', `did:webvh:${scid}:example.com:%2E%2E:admin`],
      ['encoded slash', `did:webvh:${scid}:example.com:a%2Fb`],
      ['empty segment', `did:webvh:${scid}:example.com::a`],
      ['fragment', `did:webvh:${scid}:example.com#key-1`],
      ['query', `did:webvh:${scid}:example.com?versionId=1`],
      ['path', `did:webvh:${scid}:example.com/whois`],
    ])('rejects a DID with %s', (_label, did) => {
      expect(() => deriveDidWebvhLogUrl(did)).toThrow(DidWebvhError);
    });
  });
});
