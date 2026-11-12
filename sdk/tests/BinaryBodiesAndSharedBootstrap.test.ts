/**
 * Binary request bodies in `Content-Digest`, concurrent creates sharing one bootstrap controller, and the default
 * paths of `FilesystemDIDDocumentSource`. Python: sdk-python/tests/test_binary_bodies_and_shared_bootstrap.py.
 */
import { mkdtempSync, readdirSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  AgentDidClient,
  AgentIdentity,
  FilesystemDIDDocumentSource,
  LocalKeySigner,
  WebvhDIDDocumentSource
} from '../src';
import { computeContentDigest } from '../src/core/http-profile';

describe('binary request bodies', () => {
  it('hashes bytes as they are and a string as UTF-8', () => {
    const bytes = new Uint8Array([0xff, 0x00, 0xfe, 0x80]);
    expect(computeContentDigest(bytes)).not.toBe(computeContentDigest(Buffer.from(bytes).toString('utf8')));
    expect(computeContentDigest('héllo')).toBe(computeContentDigest(new TextEncoder().encode('héllo')));
    expect(computeContentDigest()).toBe(computeContentDigest(new Uint8Array()));
  });

  it('signs and verifies a request whose body is not valid UTF-8', async () => {
    const client = new AgentDidClient();
    const [wallet] = LocalKeySigner.generate();
    const identity = new AgentIdentity({ controllerSigner: wallet, client });
    const { document, agentPrivateKey } = await identity.create({ name: 'BinaryBot', coreModel: 'm', systemPrompt: 'p' });
    const body = new Uint8Array([0xff, 0x00, 0xfe, 0x80, 0x01]);
    const url = 'https://api.example.com/v1/upload';
    const headers = await identity.signHttpRequest({
      method: 'PUT',
      url,
      body,
      agentPrivateKey,
      agentDid: document.id,
      verificationMethodId: document.authentication[0]
    });

    expect((await client.verifyHttpRequestSignatureDetailed({ method: 'PUT', url, body, headers })).ok).toBe(true);
    const changed = new Uint8Array(body);
    changed[4] = 0x02;
    const result = await client.verifyHttpRequestSignatureDetailed({ method: 'PUT', url, body: changed, headers });
    expect(result).toEqual({ ok: false, reason: 'digest_mismatch' });
  });
});

describe('concurrent creates', () => {
  it('share one bootstrap controller', async () => {
    const client = new AgentDidClient();
    const [wallet] = LocalKeySigner.generate();
    const identity = new AgentIdentity({ controllerSigner: wallet, client });
    const created = await Promise.all(
      ['ConcurrentOne', 'ConcurrentTwo', 'ConcurrentThree'].map((name) =>
        identity.create({ name, coreModel: 'm', systemPrompt: 'p' })
      )
    );

    expect(new Set(created.map((result) => result.document.controller)).size).toBe(1);
    // the controller key is returned once, to the create that made the controller
    expect(created.filter((result) => result.controllerPrivateKey).length).toBe(1);
  });
});

describe('FilesystemDIDDocumentSource default paths', () => {
  it('requires a root directory or a mapping instead of using a reference as a path', () => {
    expect(() => new FilesystemDIDDocumentSource()).toThrow(TypeError);
    expect(() => new FilesystemDIDDocumentSource({})).toThrow(TypeError);
  });

  it('keeps every reference inside the root directory', async () => {
    const root = mkdtempSync(join(tmpdir(), 'agent-did-fs-'));
    try {
      const source = new FilesystemDIDDocumentSource({ rootDirectory: root });
      const [wallet] = LocalKeySigner.generate();
      const { document } = await new AgentIdentity({ controllerSigner: wallet, client: new AgentDidClient() }).create({
        name: 'FsBot',
        coreModel: 'm',
        systemPrompt: 'p'
      });
      for (const reference of ['hash://sha256/abc', '../../escape', '/etc/passwd', 'C:\\Windows\\win.ini', '..']) {
        await source.storeByReference(reference, document);
        expect((await source.getByReference(reference))?.id).toBe(document.id);
      }
      const files = readdirSync(root);
      expect(files).toHaveLength(5);
      expect(files.every((file) => /^[A-Za-z0-9._-]+\.json$/u.test(file) && !file.startsWith('..'))).toBe(true);
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });
});

describe('exports', () => {
  it('exports WebvhDIDDocumentSource', () => {
    expect(typeof WebvhDIDDocumentSource).toBe('function');
  });
});
