/**
 * did:webvh witnesses (ADR-007): witness configuration at create and update, approvals collected before an entry is
 * returned, and resolution that fails closed without them. The DIF suite scenarios run in WebvhTestSuite.test.ts.
 * The Python SDK runs the same cases in sdk-python/tests/test_witnesses.py.
 */
import {
  AgentDidClient,
  AgentIdentity,
  createDidWebvhWitnessProof,
  DidWebvhWitnessCollector,
  InMemoryAgentRegistry,
  LocalKeySigner
} from '../src';
import { encodePublicKeyMultibase } from '../src/crypto/multibase';
import {
  createDidWebvhLog,
  deactivateDidWebvhLog,
  deriveDidWebvhLogUrl,
  deriveDidWebvhWitnessUrl,
  DID_WEBVH_PLACEHOLDER,
  DidWebvhError,
  didWebvhLogRequiresWitnesses,
  resolveDidWebvhLog,
  updateDidWebvhLog
} from '../src/webvh/adapter';
import { checkDidWebvhKeyAtTime } from '../src/verification/key-at-time';

const D = DID_WEBVH_PLACEHOLDER;

async function didKeyOf(signer: LocalKeySigner): Promise<string> {
  return `did:key:${encodePublicKeyMultibase(await signer.getPublicKey())}`;
}

/** Witnesses that approve in process, and the collector a controller would call. */
async function witnesses(count: number) {
  const signers = Array.from({ length: count }, () => LocalKeySigner.generate()[0]);
  const dids = await Promise.all(signers.map(didKeyOf));
  // Asks the members of the rule that governs the entry, like a controller contacting its witnesses.
  const approving = (subset: LocalKeySigner[] = signers): DidWebvhWitnessCollector =>
    async (request) =>
      Promise.all(
        subset
          .filter((signer) => request.witness.witnesses.includes(dids[signers.indexOf(signer)]))
          .map((signer) => createDidWebvhWitnessProof({ log: request.log, witnessFile: request.witnessFile, signer }))
      );
  return { signers, dids, collect: approving(), approving };
}

async function controllerDocument(signer: LocalKeySigner): Promise<Record<string, unknown>> {
  return {
    '@context': ['https://www.w3.org/ns/did/v1', 'https://w3id.org/security/multikey/v1'],
    id: D,
    verificationMethod: [
      { id: `${D}#key-1`, type: 'Multikey', controller: D, publicKeyMultibase: encodePublicKeyMultibase(await signer.getPublicKey()) }
    ],
    assertionMethod: [`${D}#key-1`],
    capabilityInvocation: [`${D}#key-1`]
  };
}

async function witnessedLog(count = 2, threshold = 2) {
  const [signer] = LocalKeySigner.generate();
  const w = await witnesses(count);
  const created = await createDidWebvhLog({
    domain: 'witness.example',
    document: await controllerDocument(signer),
    signer,
    witness: { threshold, witnesses: w.dids },
    collectWitnessProofs: w.collect
  });
  return { signer, w, created };
}

describe('did:webvh witnesses: adapter', () => {
  it('creates a witnessed log, returns its did-witness.json and exposes the rule in the metadata', async () => {
    const { w, created } = await witnessedLog();

    expect(created.witnessFile).toBeDefined();
    const file = JSON.parse(created.witnessFile as string) as { versionId: string; proof: unknown[] }[];
    expect(file).toEqual([{ versionId: created.metadata.versionId, proof: expect.any(Array) }]);
    expect(file[0].proof).toHaveLength(2);
    expect(created.metadata.witnessThreshold).toBe('2');
    expect(created.metadata.witnesses).toEqual(w.dids);
    expect(didWebvhLogRequiresWitnesses(created.log)).toBe(true);
    expect(deriveDidWebvhWitnessUrl(created.did)).toBe('https://witness.example/.well-known/did-witness.json');
  });

  it('reports no witnesses for a log without them', async () => {
    const [signer] = LocalKeySigner.generate();
    const created = await createDidWebvhLog({ domain: 'plain.example', document: await controllerDocument(signer), signer });

    expect(created.witnessFile).toBeUndefined();
    expect(created.metadata.witnessThreshold).toBe('0');
    expect(created.metadata.witnesses).toEqual([]);
    expect(didWebvhLogRequiresWitnesses(created.log)).toBe(false);
  });

  it('fails closed without the witness file, with an empty one or with too few approvals', async () => {
    const { created } = await witnessedLog();
    const file = JSON.parse(created.witnessFile as string) as { versionId: string; proof: unknown[] }[];

    await expect(resolveDidWebvhLog(created.log)).rejects.toThrow('no witness proofs');
    await expect(resolveDidWebvhLog(created.log, { witnessFile: '[]' })).rejects.toBeInstanceOf(DidWebvhError);
    const oneProof = JSON.stringify([{ ...file[0], proof: file[0].proof.slice(0, 1) }]);
    await expect(resolveDidWebvhLog(created.log, { witnessFile: oneProof })).rejects.toBeInstanceOf(DidWebvhError);
    await expect(resolveDidWebvhLog(created.log, { witnessFile: '{' })).rejects.toThrow('not valid JSON');
    await expect(resolveDidWebvhLog(created.log, { witnessFile: '{}' })).rejects.toThrow('JSON array');
    await expect(resolveDidWebvhLog(created.log, { witnessFile: '[{"versionId":1}]' })).rejects.toThrow('versionId');
  });

  it('rejects a proof altered after signing', async () => {
    const { created } = await witnessedLog(1, 1);
    const file = JSON.parse(created.witnessFile as string) as { versionId: string; proof: Record<string, string>[] }[];
    const value = file[0].proof[0].proofValue;
    file[0].proof[0].proofValue = value.slice(0, -2) + (value.endsWith('A') ? 'BB' : 'AA');

    await expect(resolveDidWebvhLog(created.log, { witnessFile: JSON.stringify(file) })).rejects.toBeInstanceOf(
      DidWebvhError
    );
  });

  it('refuses to create or update a governed entry without a collector, or with too few approvals', async () => {
    const [signer] = LocalKeySigner.generate();
    const w = await witnesses(2);
    const document = await controllerDocument(signer);

    await expect(
      createDidWebvhLog({ domain: 'witness.example', document, signer, witness: { threshold: 2, witnesses: w.dids } })
    ).rejects.toThrow('pass collectWitnessProofs');
    await expect(
      createDidWebvhLog({
        domain: 'witness.example',
        document,
        signer,
        witness: { threshold: 2, witnesses: w.dids },
        collectWitnessProofs: w.approving(w.signers.slice(0, 1))
      })
    ).rejects.toBeInstanceOf(DidWebvhError);

    const { created, signer: owner } = await witnessedLog();
    await expect(
      updateDidWebvhLog({ log: created.log, signer: owner, witnessFile: created.witnessFile })
    ).rejects.toThrow('pass collectWitnessProofs');
    await expect(updateDidWebvhLog({ log: created.log, signer: owner })).rejects.toThrow('no witness proofs');
  });

  it('never lets a DID outside the rule approve an entry', async () => {
    const { created, signer } = await witnessedLog(1, 1);
    const [stranger] = LocalKeySigner.generate();

    await expect(
      updateDidWebvhLog({
        log: created.log,
        signer,
        witnessFile: created.witnessFile,
        collectWitnessProofs: async (request) => [
          await createDidWebvhWitnessProof({ log: request.log, witnessFile: request.witnessFile, signer: stranger })
        ]
      })
    ).rejects.toThrow('not a member');
  });

  it('updates under the rule in force, changes it, removes it and deactivates', async () => {
    const { created, signer, w } = await witnessedLog();
    const requests: { versionId: string; threshold: number }[] = [];
    const recording: DidWebvhWitnessCollector = async (request) => {
      requests.push({ versionId: request.versionId, threshold: request.witness.threshold });
      return w.collect(request);
    };

    // The 2-of-2 witnesses approve the entry that changes the rule to 1-of-1.
    const changed = await updateDidWebvhLog({
      log: created.log,
      signer,
      witnessFile: created.witnessFile,
      witness: { threshold: 1, witnesses: [w.dids[0]] },
      collectWitnessProofs: recording
    });
    expect(changed.metadata.witnessThreshold).toBe('1');
    expect(changed.metadata.witnesses).toEqual([w.dids[0]]);

    // Under 1-of-1 the first witness alone is enough.
    const updated = await updateDidWebvhLog({
      log: changed.log,
      signer,
      witnessFile: changed.witnessFile,
      collectWitnessProofs: w.approving([w.signers[0]])
    });
    // Removing the rule is approved by the rule in force; later entries need no approval.
    const removed = await updateDidWebvhLog({
      log: updated.log,
      signer,
      witnessFile: updated.witnessFile,
      witness: null,
      collectWitnessProofs: w.approving([w.signers[0]])
    });
    expect(removed.metadata.witnessThreshold).toBe('0');
    expect(removed.metadata.witnesses).toEqual([]);
    const unwitnessed = await updateDidWebvhLog({ log: removed.log, signer, witnessFile: removed.witnessFile });
    // The history still has witnessed entries, so the file stays required.
    expect(unwitnessed.witnessFile).toBeDefined();
    await expect(resolveDidWebvhLog(unwitnessed.log)).rejects.toThrow('no witness proofs');

    const deactivated = await deactivateDidWebvhLog({
      log: unwitnessed.log,
      signer,
      witnessFile: unwitnessed.witnessFile
    });
    expect(deactivated.metadata.deactivated).toBe(true);
    expect(requests).toEqual([{ versionId: changed.metadata.versionId, threshold: 2 }]);
  });

  it('validates the witness configuration', async () => {
    const [signer] = LocalKeySigner.generate();
    const document = await controllerDocument(signer);
    const w = await witnesses(2);
    const create = (witness: unknown) =>
      createDidWebvhLog({ domain: 'witness.example', document, signer, witness: witness as never, collectWitnessProofs: w.collect });

    await expect(create({ threshold: 1, witnesses: [] })).rejects.toThrow('must not be empty');
    await expect(create({ threshold: 0, witnesses: w.dids })).rejects.toThrow('threshold');
    await expect(create({ threshold: 3, witnesses: w.dids })).rejects.toThrow('threshold');
    await expect(create({ threshold: 1.5, witnesses: w.dids })).rejects.toThrow('threshold');
    await expect(create({ threshold: 1, witnesses: [w.dids[0], w.dids[0]] })).rejects.toThrow('repeat');
    await expect(create({ threshold: 1, witnesses: ['did:web:example.com'] })).rejects.toThrow('did:key');
    await expect(create({ threshold: 1, witnesses: [`${w.dids[0]}#key`] })).rejects.toThrow('did:key');
    // A did:key whose multikey is not Ed25519 (secp256k1 prefix 0xe7 0x01).
    await expect(create({ threshold: 1, witnesses: ['did:key:zQ3shokFTS3brHcDQrn82RUDfCZESWL1ZdCEJwekUDPQiYBme'] })).rejects.toThrow(
      'Ed25519'
    );
    await expect(create(null)).rejects.toThrow('threshold, witnesses');
  });

  it('checks a key at a stated time on a witnessed log only with its witness file', async () => {
    const { created } = await witnessedLog(1, 1);
    const keyId = `${created.did}#key-1`;
    const statedTime = new Date().toISOString();

    await expect(checkDidWebvhKeyAtTime(created.log, { keyId, statedTime })).rejects.toBeInstanceOf(DidWebvhError);
    const result = await checkDidWebvhKeyAtTime(created.log, { keyId, statedTime, witnessFile: created.witnessFile });
    expect(result.status).toBe('authorized');
  });
});

describe('did:webvh witnesses: resolver and client', () => {
  /** A controller published with a 1-of-1 witness, an agent under it with 2-of-2 witnesses, served by one host. */
  async function setUp() {
    const controllerWitnesses = await witnesses(1);
    const [controllerSigner] = LocalKeySigner.generate();
    const controller = await createDidWebvhLog({
      domain: 'org.example',
      pathSegments: ['controllers', 'acme'],
      document: await controllerDocument(controllerSigner),
      signer: controllerSigner,
      witness: { threshold: 1, witnesses: controllerWitnesses.dids },
      collectWitnessProofs: controllerWitnesses.collect
    });
    const files = new Map<string, string>([
      [deriveDidWebvhLogUrl(controller.did), controller.log],
      [deriveDidWebvhWitnessUrl(controller.did), controller.witnessFile as string]
    ]);
    const host = {
      getByReference: async () => null,
      getDidLogByReference: async (url: string): Promise<string | null> => files.get(url) ?? null,
      getDidWitnessFileByReference: async (url: string): Promise<string | null> => files.get(url) ?? null
    };
    const withHost = (client: AgentDidClient, source: object = host): AgentDidClient => {
      client.useProductionResolver({
        registry: new InMemoryAgentRegistry(),
        documentSource: { getByReference: async () => null },
        webvhDocumentSource: source as typeof host
      });
      return client;
    };

    const agentWitnesses = await witnesses(2);
    const owner = withHost(new AgentDidClient({ collectWitnessProofs: agentWitnesses.collect }));
    const [wallet] = LocalKeySigner.generate();
    const identity = new AgentIdentity({ controllerSigner: wallet, client: owner });
    const agent = await identity.create({
      name: 'WitnessedBot',
      webvh: {
        domain: 'org.example',
        pathSegments: ['agents', 'bot'],
        controllerDid: controller.did,
        controllerSigner,
        witness: { threshold: 2, witnesses: agentWitnesses.dids }
      }
    });
    const publish = () => {
      const did = agent.document.id;
      files.set(deriveDidWebvhWitnessUrl(did), owner.exportDidWebvhWitnessFile(did) as string);
      files.set(deriveDidWebvhLogUrl(did), owner.exportDidWebvhHistory(did));
    };
    publish();
    const signature = await identity.signMessage('approve', agent.agentPrivateKey);
    return { controller, controllerSigner, files, host, withHost, owner, identity, agent, agentWitnesses, publish, signature };
  }

  it('verifies a signature of a witnessed agent under a witnessed controller, in the owner and in a verifier', async () => {
    const { owner, agent, signature, withHost } = await setUp();

    expect(await owner.verifySignature(agent.document.id, 'approve', signature)).toBe(true);
    expect(await withHost(new AgentDidClient()).verifySignature(agent.document.id, 'approve', signature)).toBe(true);
    const state = await withHost(new AgentDidClient()).resolveDidWebvhState(agent.document.id);
    expect(state?.provenance).toBe('fetched');
    expect(state?.witnessFile).toBe(owner.exportDidWebvhWitnessFile(agent.document.id));
  });

  it('fails closed when the host serves no witness file or a source cannot fetch one', async () => {
    const { agent, files, host, withHost } = await setUp();
    const did = agent.document.id;

    files.delete(deriveDidWebvhWitnessUrl(did));
    await expect(withHost(new AgentDidClient()).resolve(did)).rejects.toThrow('no did-witness.json');

    const { getDidWitnessFileByReference: _omitted, ...logsOnly } = host;
    await expect(withHost(new AgentDidClient(), logsOnly).resolve(did)).rejects.toThrow('cannot fetch did-witness.json');
  });

  it('fails closed when the witness file lacks the approval of the latest entry', async () => {
    const { agent, files, owner, publish, withHost } = await setUp();
    const did = agent.document.id;
    const before = owner.exportDidWebvhWitnessFile(did) as string;

    await owner.updateDidDocument(did, { description: 'changed' });
    publish();
    files.set(deriveDidWebvhWitnessUrl(did), before);

    await expect(withHost(new AgentDidClient()).resolve(did)).rejects.toThrow('verification failed');
  });

  it('updates, rotates the controller key and revokes a witnessed DID with the client collector', async () => {
    const { agent, owner, controllerSigner, agentWitnesses } = await setUp();
    const did = agent.document.id;

    await owner.updateDidDocument(did, { description: 'v2' });
    const [nextController] = LocalKeySigner.generate();
    await owner.rotateControllerKey(did, { newControllerSigner: nextController, controllerSigner });
    const rule = await owner.setDidWebvhWitnesses(did, { threshold: 1, witnesses: [agentWitnesses.dids[1]] });
    expect(rule).toEqual({ threshold: 1, witnesses: [agentWitnesses.dids[1]] });
    await owner.revokeDid(did);

    const resolved = await resolveDidWebvhLog(owner.exportDidWebvhHistory(did), {
      witnessFile: owner.exportDidWebvhWitnessFile(did)
    });
    expect(resolved.metadata.deactivated).toBe(true);
  });

  it('refuses to change a witnessed DID in a client without a collector', async () => {
    const { agent, owner, controllerSigner } = await setUp();
    const did = agent.document.id;
    const other = new AgentDidClient();
    await other.importDidWebvhHistory(owner.exportDidWebvhHistory(did), owner.exportDidWebvhWitnessFile(did));

    await expect(other.updateDidDocument(did, { description: 'x' }, { controllerSigner })).rejects.toThrow(
      'pass collectWitnessProofs'
    );
    await expect(other.importDidWebvhHistory(owner.exportDidWebvhHistory(did))).rejects.toThrow('no witness proofs');
  });

  it('saves, loads, persists and restores a witnessed history with its witness file', async () => {
    const fs = await import('node:fs/promises');
    const os = await import('node:os');
    const path = await import('node:path');
    const { agent, owner } = await setUp();
    const did = agent.document.id;
    const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'witness-'));
    try {
      const logPath = path.join(dir, 'did.jsonl');
      const witnessPath = path.join(dir, 'did-witness.json');
      await expect(owner.saveDidWebvhHistoryToFile(did, logPath)).rejects.toThrow('witnessFilePath');
      await owner.saveDidWebvhHistoryToFile(did, logPath, witnessPath);
      const loaded = new AgentDidClient();
      expect((await loaded.loadDidWebvhHistoryFromFile(logPath, witnessPath)).id).toBe(did);
      expect(loaded.exportDidWebvhWitnessFile(did)).toBe(owner.exportDidWebvhWitnessFile(did));
    } finally {
      await fs.rm(dir, { recursive: true, force: true });
    }

    const stored = new Map<string, string>();
    const source = {
      getByReference: async () => null,
      storeDidLogByReference: async (ref: string, text: string) => void stored.set(ref, text),
      getDidLogByReference: async (ref: string) => stored.get(ref) ?? null,
      storeDidWitnessFileByReference: async (ref: string, text: string) => void stored.set(ref, text),
      getDidWitnessFileByReference: async (ref: string) => stored.get(ref) ?? null
    };
    await expect(owner.persistDidWebvhHistoryToSource(did, 'log', source)).rejects.toThrow('witnessRef');
    await owner.persistDidWebvhHistoryToSource(did, 'log', source, 'witness');
    const restored = new AgentDidClient();
    expect((await restored.restoreDidWebvhHistoryFromSource('log', source, 'witness')).id).toBe(did);
    await expect(restored.restoreDidWebvhHistoryFromSource('log', source, 'missing')).rejects.toThrow('not found');
  });
});
