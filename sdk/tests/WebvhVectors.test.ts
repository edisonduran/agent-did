/**
 * Cross-SDK did:webvh log vectors (fixtures/webvh-log-vectors.json).
 *
 * The TypeScript adapter generates the vectors; both SDKs must reproduce the
 * deterministic logs byte for byte, resolve every positive log and reject
 * every negative one. Regenerate with:
 *
 *   WRITE_WEBVH_VECTORS=1 npm --prefix sdk test -- WebvhVectors.test.ts
 */
import fs from 'fs';
import path from 'path';
import bs58 from 'bs58';
import { hexToBytes } from '@noble/hashes/utils';
import { createDID, defaultVerifier, prepareDataForSigning } from 'didwebvh-ts';
import { LocalKeySigner } from '../src/core/signer';
import {
  createDidWebvhLog,
  createDidWebvhWitnessProof,
  deactivateDidWebvhLog,
  didWebvhUpdateKeyFor,
  DidWebvhError,
  DidWebvhLogResult,
  resolveDidWebvhLog,
  updateDidWebvhLog,
} from '../src/webvh/adapter';

interface ResolvableVector {
  name: string;
  did: string;
  versionId: string;
  deactivated?: boolean;
  log: string;
  /** The `did-witness.json` that approves `log` (ADR-007), for logs with witnessed entries. */
  witnessFile?: string;
  /** What both adapters must return when resolving `log`. */
  resolved: { document: Record<string, unknown>; metadata: Record<string, unknown>; versionNumber: number };
  /**
   * What both adapters must return for each version of `log`, selected by `versionNumber`, `versionId` or
   * `versionTime`. Present on the deactivated logs: `metadata.deactivated` is true for every version, and the
   * entry that deactivates the DID resolves to its raw state.
   */
  versions?: ResolvedVersion[];
}

interface ResolvedVersion {
  versionNumber: number;
  versionId: string;
  versionTime: string;
  document: Record<string, unknown>;
  metadata: Record<string, unknown>;
}

async function withVersions(vector: ResolvableVector): Promise<ResolvableVector> {
  const versions: ResolvedVersion[] = [];
  for (const [index, line] of lines(vector.log).entries()) {
    const entry = JSON.parse(line) as { versionId: string; versionTime: string };
    const resolved = await resolveDidWebvhLog(vector.log, { versionNumber: index + 1, ...witnessOf(vector) });
    versions.push({
      versionNumber: index + 1,
      versionId: entry.versionId,
      versionTime: entry.versionTime,
      document: resolved.document,
      metadata: { ...resolved.metadata },
    });
  }
  return { ...vector, versions };
}

function vector(name: string, result: DidWebvhLogResult): ResolvableVector {
  return {
    name,
    did: result.did,
    versionId: result.metadata.versionId,
    ...(result.metadata.deactivated ? { deactivated: true } : {}),
    log: result.log,
    ...(result.witnessFile !== undefined ? { witnessFile: result.witnessFile } : {}),
    resolved: { document: result.document, metadata: { ...result.metadata }, versionNumber: result.versionNumber },
  };
}

function witnessOf(vector: { witnessFile?: string }): { witnessFile?: string } {
  return vector.witnessFile !== undefined ? { witnessFile: vector.witnessFile } : {};
}

const FIXTURE_PATH = path.join(__dirname, '..', '..', 'fixtures', 'webvh-log-vectors.json');

interface WebvhVectors {
  description: string;
  regenerate: string;
  generator: { library: string; version: string };
  inputs: {
    controllerPrivateKeyHex: string;
    rotatedControllerPrivateKeyHex: string;
    /** Pre-rotation: the key committed at creation (only its hash is in the genesis entry). */
    nextControllerPrivateKeyHex: string;
    /** Pre-rotation: the key the committed key commits to in turn. */
    followingControllerPrivateKeyHex: string;
    unauthorizedPrivateKeyHex: string;
    /** Witness keys (ADR-007): their `did:key` DIDs approve the entries of the witnessed vectors. */
    witnessPrivateKeysHex: string[];
    domain: string;
    pathSegments: string[];
    document: Record<string, unknown>;
    updatedAgentMetadata: Record<string, unknown>;
    created: string;
    updated: string;
    rotated: string;
  };
  deterministic: ResolvableVector[];
  resolveOnly: ResolvableVector[];
  negative: Array<{ name: string; reason: string; log: string; witnessFile?: string }>;
}

const INPUTS: WebvhVectors['inputs'] = {
  controllerPrivateKeyHex: '9b'.repeat(32),
  rotatedControllerPrivateKeyHex: '4c'.repeat(32),
  nextControllerPrivateKeyHex: 'a3'.repeat(32),
  followingControllerPrivateKeyHex: '5d'.repeat(32),
  unauthorizedPrivateKeyHex: 'e7'.repeat(32),
  witnessPrivateKeysHex: ['1a'.repeat(32), '2b'.repeat(32)],
  domain: 'agents.example.com',
  pathSegments: ['fleet', 'support-bot'],
  document: {
    '@context': ['https://www.w3.org/ns/did/v1', 'https://agent-did.org/v1'],
    id: '{DID}',
    controller: 'did:webvh:QmControllerScid:controller.example.com',
    verificationMethod: [
      {
        id: '{DID}#key-1',
        type: 'Multikey',
        controller: '{DID}',
        publicKeyMultibase: 'z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK',
      },
    ],
    authentication: ['{DID}#key-1'],
    assertionMethod: ['{DID}#key-1'],
    agentMetadata: {
      name: 'support-bot',
      version: '1.0.0',
      coreModelHash: 'hash://hmac-sha256/model-commitment',
      systemPromptHash: 'hash://hmac-sha256/prompt-commitment',
      capabilities: ['read:tickets', 'write:replies'],
    },
  },
  updatedAgentMetadata: {
    name: 'support-bot',
    version: '1.1.0',
    coreModelHash: 'hash://hmac-sha256/model-commitment-2',
    systemPromptHash: 'hash://hmac-sha256/prompt-commitment-2',
    capabilities: ['read:tickets', 'write:replies', 'escalate:human'],
  },
  created: '2026-01-01T00:00:00Z',
  updated: '2026-01-02T00:00:00Z',
  rotated: '2026-01-03T00:00:00Z',
};

function lines(log: string): string[] {
  return log.trimEnd().split('\n');
}

function join(entries: string[]): string {
  return entries.join('\n') + '\n';
}

function mutateLine(log: string, index: number, mutate: (entry: Record<string, any>) => void): string {
  const entries = lines(log);
  const entry = JSON.parse(entries[index]);
  mutate(entry);
  entries[index] = JSON.stringify(entry);
  return join(entries);
}

async function resignLine(log: string, index: number, privateKeyHex: string): Promise<string> {
  const signer = new LocalKeySigner(privateKeyHex);
  const key = await didWebvhUpdateKeyFor(signer);
  const entries = lines(log);
  const entry = JSON.parse(entries[index]);
  const { proofValue: _ignored, ...template } = entry.proof[0];
  template.verificationMethod = `did:key:${key}#${key}`;
  const { proof: _proof, ...unsigned } = entry;
  const signature = hexToBytes(await signer.sign(await prepareDataForSigning(unsigned, template)));
  entry.proof = [{ ...template, proofValue: `z${bs58.encode(signature)}` }];
  entries[index] = JSON.stringify(entry);
  return join(entries);
}

async function generateDeterministic(inputs: WebvhVectors['inputs']) {
  const controller = new LocalKeySigner(inputs.controllerPrivateKeyHex);
  const rotatedController = new LocalKeySigner(inputs.rotatedControllerPrivateKeyHex);

  const created = await createDidWebvhLog({
    domain: inputs.domain,
    pathSegments: inputs.pathSegments,
    document: inputs.document,
    signer: controller,
    created: inputs.created,
  });
  const updated = await updateDidWebvhLog({
    log: created.log,
    signer: controller,
    document: { ...created.document, agentMetadata: inputs.updatedAgentMetadata },
    updated: inputs.updated,
  });
  const rotated = await updateDidWebvhLog({
    log: updated.log,
    signer: controller,
    updateKeys: [await didWebvhUpdateKeyFor(rotatedController)],
    updated: inputs.rotated,
  });

  // Pre-rotation: the genesis entry commits to the hash of `next`; only `next` can sign the following entry,
  // and that entry commits to `following` in turn.
  const next = new LocalKeySigner(inputs.nextControllerPrivateKeyHex);
  const following = new LocalKeySigner(inputs.followingControllerPrivateKeyHex);
  const committed = await createDidWebvhLog({
    domain: inputs.domain,
    pathSegments: inputs.pathSegments,
    document: inputs.document,
    signer: controller,
    nextUpdateKeys: [await didWebvhUpdateKeyFor(next)],
    created: inputs.created,
  });
  const preRotated = await updateDidWebvhLog({
    log: committed.log,
    signer: next,
    nextUpdateKeys: [await didWebvhUpdateKeyFor(following)],
    updated: inputs.updated,
  });

  return { created, updated, rotated, rotatedController, committed, preRotated, following };
}

/** A genesis entry that declares a witness, without its did-witness.json: both SDKs must reject it. */
async function witnessDeclaredLog(inputs: WebvhVectors['inputs']): Promise<string> {
  const signer = new LocalKeySigner(inputs.controllerPrivateKeyHex);
  const updateKey = await didWebvhUpdateKeyFor(signer);
  const witnessKey = await didWebvhUpdateKeyFor(new LocalKeySigner(inputs.unauthorizedPrivateKeyHex));
  const result = await createDID({
    address: inputs.domain,
    paths: inputs.pathSegments,
    didDocument: inputs.document as any,
    updateKeys: [updateKey],
    witness: { threshold: 1, witnesses: [{ id: `did:key:${witnessKey}` }] },
    created: inputs.created,
    verifier: defaultVerifier,
    signer: {
      getVerificationMethodId: () => `did:key:${updateKey}#${updateKey}`,
      async sign(input) {
        const signature = hexToBytes(await signer.sign(await prepareDataForSigning(input.document, input.proof)));
        return { proofValue: `z${bs58.encode(signature)}` };
      },
    },
  });
  return join(result.log.map((entry) => JSON.stringify(entry)));
}

/**
 * Witnessed logs (ADR-007): created with a 2-of-2 rule, updated under it with a change to 1-of-1, then updated under
 * the new rule. Witness proofs carry a creation time, so these are resolve-only vectors.
 */
async function witnessedVectors(inputs: WebvhVectors['inputs']) {
  const controller = new LocalKeySigner(inputs.controllerPrivateKeyHex);
  const witnessSigners = inputs.witnessPrivateKeysHex.map((hex) => new LocalKeySigner(hex));
  const witnessDids = await Promise.all(
    witnessSigners.map(async (signer) => `did:key:${await didWebvhUpdateKeyFor(signer)}`)
  );
  const collect = async (request: { log: string; witnessFile?: string; witness: { witnesses: string[] } }) =>
    Promise.all(
      witnessSigners
        .filter((_signer, index) => request.witness.witnesses.includes(witnessDids[index]))
        .map((signer) => createDidWebvhWitnessProof({ log: request.log, witnessFile: request.witnessFile, signer }))
    );
  const created = await createDidWebvhLog({
    domain: inputs.domain,
    pathSegments: inputs.pathSegments,
    document: inputs.document,
    signer: controller,
    created: inputs.created,
    witness: { threshold: 2, witnesses: witnessDids },
    collectWitnessProofs: collect,
  });
  const changed = await updateDidWebvhLog({
    log: created.log,
    signer: controller,
    witnessFile: created.witnessFile,
    witness: { threshold: 1, witnesses: [witnessDids[0]] },
    updated: inputs.updated,
    collectWitnessProofs: collect,
  });
  const updated = await updateDidWebvhLog({
    log: changed.log,
    signer: controller,
    witnessFile: changed.witnessFile,
    document: { ...changed.document, agentMetadata: inputs.updatedAgentMetadata },
    updated: inputs.rotated,
    collectWitnessProofs: collect,
  });
  return { created, updated };
}

/**
 * Deactivation logs in the shape earlier releases wrote: the deactivation entry kept `updateKeys`, and a
 * pre-rotated DID was deactivated in one entry. They are valid did:webvh v1.0 logs that both SDKs must keep
 * resolving, and the adapters no longer write them, so regeneration carries them over from the fixture.
 */
function legacyVectors(): Promise<ResolvableVector[]> {
  const existing = JSON.parse(fs.readFileSync(FIXTURE_PATH, 'utf8')) as WebvhVectors;
  return Promise.all(
    existing.resolveOnly
      .filter((vector) => vector.name.startsWith('legacy-'))
      // The log is carried over; what the adapters return for it is recomputed.
      .map(async (legacy) => withVersions(vector(legacy.name, await resolveDidWebvhLog(legacy.log))))
  );
}

async function generateVectors(): Promise<WebvhVectors> {
  const { created, updated, rotated, rotatedController, committed, preRotated, following } = await generateDeterministic(INPUTS);
  const deactivated = await deactivateDidWebvhLog({ log: rotated.log, signer: rotatedController });
  const preRotationDeactivated = await deactivateDidWebvhLog({ log: preRotated.log, signer: following });
  const witnessed = await witnessedVectors(INPUTS);
  const createdApprovals = JSON.parse(witnessed.created.witnessFile as string) as { versionId: string; proof: unknown[] }[];
  const libraryVersion = JSON.parse(
    fs.readFileSync(path.join(__dirname, '..', 'node_modules', 'didwebvh-ts', 'package.json'), 'utf8')
  ).version as string;

  return {
    description:
      'did:webvh v1.0 log vectors shared by the TypeScript and Python SDKs. Both adapters must reproduce the ' +
      'deterministic logs byte for byte, resolve every resolveOnly log and reject every negative log.',
    regenerate: 'WRITE_WEBVH_VECTORS=1 npm --prefix sdk test -- WebvhVectors.test.ts',
    generator: { library: 'didwebvh-ts', version: libraryVersion },
    inputs: INPUTS,
    deterministic: [
      vector('create', created),
      vector('update-document', updated),
      vector('rotate-update-keys', rotated),
      vector('prerotation-create', committed),
      vector('prerotation-rotate', preRotated),
    ],
    resolveOnly: [
      await withVersions(vector('deactivate-with-rotated-key', deactivated)),
      await withVersions(vector('prerotation-deactivate', preRotationDeactivated)),
      vector('witness-create', witnessed.created),
      vector('witness-change-rule', witnessed.updated),
      ...(await legacyVectors()),
    ],
    negative: [
      {
        name: 'tampered-state',
        reason: 'document state edited after signing',
        log: mutateLine(updated.log, 1, (entry) => {
          entry.state.controller = 'did:webvh:QmAttacker:attacker.example.com';
        }),
      },
      {
        name: 'tampered-genesis-scid',
        reason: 'SCID does not match the genesis entry',
        log: mutateLine(created.log, 0, (entry) => {
          entry.parameters.scid = 'QmXoypizjW3WknFiJnKLwHCnL72vedxjQkDDP1mXWo6uco';
        }),
      },
      {
        name: 'broken-hash-chain',
        reason: 'versionId entry hash does not match the entry',
        log: mutateLine(updated.log, 1, (entry) => {
          entry.versionId = '2-QmXoypizjW3WknFiJnKLwHCnL72vedxjQkDDP1mXWo6uco';
        }),
      },
      {
        name: 'missing-entry',
        reason: 'version 2 removed from the chain',
        log: join([lines(rotated.log)[0], lines(rotated.log)[2]]),
      },
      {
        name: 'unauthorized-signer',
        reason: 'entry signed by a key outside updateKeys',
        log: await resignLine(updated.log, 1, INPUTS.unauthorizedPrivateKeyHex),
      },
      {
        name: 'rotated-out-signer',
        reason: 'entry after rotation signed by the previous controller key',
        log: await resignLine(deactivated.log, 3, INPUTS.controllerPrivateKeyHex),
      },
      {
        name: 'prerotation-signed-by-active-key',
        reason: 'entry after a pre-rotation commitment signed by the key that was active before, not by a committed key',
        log: await resignLine(preRotated.log, 1, INPUTS.controllerPrivateKeyHex),
      },
      {
        name: 'prerotation-swapped-update-keys',
        reason: 'updateKeys of a pre-rotated entry replaced by a key that was never committed',
        log: mutateLine(preRotated.log, 1, (entry) => {
          entry.parameters.updateKeys = [entry.parameters.updateKeys[0].replace(/.$/u, (c: string) => (c === 'a' ? 'b' : 'a'))];
        }),
      },
      {
        name: 'version-time-not-increasing',
        reason: 'versionTime of version 2 precedes version 1',
        log: mutateLine(updated.log, 1, (entry) => {
          entry.versionTime = '2025-12-31T00:00:00Z';
        }),
      },
      {
        name: 'witness-declared',
        reason: 'log declares a witness and no did-witness.json is supplied; must be rejected without network access',
        log: await witnessDeclaredLog(INPUTS),
      },
      {
        name: 'witness-threshold-not-met',
        reason: 'genesis entry under a 2-of-2 witness rule with only one approval in did-witness.json',
        log: witnessed.created.log,
        witnessFile: JSON.stringify([{ ...createdApprovals[0], proof: createdApprovals[0].proof.slice(0, 1) }]),
      },
      {
        name: 'missing-proof',
        reason: 'entry without a Data Integrity proof',
        log: mutateLine(created.log, 0, (entry) => {
          delete entry.proof;
        }),
      },
    ],
  };
}

const WRITE_MODE = process.env.WRITE_WEBVH_VECTORS === '1';
const VECTORS: WebvhVectors | undefined = WRITE_MODE
  ? undefined
  : (JSON.parse(fs.readFileSync(FIXTURE_PATH, 'utf8')) as WebvhVectors);

const RESOLVABLE: Array<[string, ResolvableVector]> = VECTORS
  ? [...VECTORS.deterministic, ...VECTORS.resolveOnly].map((vector) => [vector.name, vector])
  : [];
const VERSIONED: Array<[string, ResolvableVector]> = RESOLVABLE.filter(([, vector]) => vector.versions !== undefined);
const NEGATIVE: Array<[string, string, string | undefined]> = VECTORS
  ? VECTORS.negative.map((vector) => [vector.name, vector.log, vector.witnessFile])
  : [];

describe('did:webvh cross-SDK log vectors', () => {
  if (WRITE_MODE) {
    it('writes fixtures/webvh-log-vectors.json', async () => {
      const vectors = await generateVectors();
      fs.writeFileSync(FIXTURE_PATH, JSON.stringify(vectors, null, 2) + '\n', 'utf8');
    });
    return;
  }

  it('reproduces the deterministic logs byte for byte', async () => {
    const vectors = VECTORS as WebvhVectors;
    const { created, updated, rotated, committed, preRotated } = await generateDeterministic(vectors.inputs);
    const produced = [created, updated, rotated, committed, preRotated];
    expect(vectors.deterministic).toHaveLength(produced.length);
    vectors.deterministic.forEach((vector, index) => {
      expect(produced[index].log).toBe(vector.log);
      expect(produced[index].did).toBe(vector.did);
      expect(produced[index].metadata.versionId).toBe(vector.versionId);
    });
  });

  it.each(RESOLVABLE)('resolves %s', async (_name, resolvable) => {
    const vector = resolvable;
    const resolved = await resolveDidWebvhLog(vector.log, { did: vector.did, ...witnessOf(vector) });
    expect(resolved.metadata.versionId).toBe(vector.versionId);
    expect(resolved.witnessFile).toBe(vector.witnessFile);
    expect(resolved.metadata.deactivated).toBe(vector.deactivated === true);
    expect(resolved.document).toEqual(vector.resolved.document);
    expect({ ...resolved.metadata }).toEqual(vector.resolved.metadata);
    expect(resolved.versionNumber).toBe(vector.resolved.versionNumber);
  });

  it('has per-version expectations for every deactivated log', () => {
    const deactivated = RESOLVABLE.filter(([, vector]) => vector.deactivated === true);
    expect(deactivated.length).toBeGreaterThan(0);
    expect(VERSIONED.map(([name]) => name)).toEqual(deactivated.map(([name]) => name));
  });

  it.each(VERSIONED)('resolves every version of %s by number, id and time', async (_name, vector) => {
    const versions = vector.versions as ResolvedVersion[];
    expect(versions).toHaveLength(lines(vector.log).length);
    for (const version of versions) {
      const selections = [
        { versionNumber: version.versionNumber },
        { versionId: version.versionId },
        { versionTime: version.versionTime },
      ];
      for (const selection of selections) {
        const resolved = await resolveDidWebvhLog(vector.log, { ...selection, ...witnessOf(vector) });
        expect(resolved.versionNumber).toBe(version.versionNumber);
        expect(resolved.document).toEqual(version.document);
        expect({ ...resolved.metadata }).toEqual(version.metadata);
        expect(resolved.metadata.deactivated).toBe(true);
      }
    }
  });

  it.each(NEGATIVE)('rejects %s at every selected version', async (_name, log, witnessFile) => {
    for (let versionNumber = 1; versionNumber <= lines(log).length; versionNumber += 1) {
      await expect(resolveDidWebvhLog(log, { versionNumber, ...witnessOf({ witnessFile }) })).rejects.toBeInstanceOf(
        DidWebvhError
      );
    }
  });

  it.each(NEGATIVE)('rejects %s', async (_name, log, witnessFile) => {
    const fetchSpy = jest.spyOn(globalThis, 'fetch');
    try {
      await expect(resolveDidWebvhLog(log, witnessOf({ witnessFile }))).rejects.toBeInstanceOf(DidWebvhError);
      expect(fetchSpy).not.toHaveBeenCalled();
    } finally {
      fetchSpy.mockRestore();
    }
  });
});
