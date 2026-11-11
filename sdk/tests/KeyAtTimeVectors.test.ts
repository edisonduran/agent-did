/**
 * Key checks at a stated time (RFC-001 §6.2.2): fixtures/key-at-time-vectors.json.
 *
 * The TypeScript adapter generates the logs; both SDKs run every vector through `checkDidWebvhKeyAtTime` /
 * `check_did_webvh_key_at_time` and through the client's `verifySignatureAtTime` / `verify_signature_at_time`.
 * The Python SDK runs the same file in sdk-python/tests/test_key_at_time_vectors.py. Regenerate with:
 *
 *   WRITE_KEY_AT_TIME_VECTORS=1 npm --prefix sdk test -- KeyAtTimeVectors.test.ts
 *
 * The deactivation entry takes the current time, so regenerating changes the second log; the vectors read its
 * time from the log.
 */
import fs from 'fs';
import path from 'path';
import { ed25519 } from '@noble/curves/ed25519';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils';
import { AgentDidClient, checkDidWebvhKeyAtTime, KeyAtTimeResult, VerificationRelationship } from '../src';
import { LocalKeySigner } from '../src/core/signer';
import { encodePublicKeyMultibase } from '../src/crypto/multibase';
import { createDidWebvhLog, deactivateDidWebvhLog, updateDidWebvhLog } from '../src/webvh/adapter';
import { parseRfc3339Millis } from '../src/verification/key-at-time';

const FIXTURE_PATH = path.join(__dirname, '..', '..', 'fixtures', 'key-at-time-vectors.json');

/** TEST-ONLY keys, public on purpose; they sign nothing real. */
const INPUTS = {
  controllerPrivateKeyHex: 'c1'.repeat(32),
  key1PrivateKeyHex: '11'.repeat(32),
  key2PrivateKeyHex: '22'.repeat(32),
  domain: 'agents.example.com',
  pathSegments: ['fleet', 'time-bot'],
  created: '2026-01-01T00:00:00Z',
  delegationRemoved: '2026-01-02T00:00:00Z',
  rotated: '2026-01-03T00:00:00Z',
  /** Log "rotatedLate": key-1's `deactivated` is after the rotation entry's versionTime, as the SDK writes it. */
  rotatedLateKeyDeactivated: '2026-01-03T00:00:00.500Z',
  payload: 'agent-did:key-at-time-vector:v1'
};

interface Vector {
  id: string;
  log: 'rotated' | 'deactivated' | 'rotatedLate';
  key: 'key-1' | 'key-2';
  requiredPurpose: VerificationRelationship;
  statedTime: string;
  trustedTimeNotAfter?: string;
  /** Use a signature by the other key: the key check passes or not, but the signature never verifies. */
  wrongSignature?: true;
  expected: {
    status: KeyAtTimeResult['status'];
    reason?: string;
    basis?: string;
    foundIn?: string[];
    boundaryVersionNumber?: number;
    boundaryTime?: string;
    signature: 'valid' | 'invalid' | 'indeterminate';
    signatureReason?: string;
  };
}

interface Fixture {
  formatVersion: number;
  description: string;
  regenerate: string;
  inputs: typeof INPUTS;
  did: string;
  logs: { rotated: string; deactivated: string; rotatedLate: string };
  signatures: { 'key-1': string; 'key-2': string };
  vectors: Vector[];
}

function publicKeyMultibase(privateKeyHex: string): string {
  return encodePublicKeyMultibase(ed25519.getPublicKey(hexToBytes(privateKeyHex)));
}

async function generate(): Promise<Fixture> {
  const controller = new LocalKeySigner(INPUTS.controllerPrivateKeyHex);
  const method = (fragment: string, privateKeyHex: string, extra: Record<string, unknown> = {}) => ({
    id: `{DID}#${fragment}`,
    type: 'Ed25519VerificationKey2020',
    controller: '{DID}',
    publicKeyMultibase: publicKeyMultibase(privateKeyHex),
    ...extra
  });
  const base = {
    '@context': ['https://www.w3.org/ns/did/v1', 'https://agent-did.org/v1'],
    id: '{DID}',
    controller: '{DID}',
    created: INPUTS.created,
    updated: INPUTS.created,
    agentMetadata: {
      name: 'time-bot',
      version: '1.0.0',
      coreModelHash: 'hash://hmac-sha256/model-commitment',
      systemPromptHash: 'hash://hmac-sha256/prompt-commitment'
    }
  };

  // 1: key-1 under authentication, assertionMethod and capabilityDelegation.
  const created = await createDidWebvhLog({
    domain: INPUTS.domain,
    pathSegments: INPUTS.pathSegments,
    signer: controller,
    created: INPUTS.created,
    document: {
      ...base,
      verificationMethod: [method('key-1', INPUTS.key1PrivateKeyHex)],
      authentication: ['{DID}#key-1'],
      assertionMethod: ['{DID}#key-1'],
      capabilityDelegation: ['{DID}#key-1']
    }
  });
  const did = created.did;
  const fill = (value: unknown): Record<string, unknown> =>
    JSON.parse(JSON.stringify(value).split('{DID}').join(did)) as Record<string, unknown>;

  // 2: key-1 leaves capabilityDelegation.
  const delegationRemoved = await updateDidWebvhLog({
    log: created.log,
    signer: controller,
    updated: INPUTS.delegationRemoved,
    document: fill({
      ...base,
      updated: INPUTS.delegationRemoved,
      verificationMethod: [method('key-1', INPUTS.key1PrivateKeyHex)],
      authentication: ['{DID}#key-1'],
      assertionMethod: ['{DID}#key-1']
    })
  });

  // 3: rotation as the SDK does it: key-1 deactivated (kept in assertionMethod), key-2 active.
  const rotated = await updateDidWebvhLog({
    log: delegationRemoved.log,
    signer: controller,
    updated: INPUTS.rotated,
    document: fill({
      ...base,
      updated: INPUTS.rotated,
      verificationMethod: [
        method('key-1', INPUTS.key1PrivateKeyHex, { deactivated: INPUTS.rotated }),
        method('key-2', INPUTS.key2PrivateKeyHex)
      ],
      authentication: ['{DID}#key-2'],
      assertionMethod: ['{DID}#key-1', '{DID}#key-2']
    })
  });

  // 3 (log "rotatedLate"): the same rotation with key-1's deactivated time after the entry's versionTime.
  const rotatedLate = await updateDidWebvhLog({
    log: delegationRemoved.log,
    signer: controller,
    updated: INPUTS.rotated,
    document: fill({
      ...base,
      updated: INPUTS.rotatedLateKeyDeactivated,
      verificationMethod: [
        method('key-1', INPUTS.key1PrivateKeyHex, { deactivated: INPUTS.rotatedLateKeyDeactivated }),
        method('key-2', INPUTS.key2PrivateKeyHex)
      ],
      authentication: ['{DID}#key-2'],
      assertionMethod: ['{DID}#key-1', '{DID}#key-2']
    })
  });

  // 4: deactivation (current time).
  const deactivated = await deactivateDidWebvhLog({ log: rotated.log, signer: controller });
  const deactivatedAt = deactivated.metadata.versionTime;

  const vectors: Vector[] = [
    {
      id: 'before-genesis',
      log: 'rotated', key: 'key-1', requiredPurpose: 'assertionMethod', statedTime: '2025-12-31T23:59:59Z',
      expected: { status: 'not_authorized', reason: 'did_not_yet_created', foundIn: [], signature: 'invalid', signatureReason: 'key_not_authorized' }
    },
    {
      id: 'retired-later-no-evidence',
      log: 'rotated', key: 'key-1', requiredPurpose: 'assertionMethod', statedTime: '2026-01-01T12:00:00Z',
      expected: { status: 'indeterminate', reason: 'key_retired_after_stated_time', boundaryVersionNumber: 3, boundaryTime: INPUTS.rotated, signature: 'indeterminate' }
    },
    {
      id: 'retired-later-evidence-before-boundary',
      log: 'rotated', key: 'key-1', requiredPurpose: 'assertionMethod', statedTime: '2026-01-01T12:00:00Z',
      trustedTimeNotAfter: '2026-01-02T23:59:59.999Z',
      expected: { status: 'authorized', basis: 'time_evidence', signature: 'valid' }
    },
    {
      id: 'retired-later-evidence-at-boundary',
      log: 'rotated', key: 'key-1', requiredPurpose: 'assertionMethod', statedTime: '2026-01-01T12:00:00Z',
      trustedTimeNotAfter: INPUTS.rotated,
      expected: { status: 'indeterminate', reason: 'key_retired_after_stated_time', boundaryVersionNumber: 3, boundaryTime: INPUTS.rotated, signature: 'indeterminate' }
    },
    {
      id: 'retired-later-bad-signature',
      log: 'rotated', key: 'key-1', requiredPurpose: 'assertionMethod', statedTime: '2026-01-01T12:00:00Z',
      trustedTimeNotAfter: '2026-01-02T00:00:00Z', wrongSignature: true,
      expected: { status: 'authorized', basis: 'time_evidence', signature: 'invalid', signatureReason: 'signature_invalid' }
    },
    {
      id: 'deactivated-before-stated-time',
      log: 'rotated', key: 'key-1', requiredPurpose: 'assertionMethod', statedTime: '2026-01-04T00:00:00Z',
      expected: { status: 'not_authorized', reason: 'key_deactivated', foundIn: ['assertionMethod'], signature: 'invalid', signatureReason: 'key_not_authorized' }
    },
    {
      id: 'delegation-removed-later',
      log: 'rotated', key: 'key-1', requiredPurpose: 'capabilityDelegation', statedTime: '2026-01-01T12:00:00Z',
      expected: { status: 'indeterminate', reason: 'key_retired_after_stated_time', boundaryVersionNumber: 2, boundaryTime: INPUTS.delegationRemoved, signature: 'indeterminate' }
    },
    {
      id: 'delegation-removed-before-stated-time',
      log: 'rotated', key: 'key-1', requiredPurpose: 'capabilityDelegation', statedTime: '2026-01-02T12:00:00Z',
      expected: { status: 'not_authorized', reason: 'key_purpose_violation', foundIn: ['authentication', 'assertionMethod'], signature: 'invalid', signatureReason: 'key_not_authorized' }
    },
    {
      id: 'key-agreement-never-signs',
      log: 'rotated', key: 'key-2', requiredPurpose: 'keyAgreement', statedTime: '2026-01-03T12:00:00Z',
      expected: { status: 'not_authorized', reason: 'key_purpose_violation', foundIn: ['authentication', 'assertionMethod'], signature: 'invalid', signatureReason: 'key_not_authorized' }
    },
    {
      id: 'key-added-after-stated-time',
      log: 'rotated', key: 'key-2', requiredPurpose: 'assertionMethod', statedTime: '2026-01-02T12:00:00Z',
      expected: { status: 'not_authorized', reason: 'key_not_found', foundIn: [], signature: 'invalid', signatureReason: 'key_not_authorized' }
    },
    {
      id: 'offset-stated-time-before-rotation',
      log: 'rotated', key: 'key-2', requiredPurpose: 'assertionMethod', statedTime: '2026-01-03T01:00:00+02:00',
      expected: { status: 'not_authorized', reason: 'key_not_found', foundIn: [], signature: 'invalid', signatureReason: 'key_not_authorized' }
    },
    {
      id: 'stated-time-equals-entry-time',
      log: 'rotated', key: 'key-2', requiredPurpose: 'assertionMethod', statedTime: INPUTS.rotated,
      expected: { status: 'authorized', basis: 'no_later_change', signature: 'valid' }
    },
    {
      id: 'current-key-no-later-change',
      log: 'rotated', key: 'key-2', requiredPurpose: 'assertionMethod', statedTime: '2026-01-03T12:00:00Z',
      expected: { status: 'authorized', basis: 'no_later_change', signature: 'valid' }
    },
    {
      id: 'current-key-bad-signature',
      log: 'rotated', key: 'key-2', requiredPurpose: 'assertionMethod', statedTime: '2026-01-03T12:00:00Z', wrongSignature: true,
      expected: { status: 'authorized', basis: 'no_later_change', signature: 'invalid', signatureReason: 'signature_invalid' }
    },
    {
      id: 'invalid-stated-time',
      log: 'rotated', key: 'key-2', requiredPurpose: 'assertionMethod', statedTime: '2026-01-03 12:00:00',
      expected: { status: 'not_authorized', reason: 'invalid_stated_time', foundIn: [], signature: 'invalid', signatureReason: 'key_not_authorized' }
    },
    {
      id: 'retired-later-deactivated-after-entry-time',
      log: 'rotatedLate', key: 'key-1', requiredPurpose: 'assertionMethod', statedTime: '2026-01-01T12:00:00Z',
      expected: { status: 'indeterminate', reason: 'key_retired_after_stated_time', boundaryVersionNumber: 3, boundaryTime: INPUTS.rotated, signature: 'indeterminate' }
    },
    {
      id: 'retired-later-deactivated-after-entry-time-evidence-before',
      log: 'rotatedLate', key: 'key-1', requiredPurpose: 'assertionMethod', statedTime: '2026-01-01T12:00:00Z',
      trustedTimeNotAfter: '2026-01-02T23:59:59.999Z',
      expected: { status: 'authorized', basis: 'time_evidence', signature: 'valid' }
    },
    {
      id: 'retiring-entry-in-effect-deactivated-time-later',
      log: 'rotatedLate', key: 'key-1', requiredPurpose: 'assertionMethod', statedTime: INPUTS.rotated,
      expected: { status: 'not_authorized', reason: 'key_deactivated', foundIn: ['assertionMethod'], signature: 'invalid', signatureReason: 'key_not_authorized' }
    },
    {
      id: 'retiring-entry-in-effect-evidence-before-deactivated-time',
      log: 'rotatedLate', key: 'key-1', requiredPurpose: 'assertionMethod', statedTime: '2026-01-03T00:00:00.250Z',
      trustedTimeNotAfter: '2026-01-03T00:00:00.300Z',
      expected: { status: 'not_authorized', reason: 'key_deactivated', foundIn: ['assertionMethod'], signature: 'invalid', signatureReason: 'key_not_authorized' }
    },
    {
      id: 'did-deactivated-later',
      log: 'deactivated', key: 'key-2', requiredPurpose: 'assertionMethod', statedTime: '2026-01-03T12:00:00Z',
      expected: { status: 'indeterminate', reason: 'did_deactivated_after_stated_time', boundaryVersionNumber: 4, boundaryTime: deactivatedAt, signature: 'indeterminate' }
    },
    {
      id: 'did-deactivated-later-evidence-before',
      log: 'deactivated', key: 'key-2', requiredPurpose: 'assertionMethod', statedTime: '2026-01-03T12:00:00Z',
      trustedTimeNotAfter: '2026-01-04T00:00:00Z',
      expected: { status: 'authorized', basis: 'time_evidence', signature: 'valid' }
    },
    {
      id: 'did-deactivated-before-stated-time',
      log: 'deactivated', key: 'key-2', requiredPurpose: 'assertionMethod', statedTime: deactivatedAt,
      expected: { status: 'not_authorized', reason: 'did_deactivated', foundIn: ['authentication', 'assertionMethod'], signature: 'invalid', signatureReason: 'key_not_authorized' }
    }
  ];

  const payload = new TextEncoder().encode(INPUTS.payload);
  return {
    formatVersion: 1,
    description:
      'RFC-001 §6.2.2: key checks at a stated time against a did:webvh log. Log "rotated": (1) key-1 under authentication, assertionMethod and capabilityDelegation; (2) key-1 leaves capabilityDelegation; (3) key-1 deactivated, key-2 added. Log "deactivated" adds (4) a deactivation. Log "rotatedLate" is "rotated" with key-1\'s deactivated time 500 ms after entry (3)\'s versionTime, as the SDK writes a rotation. A key authorized at the stated time and retired later is indeterminate unless trustedTimeNotAfter is earlier than the retirement. The entry that gives a key a deactivated time retires it from the entry\'s versionTime; the deactivated time itself is not compared. TEST-ONLY keys.',
    regenerate: 'WRITE_KEY_AT_TIME_VECTORS=1 npm --prefix sdk test -- KeyAtTimeVectors.test.ts',
    inputs: INPUTS,
    did,
    logs: { rotated: rotated.log, deactivated: deactivated.log, rotatedLate: rotatedLate.log },
    signatures: {
      'key-1': bytesToHex(ed25519.sign(payload, hexToBytes(INPUTS.key1PrivateKeyHex))),
      'key-2': bytesToHex(ed25519.sign(payload, hexToBytes(INPUTS.key2PrivateKeyHex)))
    },
    vectors
  };
}

if (process.env.WRITE_KEY_AT_TIME_VECTORS === '1') {
  it('writes the vectors', async () => {
    fs.writeFileSync(FIXTURE_PATH, `${JSON.stringify(await generate(), null, 2)}\n`);
  });
}

const fixture = JSON.parse(fs.readFileSync(FIXTURE_PATH, 'utf8')) as Fixture;
const keyId = (key: string) => `${fixture.did}#${key}`;
const otherKey = (key: 'key-1' | 'key-2') => (key === 'key-1' ? 'key-2' : 'key-1');

describe('key checks at a stated time (RFC-001 §6.2.2)', () => {
  it.each(fixture.vectors.map((vector) => [vector.id, vector] as const))('%s', async (_id, vector) => {
    const log = fixture.logs[vector.log];
    const options = {
      keyId: keyId(vector.key),
      requiredPurpose: vector.requiredPurpose,
      statedTime: vector.statedTime,
      ...(vector.trustedTimeNotAfter !== undefined ? { trustedTimeNotAfter: vector.trustedTimeNotAfter } : {})
    };
    const result = await checkDidWebvhKeyAtTime(log, { ...options, did: fixture.did });

    expect(result.status).toBe(vector.expected.status);
    expect(result.keyId).toBe(keyId(vector.key));
    if (result.status === 'authorized') {
      expect(result.basis).toBe(vector.expected.basis);
      expect(result.publicKeyMultibase).toBe(publicKeyMultibase(fixture.inputs[vector.key === 'key-1' ? 'key1PrivateKeyHex' : 'key2PrivateKeyHex']));
    } else if (result.status === 'not_authorized') {
      expect(result.reason).toBe(vector.expected.reason);
      expect(result.foundIn).toEqual(vector.expected.foundIn);
    } else {
      expect(result.reason).toBe(vector.expected.reason);
      expect(result.boundaryTime).toBe(vector.expected.boundaryTime);
      expect(result.boundaryVersionId?.split('-')[0]).toBe(String(vector.expected.boundaryVersionNumber));
    }

    const client = new AgentDidClient();
    await client.importDidWebvhHistory(log);
    const signature = fixture.signatures[vector.wrongSignature ? otherKey(vector.key) : vector.key];
    const { keyId: _keyId, ...signatureOptions } = options;
    const verified = await client.verifySignatureAtTime(fixture.did, fixture.inputs.payload, signature, keyId(vector.key), signatureOptions);
    expect(verified.status).toBe(vector.expected.signature);
    if (verified.status === 'invalid') {
      expect(verified.reason).toBe(vector.expected.signatureReason);
    }
  });

  it('rejects a log of another DID', async () => {
    await expect(
      checkDidWebvhKeyAtTime(fixture.logs.rotated, { keyId: keyId('key-2'), statedTime: '2026-01-03T12:00:00Z', did: 'did:webvh:QmOther:example.com' })
    ).rejects.toThrow();
  });

  it('rejects a tampered log', async () => {
    const tampered = fixture.logs.rotated.replace('"time-bot"', '"evil-bot"');
    await expect(
      checkDidWebvhKeyAtTime(tampered, { keyId: keyId('key-2'), statedTime: '2026-01-03T12:00:00Z' })
    ).rejects.toThrow();
  });

  it('throws on unreadable time evidence', async () => {
    await expect(
      checkDidWebvhKeyAtTime(fixture.logs.rotated, { keyId: keyId('key-2'), statedTime: '2026-01-03T12:00:00Z', trustedTimeNotAfter: 'soon' })
    ).rejects.toThrow(TypeError);
  });

  it('is indeterminate without a did:webvh log in the client', async () => {
    const client = new AgentDidClient();
    const result = await client.verifySignatureAtTime(fixture.did, fixture.inputs.payload, fixture.signatures['key-2'], keyId('key-2'), {
      statedTime: '2026-01-03T12:00:00Z'
    });
    expect(result).toEqual({ status: 'indeterminate', key: { status: 'indeterminate', keyId: keyId('key-2'), reason: 'history_unavailable' } });
  });

  it('defaults to assertionMethod', async () => {
    const result = await checkDidWebvhKeyAtTime(fixture.logs.rotated, { keyId: keyId('key-2'), statedTime: '2026-01-03T12:00:00Z' });
    expect(result.status).toBe('authorized');
  });
});

describe('parseRfc3339Millis (same cases as the Python SDK)', () => {
  it.each([
    ['2026-01-03T00:00:00Z', 1767398400000],
    ['2026-01-03T01:00:00+01:00', 1767398400000],
    ['2026-01-03T00:00:00.123456789z', 1767398400123],
    ['2024-02-29T00:00:00Z', 1709164800000],
    ['2026-02-29T00:00:00Z', undefined],
    ['0000-01-01T00:00:00Z', undefined],
    ['2026-01-03 00:00:00Z', undefined],
    ['2026-01-03T24:00:00Z', undefined],
    ['2026-01-03T00:00:00+24:00', undefined],
    [1767398400, undefined]
  ] as Array<[unknown, number | undefined]>)('%p', (value, expected) => {
    expect(parseRfc3339Millis(value)).toBe(expected);
  });
});
