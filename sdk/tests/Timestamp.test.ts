/**
 * RFC 3161 timestamp tokens (ADR-007, D-11b): fixtures/timestamp-vectors.json, recorded from FreeTSA, DigiCert and an
 * OpenSSL test TSA (scripts/record-timestamp-vectors.js). The Python SDK runs the same vectors in
 * sdk-python/tests/test_timestamp.py.
 */
import fs from 'fs';
import path from 'path';
import * as asn1js from 'asn1js';
import * as pkijs from 'pkijs';
import { sha256 } from '@noble/hashes/sha256';
import { createTimestampRequest, verifyTimestampToken, VerifyTimestampTokenResult } from '../src';

interface TimestampVector {
  name: string;
  anchors: string[];
  token: string;
  expected: VerifyTimestampTokenResult;
}

const FIXTURE = JSON.parse(
  fs.readFileSync(path.join(__dirname, '..', '..', 'fixtures', 'timestamp-vectors.json'), 'utf8')
) as { message: string; anchors: Record<string, string>; vectors: TimestampVector[] };
const MESSAGE = new Uint8Array(Buffer.from(FIXTURE.message, 'hex'));
const anchorsOf = (names: string[]) => names.map((name) => FIXTURE.anchors[name]);
const tokenOf = (vector: TimestampVector) => new Uint8Array(Buffer.from(vector.token, 'base64'));
const byName = (name: string) => FIXTURE.vectors.find((vector) => vector.name === name) as TimestampVector;

describe('verifyTimestampToken (fixtures/timestamp-vectors.json)', () => {
  it('covers real TSAs, every rejection reason and a bare token', () => {
    const reasons = new Set(
      FIXTURE.vectors.flatMap((vector) => (vector.expected.status === 'invalid' ? [vector.expected.reason] : []))
    );
    expect([...reasons].sort()).toEqual([
      'hash_algorithm_unsupported',
      'imprint_mismatch',
      'not_a_timestamping_certificate',
      'not_granted',
      'token_malformed',
      'verification_failed',
    ]);
    expect(byName('freetsa-granted').expected.status).toBe('valid');
    expect(byName('digicert-granted').expected.status).toBe('valid');
  });

  it.each(FIXTURE.vectors.map((vector) => [vector.name, vector] as const))('%s', async (_name, vector) => {
    const result = await verifyTimestampToken(tokenOf(vector), MESSAGE, { trustAnchors: anchorsOf(vector.anchors) });
    expect(result).toEqual(vector.expected);
  });

  it('accepts anchors as DER bytes', async () => {
    const pem = FIXTURE.anchors['test-root'];
    const der = new Uint8Array(Buffer.from(pem.replace(/-----[^-]+-----|\s/gu, ''), 'base64'));
    const vector = byName('test-tsa-granted');

    expect(await verifyTimestampToken(tokenOf(vector), MESSAGE, { trustAnchors: [der] })).toEqual(vector.expected);
  });

  it('rejects a token over the right hash of other bytes', async () => {
    const vector = byName('test-tsa-granted');
    const other = MESSAGE.slice();
    other[0] ^= 1;

    expect(await verifyTimestampToken(tokenOf(vector), other, { trustAnchors: anchorsOf(vector.anchors) })).toEqual({
      status: 'invalid',
      reason: 'imprint_mismatch',
    });
  });

  it('throws TypeError for invalid arguments, not for an invalid token', async () => {
    const token = tokenOf(byName('test-tsa-granted'));
    const trustAnchors = anchorsOf(['test-root']);

    await expect(verifyTimestampToken('x' as never, MESSAGE, { trustAnchors })).rejects.toThrow(TypeError);
    await expect(verifyTimestampToken(token, 'x' as never, { trustAnchors })).rejects.toThrow(TypeError);
    await expect(verifyTimestampToken(token, MESSAGE, { trustAnchors: [] })).rejects.toThrow(TypeError);
    await expect(verifyTimestampToken(token, MESSAGE, { trustAnchors: ['no certificate here'] })).rejects.toThrow(
      TypeError
    );
    await expect(verifyTimestampToken(token, MESSAGE, { trustAnchors: [new Uint8Array([1, 2, 3])] })).rejects.toThrow(
      TypeError
    );
  });
});

describe('createTimestampRequest', () => {
  it('builds a TimeStampReq with a SHA-256 imprint, certReq and a fresh positive nonce', () => {
    const first = pkijs.TimeStampReq.fromBER(Uint8Array.from(createTimestampRequest(MESSAGE)).buffer);
    const second = pkijs.TimeStampReq.fromBER(Uint8Array.from(createTimestampRequest(MESSAGE)).buffer);

    expect(first.version).toBe(1);
    expect(first.messageImprint.hashAlgorithm.algorithmId).toBe('2.16.840.1.101.3.4.2.1');
    expect(new Uint8Array(first.messageImprint.hashedMessage.valueBlock.valueHexView)).toEqual(sha256(MESSAGE));
    expect(first.certReq).toBe(true);
    const nonce = first.nonce as asn1js.Integer;
    expect(nonce.valueBlock.valueHexView[0] & 0x80).toBe(0);
    expect(Buffer.from(nonce.valueBlock.valueHexView).equals(Buffer.from((second.nonce as asn1js.Integer).valueBlock.valueHexView))).toBe(false);
    expect(() => createTimestampRequest('x' as never)).toThrow(TypeError);
  });
});

describe('verifySignatureAtTime with an RFC 3161 timestamp token', () => {
  const firstVersionTime = (log: string): string =>
    (JSON.parse(log.split('\n').find((line) => line.trim()) as string) as { versionTime: string }).versionTime;

  /** An agent whose key signed the fixture message, and whose key is retired after the token's genTime. */
  async function setUp() {
    const { AgentDidClient, AgentIdentity, LocalKeySigner } = await import('../src');
    const client = new AgentDidClient();
    const identity = new AgentIdentity({ controllerSigner: LocalKeySigner.generate()[0], client });
    const fixture = FIXTURE as unknown as { signedPayload: string; signingSeed: string };
    const agent = await identity.create({ name: 'StampedBot', signer: new LocalKeySigner(fixture.signingSeed) });
    const did = agent.document.id;
    const signature = await identity.signMessage(fixture.signedPayload, fixture.signingSeed);
    expect(signature).toBe(FIXTURE.message);
    const statedTime = firstVersionTime(client.exportDidWebvhHistory(did));
    await client.rotateVerificationMethod(did);
    return { client, did, keyId: `${did}#key-1`, payload: fixture.signedPayload, signature, statedTime };
  }

  it('turns indeterminate into valid with a token that predates the key retirement', async () => {
    const { client, did, keyId, payload, signature, statedTime } = await setUp();
    const vector = byName('test-tsa-granted');

    expect((await client.verifySignatureAtTime(did, payload, signature, keyId, { statedTime })).status).toBe(
      'indeterminate'
    );
    const result = await client.verifySignatureAtTime(did, payload, signature, keyId, {
      statedTime,
      timestampToken: tokenOf(vector),
      tsaTrustAnchors: anchorsOf(vector.anchors),
    });
    expect(result.status).toBe('valid');
  });

  it('returns timestamp_invalid for a token that does not verify or covers another signature', async () => {
    const { client, did, keyId, payload, signature, statedTime } = await setUp();
    const granted = tokenOf(byName('test-tsa-granted'));

    expect(
      await client.verifySignatureAtTime(did, payload, signature, keyId, {
        statedTime,
        timestampToken: granted,
        tsaTrustAnchors: anchorsOf(['test-other-root']),
      })
    ).toEqual({ status: 'invalid', reason: 'timestamp_invalid', timestampRejection: 'verification_failed' });
    const other = (signature.startsWith('0') ? '1' : '0') + signature.slice(1);
    expect(
      await client.verifySignatureAtTime(did, payload, other, keyId, {
        statedTime,
        timestampToken: granted,
        tsaTrustAnchors: anchorsOf(['test-root']),
      })
    ).toEqual({ status: 'invalid', reason: 'timestamp_invalid', timestampRejection: 'imprint_mismatch' });
    expect(
      await client.verifySignatureAtTime(did, payload, 'not-hex', keyId, {
        statedTime,
        timestampToken: granted,
        tsaTrustAnchors: anchorsOf(['test-root']),
      })
    ).toEqual({ status: 'invalid', reason: 'signature_invalid' });
  });

  it('refuses a token together with trustedTimeNotAfter, or without trust anchors', async () => {
    const { client, did, keyId, payload, signature, statedTime } = await setUp();
    const timestampToken = tokenOf(byName('test-tsa-granted'));

    await expect(
      client.verifySignatureAtTime(did, payload, signature, keyId, {
        statedTime,
        timestampToken,
        tsaTrustAnchors: anchorsOf(['test-root']),
        trustedTimeNotAfter: statedTime,
      })
    ).rejects.toThrow(TypeError);
    await expect(
      client.verifySignatureAtTime(did, payload, signature, keyId, { statedTime, timestampToken })
    ).rejects.toThrow(TypeError);
  });
});
