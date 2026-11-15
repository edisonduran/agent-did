#!/usr/bin/env node
/**
 * Records fixtures/timestamp-vectors.json: RFC 3161 timestamp tokens that both SDKs must verify with
 * `verifyTimestampToken` / `verify_timestamp_token` (ADR-007, D-11d).
 *
 * - Two real TSAs (FreeTSA and DigiCert) timestamp the SHA-256 of `message`, a TEST-ONLY `signMessage` signature. The request
 *   carries only that hash. Their trust anchors are downloaded from the TSAs' published URLs.
 * - A test TSA built with OpenSSL (`openssl ts -reply`) issues the valid token and the negative cases OpenSSL can make
 *   (imprint over other bytes, SHA-1 imprint, untrusted root, tampered `genTime`, bare token, not granted, malformed).
 * - The cases OpenSSL refuses to sign (a TSA certificate without a critical `id-kp-timeStamping`, a `genTime` outside
 *   the TSA certificate's validity) are signed with pkijs from the same test keys.
 *
 * Run by a maintainer, not in CI: the real-TSA tokens change on every run. Needs network access, `openssl` 3.x on the
 * PATH and `npm --prefix sdk ci`. Verification in CI: sdk/tests/Timestamp.test.ts, sdk-python/tests/test_timestamp.py
 * and scripts/verify-timestamp-vectors-openssl.js.
 *
 * Usage: node scripts/record-timestamp-vectors.js
 */

const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');
const { execFileSync } = require('child_process');

const SDK_MODULES = path.join(__dirname, '..', 'sdk', 'node_modules');
const asn1js = require(path.join(SDK_MODULES, 'asn1js'));
const pkijs = require(path.join(SDK_MODULES, 'pkijs'));

const OUTPUT = path.join(__dirname, '..', 'fixtures', 'timestamp-vectors.json');
/** TEST-ONLY Ed25519 seed: public on purpose, signs nothing real. */
const SIGNING_SEED_HEX = '7a6b5c4d3e2f10017a6b5c4d3e2f10017a6b5c4d3e2f10017a6b5c4d3e2f1001';
const SIGNED_PAYLOAD = 'agent-did timestamp vector';
/** RFC-001 §7 message-signing prefix (AGENT_DID_MESSAGE_SIGNING_PREFIX): `message` is what `signMessage` returns. */
const MESSAGE_SIGNING_PREFIX = 'agent-did/v1/message' + String.fromCharCode(10);
const REAL_TSAS = [
  {
    name: 'freetsa',
    url: 'https://freetsa.org/tsr',
    anchor: { name: 'freetsa-root', url: 'https://freetsa.org/files/cacert.pem' },
  },
  {
    name: 'digicert',
    url: 'http://timestamp.digicert.com',
    anchor: { name: 'digicert-trusted-root-g4', url: 'https://cacerts.digicert.com/DigiCertTrustedRootG4.crt' },
  },
];
const OID_TST_INFO = '1.2.840.113549.1.9.16.1.4';
const OID_SHA256 = '2.16.840.1.101.3.4.2.1';
const engine = new pkijs.CryptoEngine({ name: 'recorder', crypto: globalThis.crypto });

function ed25519Signature() {
  const pkcs8 = Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), Buffer.from(SIGNING_SEED_HEX, 'hex')]);
  const key = crypto.createPrivateKey({ key: pkcs8, format: 'der', type: 'pkcs8' });
  return new Uint8Array(crypto.sign(null, Buffer.from(MESSAGE_SIGNING_PREFIX + SIGNED_PAYLOAD, 'utf8'), key));
}

function openssl(args, cwd) {
  return execFileSync('openssl', args, { cwd, stdio: ['ignore', 'pipe', 'pipe'] });
}

function derToPem(der) {
  const body = Buffer.from(der).toString('base64').replace(/(.{64})/g, '$1\n').trim();
  return `-----BEGIN CERTIFICATE-----\n${body}\n-----END CERTIFICATE-----\n`;
}

function toArrayBuffer(bytes) {
  return bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength);
}

/** Builds the test PKI: a root, the test TSA and two TSA certificates OpenSSL will not sign tokens with. */
function buildTestPki(dir) {
  const write = (name, text) => fs.writeFileSync(path.join(dir, name), text);
  write(
    'ext.cnf',
    [
      '[root]',
      'basicConstraints = critical, CA:TRUE',
      'keyUsage = critical, keyCertSign, cRLSign',
      'subjectKeyIdentifier = hash',
      '[tsa]',
      'basicConstraints = critical, CA:FALSE',
      'keyUsage = critical, digitalSignature',
      'extendedKeyUsage = critical, timeStamping',
      'subjectKeyIdentifier = hash',
      'authorityKeyIdentifier = keyid',
      '[tsa_noncritical]',
      'basicConstraints = critical, CA:FALSE',
      'keyUsage = critical, digitalSignature',
      'extendedKeyUsage = timeStamping',
      'subjectKeyIdentifier = hash',
      'authorityKeyIdentifier = keyid',
      '[tsa_wrong_purpose]',
      'basicConstraints = critical, CA:FALSE',
      'keyUsage = critical, digitalSignature',
      'extendedKeyUsage = critical, serverAuth',
      'subjectKeyIdentifier = hash',
      'authorityKeyIdentifier = keyid',
      '',
    ].join('\n')
  );
  const key = (name) => openssl(['genpkey', '-algorithm', 'EC', '-pkeyopt', 'ec_paramgen_curve:P-256', '-out', `${name}.key`], dir);
  for (const name of ['root', 'other-root', 'tsa', 'tsa-noncritical', 'tsa-wrong-purpose']) key(name);
  for (const root of ['root', 'other-root']) {
    openssl(['req', '-new', '-x509', '-key', `${root}.key`, '-subj', `/CN=Agent-DID TEST ${root}`, '-days', '7300',
      '-config', 'ext.cnf', '-extensions', 'root', '-out', `${root}.pem`], dir);
  }
  const issue = (name, section) => {
    openssl(['req', '-new', '-key', `${name}.key`, '-subj', `/CN=Agent-DID TEST ${name}`, '-out', `${name}.csr`], dir);
    openssl(['x509', '-req', '-in', `${name}.csr`, '-CA', 'root.pem', '-CAkey', 'root.key', '-CAcreateserial',
      '-days', '7300', '-extfile', 'ext.cnf', '-extensions', section, '-out', `${name}.pem`], dir);
  };
  issue('tsa', 'tsa');
  issue('tsa-noncritical', 'tsa_noncritical');
  issue('tsa-wrong-purpose', 'tsa_wrong_purpose');
  write(
    'tsa.cnf',
    [
      '[ tsa ]',
      'default_tsa = test_tsa',
      '[ test_tsa ]',
      `dir = ${dir.replace(/\\/g, '/')}`,
      'serial = $dir/tsaserial',
      'signer_cert = $dir/tsa.pem',
      'certs = $dir/tsa.pem',
      'signer_key = $dir/tsa.key',
      'signer_digest = sha256',
      'default_policy = 1.3.6.1.4.1.4146.2.3',
      'digests = sha1, sha256, sha384, sha512',
      'accuracy = secs:1, millisecs:500, microsecs:100',
      'ordering = no',
      'tsa_name = no',
      'ess_cert_id_chain = no',
      'ess_cert_id_alg = sha256',
      '',
    ].join('\n')
  );
  write('tsaserial', '01\n');
}

function testTsaToken(dir, data, digest) {
  fs.writeFileSync(path.join(dir, 'data.bin'), data);
  openssl(['ts', '-query', '-data', 'data.bin', `-${digest}`, '-cert', '-out', 'q.tsq'], dir);
  openssl(['ts', '-reply', '-config', 'tsa.cnf', '-queryfile', 'q.tsq', '-out', 'r.tsr'], dir);
  return new Uint8Array(fs.readFileSync(path.join(dir, 'r.tsr')));
}

function bareToken(dir, response) {
  fs.writeFileSync(path.join(dir, 'bare.tsr'), response);
  openssl(['ts', '-reply', '-in', 'bare.tsr', '-token_out', '-out', 'bare.tst'], dir);
  return new Uint8Array(fs.readFileSync(path.join(dir, 'bare.tst')));
}

/** Changes one digit of `genTime` inside the signed TSTInfo, keeping the DER valid: the signature no longer verifies. */
function tamperGenTime(response) {
  const text = Buffer.from(response).toString('latin1');
  const match = /\x18\x0f(\d{14})Z/u.exec(text);
  if (!match) throw new Error('genTime not found in the test token');
  const index = match.index + 2 + 13; // last digit of the seconds
  const copy = Buffer.from(response);
  copy[index] = copy[index] === 0x30 ? 0x31 : 0x30;
  return new Uint8Array(copy);
}

async function importEcKey(dir, name) {
  const pkcs8 = openssl(['pkcs8', '-topk8', '-nocrypt', '-in', `${name}.key`, '-outform', 'DER'], dir);
  return globalThis.crypto.subtle.importKey('pkcs8', pkcs8, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign']);
}

function loadCertificate(dir, name) {
  const der = openssl(['x509', '-in', `${name}.pem`, '-outform', 'DER'], dir);
  return pkijs.Certificate.fromBER(toArrayBuffer(new Uint8Array(der)));
}

/** A granted TimeStampResp signed with pkijs by `name`'s key, with the signed attributes RFC 3161 requires. */
async function pkijsToken(dir, name, message, genTime) {
  const certificate = loadCertificate(dir, name);
  const privateKey = await importEcKey(dir, name);
  const tstInfo = new pkijs.TSTInfo({
    version: 1,
    policy: '1.3.6.1.4.1.4146.2.3',
    messageImprint: new pkijs.MessageImprint({
      hashAlgorithm: new pkijs.AlgorithmIdentifier({ algorithmId: OID_SHA256 }),
      hashedMessage: new asn1js.OctetString({ valueHex: crypto.createHash('sha256').update(message).digest() }),
    }),
    serialNumber: new asn1js.Integer({ value: 4242 }),
    genTime: new Date(Math.floor(genTime.getTime() / 1000) * 1000),
    accuracy: new pkijs.Accuracy({ seconds: 1 }),
  });
  const eContent = tstInfo.toSchema().toBER(false);
  const certHash = crypto.createHash('sha256').update(Buffer.from(certificate.toSchema().toBER(false))).digest();
  const signerInfo = new pkijs.SignerInfo({
    version: 1,
    sid: new pkijs.IssuerAndSerialNumber({ issuer: certificate.issuer, serialNumber: certificate.serialNumber }),
    signedAttrs: new pkijs.SignedAndUnsignedAttributes({
      type: 0,
      attributes: [
        new pkijs.Attribute({ type: '1.2.840.113549.1.9.3', values: [new asn1js.ObjectIdentifier({ value: OID_TST_INFO })] }),
        new pkijs.Attribute({
          type: '1.2.840.113549.1.9.4',
          values: [new asn1js.OctetString({ valueHex: crypto.createHash('sha256').update(Buffer.from(eContent)).digest() })],
        }),
        // signingCertificateV2 { certs: [ ESSCertIDv2 { certHash } ] } (SHA-256, the default algorithm)
        new pkijs.Attribute({
          type: '1.2.840.113549.1.9.16.2.47',
          values: [new asn1js.Sequence({ value: [new asn1js.Sequence({ value: [new asn1js.Sequence({ value: [new asn1js.OctetString({ valueHex: certHash })] })] })] })],
        }),
      ],
    }),
  });
  const signedData = new pkijs.SignedData({
    version: 3,
    encapContentInfo: new pkijs.EncapsulatedContentInfo({ eContentType: OID_TST_INFO, eContent: new asn1js.OctetString({ valueHex: eContent }) }),
    signerInfos: [signerInfo],
    certificates: [certificate],
  });
  // pkijs splits eContent into a constructed OCTET STRING; RFC 3161 tokens use the DER (primitive) form.
  signedData.encapContentInfo.eContent = new asn1js.OctetString({ valueHex: eContent });
  await signedData.sign(privateKey, 0, 'SHA-256', undefined, engine);
  const response = new pkijs.TimeStampResp({
    status: new pkijs.PKIStatusInfo({ status: 0 }),
    timeStampToken: new pkijs.ContentInfo({ contentType: '1.2.840.113549.1.7.2', content: signedData.toSchema(true) }),
  });
  return new Uint8Array(response.toSchema().toBER(false));
}

async function realTsaToken(tsa, message) {
  const request = new pkijs.TimeStampReq({
    version: 1,
    messageImprint: new pkijs.MessageImprint({
      hashAlgorithm: new pkijs.AlgorithmIdentifier({ algorithmId: OID_SHA256 }),
      hashedMessage: new asn1js.OctetString({ valueHex: crypto.createHash('sha256').update(message).digest() }),
    }),
    nonce: new asn1js.Integer({ valueHex: crypto.randomBytes(8).map((byte, index) => (index === 0 ? (byte & 0x7f) | 1 : byte)) }),
    certReq: true,
  });
  const response = await fetch(tsa.url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/timestamp-query' },
    body: Buffer.from(request.toSchema().toBER(false)),
  });
  if (!response.ok) throw new Error(`${tsa.name}: HTTP ${response.status}`);
  return new Uint8Array(await response.arrayBuffer());
}

async function downloadAnchor(anchor) {
  const response = await fetch(anchor.url);
  if (!response.ok) throw new Error(`${anchor.name}: HTTP ${response.status}`);
  const bytes = Buffer.from(await response.arrayBuffer());
  return bytes.toString('latin1').includes('-----BEGIN CERTIFICATE-----') ? bytes.toString('latin1') : derToPem(bytes);
}

/** What a granted token says (for the `valid` expectations): genTime, genTime + accuracy and the serial number. */
function describe(token) {
  let content = asn1js.fromBER(toArrayBuffer(token)).result;
  if (!(content.valueBlock.value[0] instanceof asn1js.ObjectIdentifier)) {
    content = new pkijs.TimeStampResp({ schema: content }).timeStampToken.toSchema();
  }
  const signedData = new pkijs.SignedData({ schema: new pkijs.ContentInfo({ schema: content }).content });
  const tstInfo = pkijs.TSTInfo.fromBER(signedData.encapContentInfo.eContent.getValue());
  const accuracy = tstInfo.accuracy ?? {};
  const accuracyMs = (accuracy.seconds ?? 0) * 1000 + (accuracy.millis ?? 0) + Math.ceil((accuracy.micros ?? 0) / 1000);
  return {
    status: 'valid',
    genTime: tstInfo.genTime.toISOString(),
    trustedTimeNotAfter: new Date(tstInfo.genTime.getTime() + accuracyMs).toISOString(),
    serialNumber: Buffer.from(tstInfo.serialNumber.valueBlock.valueHexView).toString('hex'),
  };
}

async function main() {
  const message = ed25519Signature();
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'agent-did-tsa-'));
  try {
    buildTestPki(dir);
    const anchors = {};
    for (const tsa of REAL_TSAS) anchors[tsa.anchor.name] = await downloadAnchor(tsa.anchor);
    anchors['test-root'] = fs.readFileSync(path.join(dir, 'root.pem'), 'latin1');
    anchors['test-other-root'] = fs.readFileSync(path.join(dir, 'other-root.pem'), 'latin1');

    const vectors = [];
    const add = (name, source, token, anchorNames, expected, description) =>
      vectors.push({ name, source, description, anchors: anchorNames, token: Buffer.from(token).toString('base64'), expected });

    for (const tsa of REAL_TSAS) {
      const token = await realTsaToken(tsa, message);
      add(`${tsa.name}-granted`, tsa.name, token, [tsa.anchor.name], describe(token), `Token from ${tsa.url} over the SHA-256 of message`);
    }

    const valid = testTsaToken(dir, message, 'sha256');
    add('test-tsa-granted', 'test-tsa', valid, ['test-root'], describe(valid), 'OpenSSL test TSA, SHA-256 imprint, accuracy 1.5001 s');
    const sha384 = testTsaToken(dir, message, 'sha384');
    add('test-tsa-sha384', 'test-tsa', sha384, ['test-root'], describe(sha384), 'OpenSSL test TSA, SHA-384 imprint');
    const bare = bareToken(dir, valid);
    add('test-tsa-bare-token', 'test-tsa', bare, ['test-root'], describe(bare), 'The TimeStampToken of test-tsa-granted without the TimeStampResp wrapper');
    add('test-tsa-several-anchors', 'test-tsa', valid, ['test-other-root', 'test-root', REAL_TSAS[0].anchor.name], describe(valid), 'test-tsa-granted verified against several anchors, one of them right');

    add('untrusted-root', 'test-tsa', valid, ['test-other-root'], { status: 'invalid', reason: 'verification_failed' }, 'test-tsa-granted verified against an anchor that did not issue the TSA certificate');
    add('imprint-over-other-bytes', 'test-tsa', testTsaToken(dir, Buffer.from('other bytes'), 'sha256'), ['test-root'], { status: 'invalid', reason: 'imprint_mismatch' }, 'Token over other bytes');
    add('sha1-imprint', 'test-tsa', testTsaToken(dir, message, 'sha1'), ['test-root'], { status: 'invalid', reason: 'hash_algorithm_unsupported' }, 'Token over the SHA-1 of message');
    add('tampered-gen-time', 'test-tsa', tamperGenTime(valid), ['test-root'], { status: 'invalid', reason: 'verification_failed' }, 'test-tsa-granted with one digit of genTime changed after signing');
    add('eku-not-critical', 'test-tsa', await pkijsToken(dir, 'tsa-noncritical', message, new Date()), ['test-root'], { status: 'invalid', reason: 'not_a_timestamping_certificate' }, 'Signed by a certificate whose timeStamping EKU is not critical');
    add('eku-wrong-purpose', 'test-tsa', await pkijsToken(dir, 'tsa-wrong-purpose', message, new Date()), ['test-root'], { status: 'invalid', reason: 'not_a_timestamping_certificate' }, 'Signed by a certificate whose critical EKU is serverAuth');
    add('gen-time-before-certificate', 'test-tsa', await pkijsToken(dir, 'tsa', message, new Date('2001-01-01T00:00:00Z')), ['test-root'], { status: 'invalid', reason: 'verification_failed' }, 'genTime before the TSA certificate was valid: the chain is checked at genTime');
    add('pkijs-signed-control', 'test-tsa', await pkijsToken(dir, 'tsa', message, new Date()), ['test-root'], null, 'Control for the pkijs-signed cases: the same construction with the valid TSA certificate verifies');
    add('not-granted', 'synthetic', Uint8Array.from([0x30, 0x05, 0x30, 0x03, 0x02, 0x01, 0x02]), ['test-root'], { status: 'invalid', reason: 'not_granted' }, 'TimeStampResp with status rejection (2) and no token');
    add('truncated', 'synthetic', valid.slice(0, valid.length - 10), ['test-root'], { status: 'invalid', reason: 'token_malformed' }, 'test-tsa-granted without its last 10 bytes');
    add('not-der', 'synthetic', Buffer.from('not a timestamp token'), ['test-root'], { status: 'invalid', reason: 'token_malformed' }, 'Arbitrary bytes');
    const control = vectors.find((vector) => vector.name === 'pkijs-signed-control');
    control.expected = describe(Buffer.from(control.token, 'base64'));

    const fixture = {
      description:
        'RFC 3161 timestamp tokens (ADR-007). Both SDKs verify every vector with verifyTimestampToken / verify_timestamp_token over `message` and the named anchors, and must return `expected`. Positive vectors are also checked with `openssl ts -verify` (scripts/verify-timestamp-vectors-openssl.js).',
      regenerate: 'node scripts/record-timestamp-vectors.js (maintainer only: contacts FreeTSA and DigiCert; real tokens change on every run)',
      recorded: new Date().toISOString().slice(0, 10),
      message: Buffer.from(message).toString('hex'),
      messageDescription: `signMessage(${JSON.stringify(SIGNED_PAYLOAD)}) with the TEST-ONLY agent key seed (the Ed25519 signature of the RFC-001 message-signing prefix + payload)`,
      signedPayload: SIGNED_PAYLOAD,
      signingSeed: SIGNING_SEED_HEX,
      anchors,
      vectors,
    };
    fs.writeFileSync(OUTPUT, JSON.stringify(fixture, null, 2) + '\n', 'utf8');
    console.log(`Wrote ${vectors.length} vectors to ${path.relative(process.cwd(), OUTPUT)}`);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
