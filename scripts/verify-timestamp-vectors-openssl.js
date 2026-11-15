#!/usr/bin/env node
/**
 * Cross-checks fixtures/timestamp-vectors.json with an independent implementation, `openssl ts -verify` (ADR-007,
 * D-11d): every vector the SDKs accept must verify with OpenSSL over the same message and anchors, and the vectors
 * rejected for the signature, the chain or the imprint must fail with OpenSSL too. The EKU, hash-algorithm and parsing
 * cases are SDK policy or malformed input and are not cross-checked.
 *
 * Needs `openssl` 3.x on the PATH. Usage: node scripts/verify-timestamp-vectors-openssl.js
 */

const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync } = require('child_process');

const FIXTURE = JSON.parse(fs.readFileSync(path.join(__dirname, '..', 'fixtures', 'timestamp-vectors.json'), 'utf8'));
/** Rejections OpenSSL must reproduce (the others are SDK policy or input OpenSSL rejects before verifying). */
const CROSS_CHECKED_REJECTIONS = new Set(['verification_failed', 'imprint_mismatch']);

/**
 * `genTime` of a token as Unix seconds: the first GeneralizedTime (YYYYMMDDHHMMSS[.fff]Z) in it, which is TSTInfo's
 * (it precedes the certificates). OpenSSL validates the chain at the current time unless told otherwise; RFC 3161 and
 * the SDKs validate it at `genTime`, so the cross-check passes `-attime`.
 */
function genTimeSeconds(token) {
  const match = /\u0018[\u000f-\u0013](\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(?:\.\d+)?Z/u.exec(token.toString('latin1'));
  if (!match) return undefined;
  const [, y, mo, d, h, mi, se] = match;
  return Math.floor(Date.UTC(+y, +mo - 1, +d, +h, +mi, +se) / 1000);
}

function isBareToken(token) {
  // A ContentInfo starts with SEQUENCE then OBJECT IDENTIFIER; a TimeStampResp with SEQUENCE then SEQUENCE.
  const lengthBytes = token[1] & 0x80 ? 1 + (token[1] & 0x7f) : 1;
  return token[1 + lengthBytes] === 0x06;
}

const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'agent-did-ts-verify-'));
let failures = 0;
let checked = 0;
try {
  fs.writeFileSync(path.join(dir, 'message.bin'), Buffer.from(FIXTURE.message, 'hex'));
  for (const vector of FIXTURE.vectors) {
    const valid = vector.expected.status === 'valid';
    if (!valid && !CROSS_CHECKED_REJECTIONS.has(vector.expected.reason)) continue;
    const token = Buffer.from(vector.token, 'base64');
    fs.writeFileSync(path.join(dir, 'token.der'), token);
    fs.writeFileSync(path.join(dir, 'anchors.pem'), vector.anchors.map((name) => FIXTURE.anchors[name]).join('\n'));
    const args = ['ts', '-verify', '-data', 'message.bin', '-in', 'token.der', '-CAfile', 'anchors.pem'];
    if (isBareToken(token)) args.push('-token_in');
    const genTime = genTimeSeconds(token);
    if (genTime !== undefined) args.push('-attime', String(genTime));
    const run = spawnSync('openssl', args, { cwd: dir, encoding: 'utf8' });
    const ok = run.status === 0 && /Verification: OK/u.test(run.stdout);
    checked += 1;
    if (ok !== valid) {
      failures += 1;
      console.error(`${vector.name}: SDKs say ${valid ? 'valid' : vector.expected.reason}, OpenSSL says ${ok ? 'OK' : 'FAILED'}`);
      console.error((run.stdout + run.stderr).trim());
    } else {
      console.log(`${vector.name}: ${ok ? 'OK' : 'rejected'} (agrees)`);
    }
  }
} finally {
  fs.rmSync(dir, { recursive: true, force: true });
}

if (failures > 0) {
  console.error(`OpenSSL disagrees with the SDK expectations on ${failures} of ${checked} vectors`);
  process.exit(1);
}
console.log(`OpenSSL agrees with the SDK expectations on ${checked} vectors`);
