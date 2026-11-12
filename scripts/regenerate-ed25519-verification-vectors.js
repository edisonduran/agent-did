#!/usr/bin/env node
/**
 * Regenerates fixtures/ed25519-verification-vectors.json: the Ed25519 verification rule of RFC-001 §7
 * as test vectors that both SDKs run (TypeScript `verifyEd25519`, Python `verify_ed25519`).
 *
 * Ed25519 libraries disagree on edge cases (ZIP-215 in @noble/curves, stricter libsodium in PyNaCl). The
 * SDKs apply one rule before the curve equation: 64-byte signature and 32-byte key, S < L, and A and R
 * canonical encodings of points of the prime-order subgroup (no small order, no torsion component). Every
 * vector flagged `valid: false` is rejected for exactly that reason; the control vectors are valid.
 *
 * The output is deterministic. The seeds below are TEST-ONLY keys, public on purpose.
 * The vectors are built here with noble's point arithmetic, independently of the SDKs' verification.
 *
 * Usage: node scripts/regenerate-ed25519-verification-vectors.js   (needs `npm ci` in sdk/)
 */

const fs = require('fs');
const path = require('path');
const sdkModules = path.join(__dirname, '..', 'sdk', 'node_modules');
const { ed25519 } = require(path.join(sdkModules, '@noble/curves', 'ed25519'));
const { sha512 } = require(path.join(sdkModules, '@noble/hashes', 'sha512'));

const Point = ed25519.ExtendedPoint;
const L = ed25519.CURVE.n;
const P = 2n ** 255n - 19n;

const hex = (bytes) => Buffer.from(bytes).toString('hex');
const bytesToBigIntLE = (bytes) => BigInt('0x' + Buffer.from(bytes).reverse().toString('hex'));
const bigIntToBytesLE = (value, length = 32) =>
  Buffer.from(value.toString(16).padStart(length * 2, '0'), 'hex').reverse();
const mod = (value) => ((value % L) + L) % L;

// A point of order 8 (canonical encoding): the torsion component added to A or R in the mixed-order vectors.
const TORSION = Point.fromHex('c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a');
const IDENTITY = '01' + '00'.repeat(31);

const secret = mod(bytesToBigIntLE(sha512(Buffer.from('agent-did ed25519 vectors: a')).subarray(0, 32)));
const nonce = mod(bytesToBigIntLE(sha512(Buffer.from('agent-did ed25519 vectors: r')).subarray(0, 32)));
const publicPoint = Point.BASE.multiply(secret);
const encode = (point) => point.toRawBytes();

/** Signs `message` by hand for public key point `A` and signature point `R` (secret = scalar of A's honest part). */
function signWith(message, publicKey, commitmentPoint, s) {
  const R = encode(commitmentPoint);
  const k = mod(bytesToBigIntLE(sha512(Buffer.concat([R, publicKey, message]))));
  return { R, k, S: mod(nonce + k * s) };
}

const vectors = [];
function add(name, description, publicKey, message, signature, valid) {
  vectors.push({
    name,
    description,
    publicKey: hex(publicKey),
    message: hex(message),
    signature: hex(signature),
    valid
  });
}

for (let index = 0; index < 2; index += 1) {
  const message = Buffer.from(`ed25519 vector message ${index}`);
  const honestKey = encode(publicPoint);

  // Control: an ordinary signature
  const honest = signWith(message, honestKey, Point.BASE.multiply(nonce), secret);
  const honestSignature = Buffer.concat([honest.R, bigIntToBytesLE(honest.S)]);
  add(`valid-${index}`, 'An ordinary signature by a key in the prime-order subgroup', honestKey, message, honestSignature, true);

  add(
    `wrong-message-${index}`,
    'A valid signature over a different message',
    honestKey,
    Buffer.from(`not the signed message ${index}`),
    honestSignature,
    false
  );

  // S + L: the same signature with a non-canonical S (S >= L)
  add(
    `non-canonical-s-${index}`,
    'The ordinary signature with S replaced by S + L (S must be below the group order)',
    honestKey,
    message,
    Buffer.concat([honest.R, bigIntToBytesLE(honest.S + L)]),
    false
  );

  // Torsion in A: public key A + T, honest R
  const mixedKey = encode(publicPoint.add(TORSION));
  const mixedA = signWith(message, mixedKey, Point.BASE.multiply(nonce), secret);
  add(
    `torsion-in-public-key-${index}`,
    'Public key A + T where T has order 8 (a torsion component in the key)',
    mixedKey,
    message,
    Buffer.concat([mixedA.R, bigIntToBytesLE(mixedA.S)]),
    false
  );

  // Torsion in R: honest key, R + T
  const mixedR = signWith(message, honestKey, Point.BASE.multiply(nonce).add(TORSION), secret);
  add(
    `torsion-in-r-${index}`,
    'Signature point R + T where T has order 8 (a torsion component in R)',
    honestKey,
    message,
    Buffer.concat([mixedR.R, bigIntToBytesLE(mixedR.S)]),
    false
  );

  // Small-order key: the identity as public key with the identity as R and S = 0 verifies for EVERY message
  add(
    `small-order-public-key-${index}`,
    'The identity as public key, R = identity and S = 0: valid under ZIP-215 for any message',
    Buffer.from(IDENTITY, 'hex'),
    message,
    Buffer.from(IDENTITY + '00'.repeat(32), 'hex'),
    false
  );
}

// The identity written with a non-canonical y (1 + p): a second encoding of the same small-order point
const nonCanonicalIdentity = bigIntToBytesLE(1n + P);
add(
  'non-canonical-small-order-public-key',
  'The identity encoded non-canonically (y = 1 + p) as public key, R = identity, S = 0',
  nonCanonicalIdentity,
  Buffer.from('ed25519 vector message 0'),
  Buffer.concat([nonCanonicalIdentity, Buffer.alloc(32)]),
  false
);

const honestKeyBytes = encode(publicPoint);
const honestMessage = Buffer.from('ed25519 vector message 0');
const honestRef = signWith(honestMessage, honestKeyBytes, Point.BASE.multiply(nonce), secret);
const honestSig = Buffer.concat([honestRef.R, bigIntToBytesLE(honestRef.S)]);
add('signature-too-short', 'A 63-byte signature', honestKeyBytes, honestMessage, honestSig.subarray(0, 63), false);
add('signature-too-long', 'A 65-byte signature', honestKeyBytes, honestMessage, Buffer.concat([honestSig, Buffer.from([0])]), false);
add('public-key-too-short', 'A 31-byte public key', honestKeyBytes.subarray(0, 31), honestMessage, honestSig, false);

const output = {
  formatVersion: 1,
  description:
    'Ed25519 verification vectors of RFC-001 §7. A vector with valid=false must be rejected by every SDK; ' +
    'valid=true ones must verify. Regenerate with scripts/regenerate-ed25519-verification-vectors.js.',
  vectors
};

const target = path.join(__dirname, '..', 'fixtures', 'ed25519-verification-vectors.json');
fs.writeFileSync(target, `${JSON.stringify(output, null, 2)}\n`);
console.log(`Wrote ${path.relative(process.cwd(), target)} (${vectors.length} vectors)`);
