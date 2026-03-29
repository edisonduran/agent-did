#!/usr/bin/env node
/**
 * Regenerates fixtures/interop-vectors.json with a fresh Ed25519 keypair
 * that includes anti-replay fields (x-request-nonce, expires).
 *
 * Usage: node scripts/regenerate-interop-vectors.js
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

// @noble/curves is ESM-only, so we use Node's built-in crypto for Ed25519
function ed25519Sign(message, privateKey) {
  const keyObj = crypto.createPrivateKey({
    key: Buffer.concat([
      Buffer.from('302e020100300506032b657004220420', 'hex'), // PKCS8 Ed25519 prefix
      privateKey
    ]),
    format: 'der',
    type: 'pkcs8'
  });
  return crypto.sign(null, message, keyObj);
}

function ed25519GetPublicKey(privateKey) {
  const keyObj = crypto.createPrivateKey({
    key: Buffer.concat([
      Buffer.from('302e020100300506032b657004220420', 'hex'),
      privateKey
    ]),
    format: 'der',
    type: 'pkcs8'
  });
  const pubDer = crypto.createPublicKey(keyObj).export({ format: 'der', type: 'spki' });
  return pubDer.subarray(pubDer.length - 32); // last 32 bytes is the raw key
}

// Base58btc encoding (Bitcoin alphabet)
const B58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
function base58Encode(bytes) {
  let num = BigInt('0x' + Buffer.from(bytes).toString('hex'));
  let result = '';
  while (num > 0n) {
    result = B58_ALPHABET[Number(num % 58n)] + result;
    num = num / 58n;
  }
  for (const b of bytes) {
    if (b === 0) result = '1' + result;
    else break;
  }
  return result;
}

function encodePublicKeyMultibase(rawPublicKey) {
  const multicodecPrefix = Buffer.from([0xed, 0x01]);
  const prefixed = Buffer.concat([multicodecPrefix, rawPublicKey]);
  const encoded = base58Encode(prefixed);
  return `z${encoded}`;
}

function computeContentDigest(body) {
  const hash = crypto.createHash('sha256').update(body || '', 'utf-8').digest();
  return `sha-256=:${hash.toString('base64')}:`;
}

function buildHttpSignatureBase({ method, url, dateHeader, contentDigest, nonce }) {
  const urlObj = new URL(url);
  const lines = [
    `(request-target): ${method.toLowerCase()} ${urlObj.pathname}${urlObj.search}`,
    `host: ${urlObj.host}`,
    `date: ${dateHeader}`,
    `content-digest: ${contentDigest}`
  ];
  if (nonce) {
    lines.push(`x-request-nonce: ${nonce}`);
  }
  return lines.join('\n');
}

// --- Generate ---
const privateKeyBytes = crypto.randomBytes(32);
const publicKeyBytes = ed25519GetPublicKey(privateKeyBytes);
const privateKeyHex = privateKeyBytes.toString('hex');
const publicKeyMultibase = encodePublicKeyMultibase(publicKeyBytes);

const did = 'did:agent:polygon:0xinteropfixture';
const controller = 'did:ethr:0xfixturecontroller';
const keyId = `${did}#key-1`;

// 1. Message vector
const messagePayload = 'interop-message:v1';
const messageBytes = Buffer.from(messagePayload, 'utf-8');
const messageSig = ed25519Sign(messageBytes, privateKeyBytes);
const messageSignatureHex = messageSig.toString('hex');

// 2. HTTP vector
const httpMethod = 'POST';
const httpUrl = 'https://api.example.com/v1/interop?mode=fixture';
const httpBody = '{"fixture":true}';
const httpDate = 'Mon, 01 Jan 2024 00:00:00 GMT';
const nonce = crypto.randomBytes(16).toString('hex');
const created = 1704067200; // 2024-01-01T00:00:00Z
const expiresAt = created + 999999999; // ~2055, so fixture never expires in tests

const contentDigest = computeContentDigest(httpBody);
const signatureBase = buildHttpSignatureBase({
  method: httpMethod,
  url: httpUrl,
  dateHeader: httpDate,
  contentDigest,
  nonce
});

const httpSigBytes = ed25519Sign(Buffer.from(signatureBase, 'utf-8'), privateKeyBytes);
const httpSigBase64 = httpSigBytes.toString('base64');

const fixture = {
  did,
  controller,
  verificationMethod: {
    id: keyId,
    type: 'Ed25519VerificationKey2020',
    controller,
    publicKeyMultibase
  },
  messageVector: {
    payload: messagePayload,
    signatureHex: messageSignatureHex
  },
  httpVector: {
    method: httpMethod,
    url: httpUrl,
    body: httpBody,
    date: httpDate,
    contentDigest,
    headers: {
      'Signature': `sig1=:${httpSigBase64}:`,
      'Signature-Input': `sig1=("@request-target" "host" "date" "content-digest" "x-request-nonce");created=${created};expires=${expiresAt};keyid="${keyId}";alg="ed25519"`,
      'Signature-Agent': did,
      'Date': httpDate,
      'Content-Digest': contentDigest,
      'X-Request-Nonce': nonce
    },
    maxCreatedSkewSeconds: 999999999
  }
};

const outPath = path.join(__dirname, '..', 'fixtures', 'interop-vectors.json');
fs.writeFileSync(outPath, JSON.stringify(fixture, null, 2) + '\n');
console.log(`Wrote ${outPath}`);

// Also copy to sdk-python
const pyPath = path.join(__dirname, '..', 'sdk-python', 'tests', 'fixtures', 'interop-vectors.json');
if (fs.existsSync(path.dirname(pyPath))) {
  fs.writeFileSync(pyPath, JSON.stringify(fixture, null, 2) + '\n');
  console.log(`Wrote ${pyPath}`);
}

console.log('\nGenerated fixture details:');
console.log(`  DID: ${did}`);
console.log(`  Public key (multibase): ${publicKeyMultibase}`);
console.log(`  Private key (hex): ${privateKeyHex}`);
console.log(`  Nonce: ${nonce}`);
console.log(`  Expires: ${expiresAt}`);
