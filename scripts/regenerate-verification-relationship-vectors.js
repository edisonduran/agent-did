#!/usr/bin/env node
/**
 * Regenerates fixtures/verification-relationship-vectors.json: the vectors for RFC-001 §6.2.1.3, the
 * verification relationship each kind of signed artifact requires.
 *
 * One DID document lists five keys, each under exactly one verification relationship. Every key signs the
 * same payload, and every signature is cryptographically valid. Each vector pairs one key with one artifact
 * kind, so the only reason a vector is rejected is that the key is not listed under the relationship the
 * artifact requires (`key_purpose_violation`). 5 keys x 5 artifact kinds = 25 vectors: 5 accepted (the assertionMethod key serves both `assertion` and
 * `http_request`), 20 rejected.
 *
 * The output is deterministic. The Ed25519 seeds below are TEST-ONLY keys, public on purpose so anyone can
 * re-create the vectors; they sign nothing real. Keys are encoded here independently of the SDKs.
 *
 * Usage: node scripts/regenerate-verification-relationship-vectors.js
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const OUTPUT = path.join(__dirname, '..', 'fixtures', 'verification-relationship-vectors.json');
const DID = 'did:example:relationship-vectors';
const PAYLOAD = 'agent-did:verification-relationship-vector:v1';
const CREATED = '2026-11-07T00:00:00.000Z';

/** RFC-001 §6.2.1.3. Both SDKs export the same table; the tests compare it with this one. */
const REQUIRED_RELATIONSHIP_BY_ARTIFACT = {
  assertion: 'assertionMethod',
  http_request: 'assertionMethod',
  delegation: 'capabilityDelegation',
  invocation: 'capabilityInvocation',
  authentication: 'authentication'
};

/** One key per relationship. `keyAgreement` is included to show it never signs. */
const KEYS = [
  { fragment: 'key-assertion', relationship: 'assertionMethod', seed: '1f0c7a5e3d2b49186f7e4c3a2b1d0e9f8a7b6c5d4e3f2a1b0c9d8e7f6a5b4c3d' },
  { fragment: 'key-delegation', relationship: 'capabilityDelegation', seed: '2a1b0c9d8e7f6a5b4c3d2e1f0a9b8c7d6e5f4a3b2c1d0e9f8a7b6c5d4e3f2a1b' },
  { fragment: 'key-invocation', relationship: 'capabilityInvocation', seed: '3b2c1d0e9f8a7b6c5d4e3f2a1b0c9d8e7f6a5b4c3d2e1f0a9b8c7d6e5f4a3b2c' },
  { fragment: 'key-authentication', relationship: 'authentication', seed: '4c3d2e1f0a9b8c7d6e5f4a3b2c1d0e9f8a7b6c5d4e3f2a1b0c9d8e7f6a5b4c3d' },
  { fragment: 'key-agreement', relationship: 'keyAgreement', seed: '5d4e3f2a1b0c9d8e7f6a5b4c3d2e1f0a9b8c7d6e5f4a3b2c1d0e9f8a7b6c5d4e' }
];

const RELATIONSHIPS = ['authentication', 'assertionMethod', 'capabilityDelegation', 'capabilityInvocation', 'keyAgreement'];

const PKCS8_PREFIX = Buffer.from('302e020100300506032b657004220420', 'hex');
const BASE58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

function privateKeyObject(seedHex) {
  return crypto.createPrivateKey({
    key: Buffer.concat([PKCS8_PREFIX, Buffer.from(seedHex, 'hex')]),
    format: 'der',
    type: 'pkcs8'
  });
}

function publicKeyBytes(seedHex) {
  const der = crypto.createPublicKey(privateKeyObject(seedHex)).export({ format: 'der', type: 'spki' });
  return der.subarray(der.length - 32);
}

function base58btc(bytes) {
  let value = BigInt(`0x${Buffer.from(bytes).toString('hex') || '0'}`);
  let out = '';
  while (value > 0n) {
    out = BASE58_ALPHABET[Number(value % 58n)] + out;
    value /= 58n;
  }
  for (const byte of bytes) {
    if (byte !== 0) break;
    out = `1${out}`;
  }
  return out;
}

/** Multikey: `z` + base58btc(0xed 0x01 || 32-byte Ed25519 public key). */
function publicKeyMultibase(seedHex) {
  return `z${base58btc(Buffer.concat([Buffer.from([0xed, 0x01]), publicKeyBytes(seedHex)]))}`;
}

function keyId(fragment) {
  return `${DID}#${fragment}`;
}

const didDocument = {
  '@context': ['https://www.w3.org/ns/did/v1', 'https://agent-did.org/v1'],
  id: DID,
  controller: DID,
  created: CREATED,
  updated: CREATED,
  agentMetadata: {
    name: 'RelationshipVectorAgent',
    version: '1.0.0',
    coreModelHash: 'hash://sha256/0000000000000000000000000000000000000000000000000000000000000000',
    systemPromptHash: 'hash://sha256/0000000000000000000000000000000000000000000000000000000000000000'
  },
  verificationMethod: KEYS.map((key) => ({
    id: keyId(key.fragment),
    type: 'Ed25519VerificationKey2020',
    controller: DID,
    publicKeyMultibase: publicKeyMultibase(key.seed)
  })),
  ...Object.fromEntries(
    RELATIONSHIPS.map((relationship) => [
      relationship,
      KEYS.filter((key) => key.relationship === relationship).map((key) => keyId(key.fragment))
    ])
  )
};

const vectors = [];
for (const key of KEYS) {
  const signatureHex = crypto.sign(null, Buffer.from(PAYLOAD, 'utf-8'), privateKeyObject(key.seed)).toString('hex');
  for (const [artifact, required] of Object.entries(REQUIRED_RELATIONSHIP_BY_ARTIFACT)) {
    const accepted = key.relationship === required;
    vectors.push({
      id: `${artifact}--${key.fragment}`,
      artifact,
      keyId: keyId(key.fragment),
      signatureHex,
      expected: accepted
        ? { ok: true }
        : { ok: false, reason: 'key_purpose_violation', requiredPurpose: required, foundIn: [key.relationship] }
    });
  }
}

const fixture = {
  formatVersion: 1,
  description:
    'RFC-001 §6.2.1.3: the verification relationship each kind of signed artifact requires. Every signature is valid for its key; a vector is rejected only because the key is not listed under the required relationship. Generated by scripts/regenerate-verification-relationship-vectors.js; TEST-ONLY keys.',
  requiredRelationshipByArtifact: REQUIRED_RELATIONSHIP_BY_ARTIFACT,
  payload: PAYLOAD,
  didDocument,
  vectors
};

fs.writeFileSync(OUTPUT, `${JSON.stringify(fixture, null, 2)}\n`);
console.log(`Wrote ${vectors.length} vectors to ${path.relative(process.cwd(), OUTPUT)}`);
