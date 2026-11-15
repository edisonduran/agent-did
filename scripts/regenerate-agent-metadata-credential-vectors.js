#!/usr/bin/env node
/**
 * Regenerates fixtures/agent-metadata-credential-vectors.json: the shared vectors of the AgentMetadataCredential
 * profile (RFC-001 §4.4, ADR-006 D-8d).
 *
 * - `issue`: the inputs of one credential and the exact signed credential. Both SDKs build it with their profile
 *   builder and their `eddsa-jcs-2022` implementation and must produce it byte for byte.
 * - `cases`: mutations of that credential and the outcome both SDKs must give after the checks that need no
 *   resolution (form, proof form, validity period) and the proof: `ok`, `signature_invalid` or a rejection reason.
 *   Resolution outcomes (deactivated, not bound, issuer is not the controller...) are covered by the SDK tests.
 *
 * The output is deterministic and built without the SDKs (node:crypto only). The Ed25519 seed below is a TEST-ONLY
 * key, public on purpose so anyone can re-create the vectors; it signs nothing real. The canonicalization here
 * handles only what the credential contains (objects, arrays, strings): it is RFC 8785 for that subset.
 *
 * Usage: node scripts/regenerate-agent-metadata-credential-vectors.js
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const OUTPUT = path.join(__dirname, '..', 'fixtures', 'agent-metadata-credential-vectors.json');
const SEED = '6e5f4a3b2c1d0e9f8a7b6c5d4e3f2a1b0c9d8e7f6a5b4c3d2e1f0a9b8c7d6e5f';
const ISSUER = 'did:webvh:QmcredentialVectorsController:agents.example:controllers:acme';
const AGENT = 'did:webvh:QmcredentialVectorsAgent:agents.example:agents:billing-bot';
const VERIFICATION_METHOD = `${ISSUER}#key-1`;
const NOW = '2026-11-15T12:00:00.000Z';

const CONTEXT = [
  'https://www.w3.org/ns/credentials/v2',
  'https://agent-did.org/v1',
  { AgentMetadataCredential: 'https://agent-did.org/vocab#AgentMetadataCredential' }
];

const ISSUE = {
  issuer: ISSUER,
  agentDid: AGENT,
  id: 'urn:uuid:3f6c2a0e-8a1d-4c55-9f0b-2d7e4a1c9b10',
  validFrom: '2026-11-15T00:00:00Z',
  validUntil: '2026-12-15T00:00:00Z',
  created: '2026-11-15T00:00:00.000Z',
  verificationMethod: VERIFICATION_METHOD,
  agentMetadata: {
    name: 'BillingBot',
    description: 'Answers billing questions',
    version: '2.1.0',
    capabilities: ['billing:read', 'tickets:write'],
    memberOf: 'did:webvh:QmcredentialVectorsFleet:agents.example:fleets:billing',
    coreModelHash: 'hash://hmac-sha256/5a2f0c7d3e9b4a1f6c8d2e7b0a5f3c9e1d4b8a2f7c0e6d3b9a1f5c8e2d7b4a0f',
    systemPromptHash: 'hash://hmac-sha256/0f4a7b2d8e3c5f1a9d6b0e4c7a2f8d3b5e1c9a6f0d4b7e2a8c5f3d1b9e6a0c4f'
  }
};

const PKCS8_PREFIX = Buffer.from('302e020100300506032b657004220420', 'hex');
const BASE58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

function privateKey() {
  return crypto.createPrivateKey({ key: Buffer.concat([PKCS8_PREFIX, Buffer.from(SEED, 'hex')]), format: 'der', type: 'pkcs8' });
}

function publicKeyBytes() {
  const der = crypto.createPublicKey(privateKey()).export({ format: 'der', type: 'spki' });
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

/** RFC 8785 for objects, arrays and strings (UTF-16 code unit key order, JSON string escaping). */
function jcs(value) {
  if (typeof value === 'string') return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(jcs).join(',')}]`;
  if (value && typeof value === 'object') {
    const keys = Object.keys(value).sort();
    return `{${keys.map((key) => `${JSON.stringify(key)}:${jcs(value[key])}`).join(',')}}`;
  }
  throw new TypeError(`unsupported value in the credential: ${String(value)}`);
}

const sha256 = (text) => crypto.createHash('sha256').update(text, 'utf8').digest();

function unsignedCredential() {
  return {
    '@context': CONTEXT,
    id: ISSUE.id,
    type: ['VerifiableCredential', 'AgentMetadataCredential'],
    issuer: ISSUE.issuer,
    validFrom: ISSUE.validFrom,
    validUntil: ISSUE.validUntil,
    credentialSubject: { id: ISSUE.agentDid, agentMetadata: ISSUE.agentMetadata }
  };
}

function signedCredential() {
  const unsigned = unsignedCredential();
  const proofConfig = {
    type: 'DataIntegrityProof',
    cryptosuite: 'eddsa-jcs-2022',
    created: ISSUE.created,
    verificationMethod: ISSUE.verificationMethod,
    proofPurpose: 'assertionMethod',
    '@context': CONTEXT
  };
  const hashData = Buffer.concat([sha256(jcs(proofConfig)), sha256(jcs(unsigned))]);
  const signature = crypto.sign(null, hashData, privateKey());
  return {
    hashDataHex: hashData.toString('hex'),
    credential: { ...unsigned, proof: { ...proofConfig, proofValue: `z${base58btc(signature)}` } }
  };
}

/** `set` replaces the value at `path`, `delete` removes it. */
const set = (pathParts, value) => ({ op: 'set', path: pathParts, value });
const del = (pathParts) => ({ op: 'delete', path: pathParts });

const CASES = [
  { name: 'valid credential', mutations: [], expected: 'ok' },
  { name: 'valid at validUntil', now: '2026-12-15T00:00:00.000Z', mutations: [], expected: 'ok' },
  {
    name: 'changed claim',
    mutations: [set(['credentialSubject', 'agentMetadata', 'capabilities'], ['admin'])],
    expected: 'signature_invalid'
  },
  { name: 'changed proof created', mutations: [set(['proof', 'created'], '2026-11-15T00:00:01.000Z')], expected: 'signature_invalid' },
  {
    name: 'proof context differs from the credential context',
    mutations: [set(['proof', '@context'], ['https://www.w3.org/ns/credentials/v2'])],
    expected: 'signature_invalid'
  },
  { name: 'credential id removed', mutations: [del(['id'])], expected: 'signature_invalid' },
  { name: 'not an object', replace: 'not a credential', mutations: [], expected: 'malformed_credential' },
  {
    name: 'context without the credential type term',
    mutations: [set(['@context'], ['https://www.w3.org/ns/credentials/v2', 'https://agent-did.org/v1'])],
    expected: 'malformed_credential'
  },
  { name: 'types in another order', mutations: [set(['type'], ['AgentMetadataCredential', 'VerifiableCredential'])], expected: 'malformed_credential' },
  { name: 'issuer as an object', mutations: [set(['issuer'], { id: ISSUER })], expected: 'malformed_credential' },
  { name: 'issuer with a fragment', mutations: [set(['issuer'], `${ISSUER}#key-1`)], expected: 'malformed_credential' },
  { name: 'empty credential id', mutations: [set(['id'], '')], expected: 'malformed_credential' },
  { name: 'unknown credential member', mutations: [set(['credentialStatus'], { id: 'https://status.example/1' })], expected: 'malformed_credential' },
  { name: 'unknown subject member', mutations: [set(['credentialSubject', 'role'], 'admin')], expected: 'malformed_credential' },
  { name: 'subject id is not a DID', mutations: [set(['credentialSubject', 'id'], 'https://agents.example/billing-bot')], expected: 'malformed_credential' },
  { name: 'no agentMetadata', mutations: [del(['credentialSubject', 'agentMetadata'])], expected: 'malformed_credential' },
  { name: 'empty agentMetadata', mutations: [set(['credentialSubject', 'agentMetadata'], {})], expected: 'malformed_credential' },
  { name: 'unknown agentMetadata member', mutations: [set(['credentialSubject', 'agentMetadata', 'owner'], 'acme')], expected: 'malformed_credential' },
  {
    name: 'capabilities with a non-string',
    mutations: [set(['credentialSubject', 'agentMetadata', 'capabilities'], ['billing:read', 7])],
    expected: 'malformed_credential'
  },
  { name: 'name is not a string', mutations: [set(['credentialSubject', 'agentMetadata', 'name'], null)], expected: 'malformed_credential' },
  { name: 'validFrom without time', mutations: [set(['validFrom'], '2026-11-15')], expected: 'malformed_credential' },
  { name: 'no validFrom', mutations: [del(['validFrom'])], expected: 'malformed_credential' },
  { name: 'validUntil before validFrom', mutations: [set(['validUntil'], '2026-11-14T00:00:00Z')], expected: 'malformed_credential' },
  { name: 'validUntil null', mutations: [set(['validUntil'], null)], expected: 'malformed_credential' },
  { name: 'proof set', mutations: [set(['proof'], '$proofSet')], expected: 'unsupported_proof' },
  { name: 'no proof', mutations: [del(['proof'])], expected: 'unsupported_proof' },
  { name: 'rdfc cryptosuite', mutations: [set(['proof', 'cryptosuite'], 'eddsa-rdfc-2022')], expected: 'unsupported_proof' },
  { name: 'legacy proof type', mutations: [set(['proof', 'type'], 'Ed25519Signature2020')], expected: 'unsupported_proof' },
  { name: 'authentication purpose', mutations: [set(['proof', 'proofPurpose'], 'authentication')], expected: 'unsupported_proof' },
  { name: 'key of another DID', mutations: [set(['proof', 'verificationMethod'], `${AGENT}#key-1`)], expected: 'unsupported_proof' },
  { name: 'key of a DID that extends the issuer', mutations: [set(['proof', 'verificationMethod'], `${ISSUER}x#key-1`)], expected: 'unsupported_proof' },
  { name: 'empty key fragment', mutations: [set(['proof', 'verificationMethod'], `${ISSUER}#`)], expected: 'unsupported_proof' },
  { name: 'hex proofValue', mutations: [set(['proof', 'proofValue'], `f${'ab'.repeat(64)}`)], expected: 'unsupported_proof' },
  { name: 'proofValue of 63 bytes', mutations: [set(['proof', 'proofValue'], `z${base58btc(Buffer.alloc(63, 7))}`)], expected: 'unsupported_proof' },
  { name: 'proofValue with a non-base58 character', mutations: [set(['proof', 'proofValue'], 'z0OIl')], expected: 'unsupported_proof' },
  { name: 'invalid proof created', mutations: [set(['proof', 'created'], 'yesterday')], expected: 'unsupported_proof' },
  { name: 'invalid proof expires', mutations: [set(['proof', 'expires'], 'tomorrow')], expected: 'unsupported_proof' },
  { name: 'before validFrom', now: '2026-11-14T23:59:59.999Z', mutations: [], expected: 'not_yet_valid' },
  { name: 'after validUntil', now: '2026-12-15T00:00:00.001Z', mutations: [], expected: 'expired' },
  { name: 'after the proof expires', mutations: [set(['proof', 'expires'], '2026-11-15T11:00:00Z')], expected: 'expired' }
];

function main() {
  const { credential, hashDataHex } = signedCredential();
  const vectors = {
    description:
      'AgentMetadataCredential vectors (RFC-001 §4.4). `issue`: both SDKs must build `credential` byte for byte from ' +
      'these inputs with the TEST-ONLY seed. `cases`: apply each mutation to a copy of `credential` (`set` replaces the ' +
      'value at `path`, creating it if absent; `delete` removes it; the value "$proofSet" means `[proof]`; `replace` ' +
      'replaces the whole credential), then run the form checks at `now` (default `now` below) and the eddsa-jcs-2022 ' +
      'proof with `publicKeyMultibase`. Generated by scripts/regenerate-agent-metadata-credential-vectors.js.',
    seedHex: SEED,
    publicKeyMultibase: `z${base58btc(Buffer.concat([Buffer.from([0xed, 0x01]), publicKeyBytes()]))}`,
    now: NOW,
    issue: ISSUE,
    hashDataHex,
    credential,
    cases: CASES
  };
  fs.writeFileSync(OUTPUT, `${JSON.stringify(vectors, null, 2)}\n`);
  console.log(`Wrote ${CASES.length} cases to ${path.relative(process.cwd(), OUTPUT)}`);
}

main();
