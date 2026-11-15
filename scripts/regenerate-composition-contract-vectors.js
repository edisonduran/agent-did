#!/usr/bin/env node
/**
 * Regenerates fixtures/composition-contract-vectors.json: the shared vectors of the A2A identity composition contract
 * (docs/RFC-001-A2A-Identity-Composition-Contract.md §7) that need no resolution.
 *
 * - `sign`: an unsigned Agent Card, a key id and the exact signed card. Both SDKs sign it with `signAgentCard` /
 *   `sign_agent_card` and the TEST-ONLY seed and must produce it byte for byte (Ed25519 is deterministic).
 * - `cards`: cards and the outcome of the format check (`parseSignedAgentCard`) followed by the Ed25519 check of every
 *   signature with the key of its `kid` (`keys`): `ok` (with the agent DID and the published keys), `format_drift`
 *   or `tampered`.
 * - `documents`: DID documents and whether the document guard accepts them (`revoked`, inline context term).
 * - `reasons`: a DID document, a key id whose signature did not verify, and the contract reason
 *   (`compositionReasonForKey` / `composition_reason_for_key`).
 * - `scenarios`: where each fixture F1-F8 of contract §7 is covered.
 *
 * The output is deterministic and built without the SDKs (node:crypto only). The seeds below are TEST-ONLY keys, public
 * on purpose so anyone can re-create the vectors; they sign nothing real. The canonicalization here handles only what
 * the cards contain (objects, arrays, strings, booleans): it is RFC 8785 for that subset.
 *
 * Usage: node scripts/regenerate-composition-contract-vectors.js
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const OUTPUT = path.join(__dirname, '..', 'fixtures', 'composition-contract-vectors.json');
const DID = 'did:webvh:QmcompositionVectorsAgent:agents.example:agents:card-bot';
const OTHER_DID = 'did:webvh:QmcompositionVectorsOther:agents.example:agents:other-bot';
const CONTROLLER = 'did:webvh:QmcompositionVectorsController:agents.example:controllers:acme';
const EXTENSION_URI = 'https://agent-did.org/a2a/identity/v1';
const SEEDS = {
  [`${DID}#key-1`]: '1f2e3d4c5b6a79881f2e3d4c5b6a79881f2e3d4c5b6a79881f2e3d4c5b6a7988',
  [`${DID}#key-2`]: '2a3b4c5d6e7f80912a3b4c5d6e7f80912a3b4c5d6e7f80912a3b4c5d6e7f8091',
  [`${DID}#key-3`]: '3c4d5e6f708192a33c4d5e6f708192a33c4d5e6f708192a33c4d5e6f708192a3',
  [`${DID}#key-4`]: '5d6e7f8091a2b3c45d6e7f8091a2b3c45d6e7f8091a2b3c45d6e7f8091a2b3c4',
  [`${OTHER_DID}#key-1`]: '4e5f60718293a4b54e5f60718293a4b54e5f60718293a4b54e5f60718293a4b5'
};
const KEY1 = `${DID}#key-1`;
const KEY2 = `${DID}#key-2`;
const KEY3 = `${DID}#key-3`;
const REVOKED_TERM = {
  revoked: { '@id': 'https://w3id.org/security#revoked', '@type': 'http://www.w3.org/2001/XMLSchema#dateTime' }
};

const PKCS8_PREFIX = Buffer.from('302e020100300506032b657004220420', 'hex');
const BASE58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

const privateKey = (keyId) =>
  crypto.createPrivateKey({ key: Buffer.concat([PKCS8_PREFIX, Buffer.from(SEEDS[keyId], 'hex')]), format: 'der', type: 'pkcs8' });

function publicKeyMultibase(keyId) {
  const der = crypto.createPublicKey(privateKey(keyId)).export({ format: 'der', type: 'spki' });
  const bytes = Buffer.concat([Buffer.from([0xed, 0x01]), der.subarray(der.length - 32)]);
  let value = BigInt(`0x${bytes.toString('hex')}`);
  let out = '';
  while (value > 0n) {
    out = BASE58_ALPHABET[Number(value % 58n)] + out;
    value /= 58n;
  }
  return `z${out}`;
}

/** RFC 8785 for objects, arrays, strings and booleans (UTF-16 code unit key order, JSON string escaping). */
function jcs(value) {
  if (typeof value === 'string' || typeof value === 'boolean') return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(jcs).join(',')}]`;
  if (value && typeof value === 'object') {
    const keys = Object.keys(value).sort();
    return `{${keys.map((key) => `${JSON.stringify(key)}:${jcs(value[key])}`).join(',')}}`;
  }
  throw new TypeError(`unsupported value in a card: ${String(value)}`);
}

const b64url = (bytes) => Buffer.from(bytes).toString('base64url');
const clone = (value) => JSON.parse(JSON.stringify(value));

function card(keyIds = [KEY1, KEY2]) {
  return {
    name: 'CardBot',
    description: 'Answers questions about cards',
    version: '1.0.0',
    supportedInterfaces: [{ url: 'https://agents.example/a2a', protocolBinding: 'JSONRPC' }],
    capabilities: {
      streaming: false,
      extensions: [{ uri: EXTENSION_URI, params: { did: DID, keyIds } }]
    },
    defaultInputModes: ['text/plain'],
    defaultOutputModes: ['text/plain'],
    skills: []
  };
}

/** One JWS entry over `value` (without its `signatures`), with `header` as the protected header text. */
function signatureEntry(value, keyId, headerText, signingKeyId = keyId) {
  const { signatures: _ignored, ...unsigned } = value;
  const protectedB64 = b64url(Buffer.from(headerText, 'utf8'));
  const signingInput = `${protectedB64}.${b64url(Buffer.from(jcs(unsigned), 'utf8'))}`;
  return { protected: protectedB64, signature: b64url(crypto.sign(null, Buffer.from(signingInput, 'ascii'), privateKey(signingKeyId))) };
}

const header = (keyId, extra = {}) => jcs({ alg: 'EdDSA', kid: keyId, typ: 'JOSE', ...extra });

function signed(value, keyId = KEY1, headerText = header(keyId), signingKeyId = keyId) {
  return { ...value, signatures: [...(value.signatures ?? []), signatureEntry(value, keyId, headerText, signingKeyId)] };
}

function cardCases() {
  const base = signed(card());
  const ok = (name, value, publishedKeyIds) => ({ name, card: value, expected: 'ok', did: DID, publishedKeyIds });
  const drift = (name, value) => ({ name, card: value, expected: 'format_drift' });
  const tampered = (name, value) => ({ name, card: value, expected: 'tampered' });
  const withEntry = (members) => ({ ...base, signatures: [{ ...base.signatures[0], ...members }] });

  const twoExtensions = card();
  twoExtensions.capabilities.extensions.push(clone(twoExtensions.capabilities.extensions[0]));
  const otherDidExtension = card();
  otherDidExtension.capabilities.extensions[0].params.did = OTHER_DID;
  const foreignKeyIds = card([KEY1, `${OTHER_DID}#key-1`]);
  const noExtension = card();
  delete noExtension.capabilities.extensions;
  const shortSignature = Buffer.from(base.signatures[0].signature, 'base64url').subarray(0, 63);

  return [
    ok('signed by key-1, extension publishes key-1 and key-2', base, [KEY1, KEY2]),
    ok('two signatures (key-1, key-2)', signed(base, KEY2), [KEY1, KEY2]),
    ok('no Agent-DID extension: the signature kid is the only published key', signed(noExtension), [KEY1]),
    ok('protected header without typ', signed(card(), KEY1, jcs({ alg: 'EdDSA', kid: KEY1 })), [KEY1, KEY2]),
    ok('protected header with jku (ignored)', signed(card(), KEY1, header(KEY1, { jku: 'https://agents.example/jwks.json' })), [KEY1, KEY2]),
    ok('unprotected header (not covered, ignored)', withEntry({ header: { note: 'not covered' } }), [KEY1, KEY2]),
    ok('protected header that is not in JCS form', signed(card(), KEY1, `{"typ":"JOSE", "kid":"${KEY1}","alg":"EdDSA"}`), [KEY1, KEY2]),
    tampered('a member changed after signing', { ...base, name: 'Other' }),
    tampered('a member added after signing', { ...base, iconUrl: 'https://agents.example/icon.png' }),
    tampered('kid key-1, signed by key-2', signed(card(), KEY1, header(KEY1), KEY2)),
    tampered('second signature tampered', { ...signed(base, KEY2), description: 'changed' }),
    drift('no signatures member', card()),
    drift('empty signatures', { ...card(), signatures: [] }),
    drift('signatures is not a list', { ...card(), signatures: base.signatures[0] }),
    drift('the card is a list', [base]),
    drift('alg ES256', signed(card(), KEY1, header(KEY1, { alg: 'ES256' }))),
    drift('typ JWT', signed(card(), KEY1, header(KEY1, { typ: 'JWT' }))),
    drift('crit present', signed(card(), KEY1, header(KEY1, { crit: ['b64'], b64: false }))),
    drift('kid is a DID without fragment', signed(card(), KEY1, header(DID))),
    drift('kid is a relative fragment', signed(card(), KEY1, header('#key-1'))),
    drift('protected header is not JSON', withEntry({ protected: b64url(Buffer.from('not json')) })),
    drift('protected header is a JSON list', withEntry({ protected: b64url(Buffer.from('["EdDSA"]')) })),
    drift('protected header has NaN', withEntry({ protected: b64url(Buffer.from(`{"alg":"EdDSA","kid":"${KEY1}","x":NaN}`)) })),
    drift('signature with base64 padding', withEntry({ signature: `${base.signatures[0].signature}=` })),
    drift('signature in standard base64', withEntry({ signature: Buffer.from(base.signatures[0].signature, 'base64url').toString('base64') })),
    drift('signature of 63 bytes', withEntry({ signature: b64url(shortSignature) })),
    drift('extra member in a signature entry', withEntry({ kid: KEY1 })),
    drift('unprotected header is not an object', withEntry({ header: 'x' })),
    drift('Agent-DID extension names another DID', signed(otherDidExtension)),
    drift('Agent-DID extension lists a key of another DID', signed(foreignKeyIds)),
    drift('two Agent-DID extensions', signed(twoExtensions)),
    drift('signatures by two DIDs', signed(signed(noExtension), `${OTHER_DID}#key-1`))
  ];
}

function method(keyId, extra = {}) {
  return { id: keyId, type: 'Multikey', controller: CONTROLLER, publicKeyMultibase: publicKeyMultibase(keyId), ...extra };
}

function document({ context, methods, authentication = [KEY2], assertionMethod = [KEY2], extra = {} }) {
  return {
    '@context': context ?? ['https://www.w3.org/ns/did/v1', 'https://agent-did.org/v1'],
    id: DID,
    controller: CONTROLLER,
    created: '2026-11-15T00:00:00.000Z',
    updated: '2026-11-15T01:00:00.000Z',
    agentMetadata: { name: 'CardBot', version: '1.0.0' },
    verificationMethod: methods,
    authentication,
    assertionMethod,
    ...extra
  };
}

const RETIRED_AT = '2026-11-15T01:00:00.000Z';
const URLS = ['https://www.w3.org/ns/did/v1', 'https://agent-did.org/v1'];

function documentCases() {
  const revoked = method(KEY1, { deactivated: RETIRED_AT, revoked: RETIRED_AT });
  const planned = method(KEY1, { deactivated: RETIRED_AT });
  const active = method(KEY2);
  const cases = [
    ['no retired key', document({ methods: [method(KEY1), active], authentication: [KEY1, KEY2], assertionMethod: [KEY1, KEY2] }), true],
    ['planned retirement, no inline term', document({ methods: [planned, active] }), true],
    ['revoked key with the inline term last', document({ context: [...URLS, REVOKED_TERM], methods: [revoked, active] }), true],
    ['revoked key without the inline term', document({ methods: [revoked, active] }), false],
    ['inline term without a revoked key', document({ context: [...URLS, REVOKED_TERM], methods: [planned, active] }), false],
    ['inline term not last', document({ context: [URLS[0], REVOKED_TERM, URLS[1]], methods: [revoked, active] }), false],
    ['inline term twice', document({ context: [...URLS, REVOKED_TERM, REVOKED_TERM], methods: [revoked, active] }), false],
    ['inline term with another @id', document({ context: [...URLS, { revoked: { ...REVOKED_TERM.revoked, '@id': 'https://example.com/revoked' } }], methods: [revoked, active] }), false],
    ['inline term with an extra member', document({ context: [...URLS, { ...REVOKED_TERM, expires: 'sec:expiration' }], methods: [revoked, active] }), false],
    ['revoked without deactivated', document({ context: [...URLS, REVOKED_TERM], methods: [method(KEY1, { revoked: RETIRED_AT }), active] }), false],
    ['revoked is not a string', document({ context: [...URLS, REVOKED_TERM], methods: [method(KEY1, { deactivated: RETIRED_AT, revoked: 1 }), active] }), false]
  ];
  return cases.map(([name, value, valid]) => ({ name, document: value, valid }));
}

function reasonCases() {
  const doc = document({
    context: [...URLS, REVOKED_TERM],
    methods: [
      method(KEY1, { deactivated: RETIRED_AT, revoked: RETIRED_AT }),
      method(KEY2),
      method(KEY3),
      method(`${DID}#key-4`, { deactivated: RETIRED_AT })
    ],
    extra: { capabilityInvocation: [KEY3] }
  });
  return [
    { name: 'F5: revoked key', contractFixture: 'F5', document: doc, keyId: KEY1, expected: 'emergency_revoked' },
    { name: 'F4: retired key', contractFixture: 'F4', document: doc, keyId: `${DID}#key-4`, expected: 'rotation_window_closed' },
    { name: 'F6: active key outside assertionMethod', contractFixture: 'F6', document: doc, keyId: KEY3, expected: 'key_purpose_violation' },
    { name: 'active assertionMethod key, bad signature', document: doc, keyId: KEY2, expected: 'tampered' },
    { name: 'key not in the document', document: doc, keyId: `${DID}#key-9`, expected: 'tampered' }
  ];
}

const SCENARIOS = {
  F1: 'accept: current key, valid card, valid request. SDK tests (CompositionContract / test_composition_contract) and the `cards` ok cases.',
  F2: 'accept: prior key still listed during a planned overlap. SDK tests; in Agent-DID the overlap is both keys listed in the DID document.',
  F3: 'reject card_keyid_mismatch: the request keyid is not a key the card publishes. SDK tests; published keys are the `cards` publishedKeyIds.',
  F4: 'reject rotation_window_closed: `reasons` F4 and SDK tests.',
  F5: 'reject emergency_revoked: `reasons` F5, `documents` and SDK tests.',
  F6: 'reject key_purpose_violation: `reasons` F6 and SDK tests.',
  F7: 'not emitted: the Agent-DID SDKs fail closed with did_document_unresolvable for a DID they cannot resolve; the caller policy decides (contract §4.1 3e as amended).',
  F8: 'reject format_drift: `cards` format_drift cases.'
};

function main() {
  const unsigned = card();
  const vectors = {
    description:
      'Composition contract vectors (docs/RFC-001-A2A-Identity-Composition-Contract.md §7). `sign`: both SDKs must sign ' +
      '`card` as `keyId` with the TEST-ONLY seed of that key and produce `signedCard` byte for byte. `cards`: run the ' +
      'format check, then the Ed25519 check of every signature with the key of its kid (`keys`); expect `ok` (with `did` ' +
      'and `publishedKeyIds`), `format_drift` or `tampered`. `documents`: whether the document guard accepts each ' +
      'document. `reasons`: the contract reason for a key whose signature did not verify, read from `document`. ' +
      'Generated by scripts/regenerate-composition-contract-vectors.js.',
    keys: Object.fromEntries(
      Object.keys(SEEDS).map((keyId) => [keyId, { seedHex: SEEDS[keyId], publicKeyMultibase: publicKeyMultibase(keyId) }])
    ),
    sign: { card: unsigned, keyId: KEY1, signedCard: signed(unsigned) },
    cards: cardCases(),
    documents: documentCases(),
    reasons: reasonCases(),
    scenarios: SCENARIOS
  };
  fs.writeFileSync(OUTPUT, `${JSON.stringify(vectors, null, 2)}\n`);
  console.log(
    `Wrote ${vectors.cards.length} card, ${vectors.documents.length} document and ${vectors.reasons.length} reason cases ` +
      `to ${path.relative(process.cwd(), OUTPUT)}`
  );
}

main();
