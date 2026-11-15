#!/usr/bin/env node
/**
 * Regenerates fixtures/delegation-vectors.json: the shared vectors of capabilities (RFC-001 §6.7) and the OAuth client
 * assertion (RFC-001 §6.8), ADR-008 D-12f. Every check here needs no resolution; the DID documents a verifier would
 * resolve are replaced by `keys` (the Ed25519 key of each key id).
 *
 * - `capabilities.sign`: unsigned capabilities with their proof options and the exact `proofValue` both SDKs must
 *   produce with the TEST-ONLY seeds (`eddsa-jcs-2022`, Ed25519 is deterministic).
 * - `capabilities.chains`: a capability, the verifier's `rootControllers`, `now` and `maxChainLength`, and the outcome
 *   of the checks without resolution (`checkCapabilityChain` / `check_capability_chain`) followed by, for every link,
 *   the delegator check and the proof check with the key of its `verificationMethod`: `ok` (with `delegators` and
 *   `allowedAction`) or a reason.
 * - `capabilities.targets`: request URL, method, invocation target, allowed actions and whether they match.
 * - `capabilities.headers`: `Agent-DID-Capability` field values and what the member of `sig1` parses to.
 * - `capabilities.invocation`: a signed invocation request (fixed `created`, `expires`, `nonce`) with its exact
 *   signature base and signature, verified with the invoker's key.
 * - `clientAssertions.sign`: parameters and the exact JWS both SDKs must produce.
 * - `clientAssertions.verify`: an assertion, the verifier's expectations and the outcome of `parseClientAssertion` /
 *   `parse_client_assertion` followed by the Ed25519 check with the key of its `kid`: `ok` or a reason.
 *
 * The output is deterministic and built without the SDKs (node:crypto only). The seeds below are TEST-ONLY keys, public
 * on purpose so anyone can re-create the vectors; they sign nothing real. The canonicalization here handles only what
 * the vectors contain (objects, arrays, strings, integers): it is RFC 8785 for that subset.
 *
 * Usage: node scripts/regenerate-delegation-vectors.js
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const OUTPUT = path.join(__dirname, '..', 'fixtures', 'delegation-vectors.json');
const OWNER = 'did:webvh:QmdelegationVectorsOwner:api.example:owners:acme';
const ALICE = 'did:webvh:QmdelegationVectorsAlice:agents.example:agents:alice';
const BOB = 'did:webvh:QmdelegationVectorsBob:agents.example:agents:bob';
const CAROL = 'did:webvh:QmdelegationVectorsCarol:agents.example:agents:carol';
const SEEDS = {
  [`${OWNER}#key-1`]: '6a7b8c9d0e1f20316a7b8c9d0e1f20316a7b8c9d0e1f20316a7b8c9d0e1f2031',
  [`${ALICE}#key-1`]: '7b8c9d0e1f2031427b8c9d0e1f2031427b8c9d0e1f2031427b8c9d0e1f203142',
  [`${BOB}#key-1`]: '8c9d0e1f203142538c9d0e1f203142538c9d0e1f203142538c9d0e1f20314253',
  [`${CAROL}#key-1`]: '9d0e1f20314253649d0e1f20314253649d0e1f20314253649d0e1f2031425364'
};
const TARGET = 'https://api.example.com/files';
const ZCAP_CONTEXT = 'https://w3id.org/zcap/v1';
const ROOT_ID = `urn:zcap:root:${encodeURIComponent(TARGET)}`;
const CREATED = '2026-11-15T00:00:00Z';
const NOW = '2026-11-15T12:00:00Z';
const ISSUER = 'https://auth.example.com';
const CLIENT_ID = 'https://agents.example.com/bob/client.json';
const IAT = 1800000000;

const PKCS8_PREFIX = Buffer.from('302e020100300506032b657004220420', 'hex');
const BASE58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

const privateKey = (keyId) =>
  crypto.createPrivateKey({ key: Buffer.concat([PKCS8_PREFIX, Buffer.from(SEEDS[keyId], 'hex')]), format: 'der', type: 'pkcs8' });
const rawPublicKey = (keyId) => {
  const der = crypto.createPublicKey(privateKey(keyId)).export({ format: 'der', type: 'spki' });
  return der.subarray(der.length - 32);
};
const sign = (keyId, bytes) => crypto.sign(null, Buffer.from(bytes), privateKey(keyId));

function base58(bytes) {
  let value = BigInt(`0x${Buffer.from(bytes).toString('hex')}`);
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

const publicKeyMultibase = (keyId) => `z${base58(Buffer.concat([Buffer.from([0xed, 0x01]), rawPublicKey(keyId)]))}`;

/** RFC 8785 for objects, arrays, strings and safe integers (UTF-16 code unit key order, JSON string escaping). */
function jcs(value) {
  if (typeof value === 'string' || typeof value === 'boolean') return JSON.stringify(value);
  if (typeof value === 'number' && Number.isSafeInteger(value)) return String(value);
  if (Array.isArray(value)) return `[${value.map(jcs).join(',')}]`;
  if (value && typeof value === 'object') {
    const keys = Object.keys(value).sort();
    return `{${keys.map((key) => `${JSON.stringify(key)}:${jcs(value[key])}`).join(',')}}`;
  }
  throw new TypeError(`unsupported value: ${String(value)}`);
}

const sha256 = (text) => crypto.createHash('sha256').update(text, 'utf8').digest();
const clone = (value) => JSON.parse(JSON.stringify(value));
const b64url = (bytes) => Buffer.from(bytes).toString('base64url');

// ---------------------------------------------------------------------------
// Capabilities
// ---------------------------------------------------------------------------

function uuid(n) {
  return `urn:uuid:00000000-0000-4000-8000-${String(n).padStart(12, '0')}`;
}

function unsignedCapability({ id, parent, target, controller, expires, actions }) {
  return {
    '@context': [ZCAP_CONTEXT],
    id,
    parentCapability: parent,
    invocationTarget: target,
    controller,
    ...(actions ? { allowedAction: actions } : {}),
    expires
  };
}

function chainOf(parent) {
  if (typeof parent === 'string') return [parent];
  const ids = parent.proof.capabilityChain.map((entry) => (typeof entry === 'string' ? entry : entry.id));
  return [...ids, clone(parent)];
}

function proofOptions(keyId, parent) {
  return {
    type: 'DataIntegrityProof',
    cryptosuite: 'eddsa-jcs-2022',
    created: CREATED,
    verificationMethod: keyId,
    proofPurpose: 'capabilityDelegation',
    capabilityChain: chainOf(parent),
    '@context': [ZCAP_CONTEXT]
  };
}

function signCapability(unsigned, keyId, parent) {
  const config = proofOptions(keyId, parent);
  const hashData = Buffer.concat([sha256(jcs(config)), sha256(jcs(unsigned))]);
  return { ...unsigned, proof: { ...config, proofValue: `z${base58(sign(keyId, hashData))}` } };
}

const c1Unsigned = unsignedCapability({
  id: uuid(1), parent: ROOT_ID, target: TARGET, controller: ALICE, expires: '2099-01-01T00:00:00Z', actions: ['GET', 'POST']
});
const c1 = signCapability(c1Unsigned, `${OWNER}#key-1`, ROOT_ID);
const c2Unsigned = unsignedCapability({
  id: uuid(2), parent: c1.id, target: `${TARGET}/reports`, controller: BOB, expires: '2098-01-01T00:00:00Z', actions: ['GET']
});
const c2 = signCapability(c2Unsigned, `${ALICE}#key-1`, c1);
const c3Unsigned = unsignedCapability({
  id: uuid(3), parent: c2.id, target: `${TARGET}/reports/2026`, controller: CAROL, expires: '2097-01-01T00:00:00Z'
});
const c3 = signCapability(c3Unsigned, `${BOB}#key-1`, c2);

const roots = { [TARGET]: [OWNER] };
const chain = (name, capability, expected, extra = {}) => ({
  name,
  capability,
  rootControllers: extra.rootControllers ?? roots,
  now: extra.now ?? NOW,
  maxChainLength: extra.maxChainLength ?? 5,
  ...expected
});

const widened = signCapability(
  unsignedCapability({ id: uuid(4), parent: c1.id, target: 'https://api.example.com/other', controller: BOB, expires: '2098-01-01T00:00:00Z' }),
  `${ALICE}#key-1`,
  c1
);
const moreActions = signCapability(
  unsignedCapability({ id: uuid(5), parent: c1.id, target: TARGET, controller: BOB, expires: '2098-01-01T00:00:00Z', actions: ['GET', 'DELETE'] }),
  `${ALICE}#key-1`,
  c1
);
const longer = signCapability(
  unsignedCapability({ id: uuid(6), parent: c1.id, target: TARGET, controller: BOB, expires: '2099-06-01T00:00:00Z' }),
  `${ALICE}#key-1`,
  c1
);
const inherits = signCapability(
  unsignedCapability({ id: uuid(7), parent: c1.id, target: `${TARGET}/a`, controller: BOB, expires: '2098-01-01T00:00:00Z' }),
  `${ALICE}#key-1`,
  c1
);
const byOwner = signCapability(c2Unsigned, `${OWNER}#key-1`, c1);
const tampered = clone(c2);
tampered.controller = CAROL;
const wrongParent = clone(c2);
wrongParent.parentCapability = uuid(9);
const extraMember = { ...clone(c1), note: 'x' };
const assertionPurpose = clone(c1);
assertionPurpose.proof.proofPurpose = 'assertionMethod';
const queryTarget = clone(c1);
queryTarget.invocationTarget = `${TARGET}?q=1`;
const notRootFirst = clone(c1);
notRootFirst.parentCapability = uuid(8);
notRootFirst.proof.capabilityChain = [uuid(8)];
const badContext = clone(c1);
badContext['@context'] = [ZCAP_CONTEXT, 'https://example.com/extra'];
const badId = clone(c1);
badId.id = 'urn:uuid:NOT-A-UUID';
const noExpires = clone(c1);
delete noExpires.expires;
const proofSet = clone(c1);
proofSet.proof = [proofSet.proof];

const chains = [
  chain('root delegation', c1, { expected: 'ok', delegators: [OWNER], allowedAction: ['GET', 'POST'], controller: ALICE }),
  chain('two links, narrowed', c2, { expected: 'ok', delegators: [OWNER, ALICE], allowedAction: ['GET'], controller: BOB }),
  chain('three links, actions inherited', c3, { expected: 'ok', delegators: [OWNER, ALICE, BOB], allowedAction: ['GET'], controller: CAROL }),
  chain('absent allowedAction inherits the parent', inherits, { expected: 'ok', delegators: [OWNER, ALICE], allowedAction: ['GET', 'POST'], controller: BOB }),
  chain('chain longer than maxChainLength', c3, { expected: 'chain_too_long', capabilityId: c3.id }, { maxChainLength: 2 }),
  chain('no root controller configured', c1, { expected: 'root_controller_unknown', capabilityId: c1.id }, { rootControllers: {} }),
  chain('root controller for another target', c1, { expected: 'root_controller_unknown', capabilityId: c1.id }, { rootControllers: { [`${TARGET}/other`]: [OWNER] } }),
  chain('target outside the parent', widened, { expected: 'attenuation_violation', capabilityId: widened.id }),
  chain('actions wider than the parent', moreActions, { expected: 'attenuation_violation', capabilityId: moreActions.id }),
  chain('expires after the parent', longer, { expected: 'attenuation_violation', capabilityId: longer.id }),
  chain('expired link', c2, { expected: 'expired', capabilityId: c2.id }, { now: '2098-06-01T00:00:00Z' }),
  chain('root signed by a DID that is not a root controller', c1, { expected: 'delegator_mismatch', capabilityId: c1.id }, { rootControllers: { [TARGET]: [BOB] } }),
  chain('link signed by someone other than the parent controller', byOwner, { expected: 'delegator_mismatch', capabilityId: c2.id }),
  chain('controller changed after signing', tampered, { expected: 'signature_invalid', capabilityId: c2.id }),
  chain('parentCapability does not name the embedded parent', wrongParent, { expected: 'malformed_capability', capabilityId: c2.id }),
  chain('chain does not start at the root', notRootFirst, { expected: 'malformed_capability', capabilityId: c1.id }),
  chain('unknown member', extraMember, { expected: 'malformed_capability' }),
  chain('extra @context entry', badContext, { expected: 'malformed_capability' }),
  chain('id is not a lowercase urn:uuid', badId, { expected: 'malformed_capability' }),
  chain('no expires', noExpires, { expected: 'malformed_capability' }),
  chain('target with a query', queryTarget, { expected: 'malformed_capability' }),
  chain('proof purpose assertionMethod', assertionPurpose, { expected: 'unsupported_proof' }),
  chain('proof set', proofSet, { expected: 'unsupported_proof' })
];

const capabilitySign = [
  { name: 'from the root', unsigned: c1Unsigned, proofOptions: proofOptions(`${OWNER}#key-1`, ROOT_ID), keyId: `${OWNER}#key-1`, proofValue: c1.proof.proofValue },
  { name: 'from a parent', unsigned: c2Unsigned, proofOptions: proofOptions(`${ALICE}#key-1`, c1), keyId: `${ALICE}#key-1`, proofValue: c2.proof.proofValue },
  { name: 'third link', unsigned: c3Unsigned, proofOptions: proofOptions(`${BOB}#key-1`, c2), keyId: `${BOB}#key-1`, proofValue: c3.proof.proofValue }
];

const targets = [
  { url: `${TARGET}`, method: 'GET', invocationTarget: TARGET, allowedAction: ['GET'], matches: true },
  { url: `${TARGET}/reports?year=2026`, method: 'GET', invocationTarget: TARGET, allowedAction: ['GET'], matches: true },
  { url: 'https://api.example.com/filesystem', method: 'GET', invocationTarget: TARGET, allowedAction: ['GET'], matches: false },
  { url: `${TARGET}/`, method: 'GET', invocationTarget: TARGET, allowedAction: ['GET'], matches: false },
  { url: `${TARGET}/x`, method: 'POST', invocationTarget: TARGET, allowedAction: ['GET'], matches: false },
  { url: `${TARGET}/x`, method: 'DELETE', invocationTarget: TARGET, matches: true },
  { url: 'https://api.example.com/a', method: 'GET', invocationTarget: 'https://api.example.com/', matches: true },
  { url: 'https://api.example.com:8443/files', method: 'GET', invocationTarget: TARGET, matches: false }
];

const member = (capability) => `sig1=:${Buffer.from(jcs(capability), 'utf8').toString('base64')}:`;
const headers = [
  { name: 'JCS of the capability', value: member(c2), expected: 'capability', capability: c2 },
  { name: 'another label only', value: `sig2=:${Buffer.from(jcs(c2)).toString('base64')}:`, expected: 'missing' },
  { name: 'String instead of Byte Sequence', value: 'sig1="x"', expected: 'malformed' },
  { name: 'Byte Sequence with a parameter', value: `${member(c2)};a=1`, expected: 'malformed' },
  { name: 'not JCS (spaces)', value: `sig1=:${Buffer.from(JSON.stringify(c2, null, 1)).toString('base64')}:`, expected: 'malformed' },
  { name: 'a JSON array', value: `sig1=:${Buffer.from('[]').toString('base64')}:`, expected: 'malformed' },
  { name: 'not UTF-8', value: `sig1=:${Buffer.from([0xff, 0xfe]).toString('base64')}:`, expected: 'malformed' },
  { name: 'not a Dictionary', value: 'sig1=:', expected: 'malformed' }
];

// A signed invocation of c2 by Bob (fixed time and nonce)
const invocationUrl = `${TARGET}/reports/q1?format=csv`;
const created = 1794744000; // 2026-11-15T12:00:00Z
const contentDigest = `sha-256=:${crypto.createHash('sha256').update('').digest('base64')}:`;
const invocationHeaders = {
  'Agent-DID': `sig1="${BOB}"`,
  Date: new Date(created * 1000).toUTCString(),
  'Content-Digest': contentDigest,
  'Agent-DID-Capability': member(c2)
};
const components = '("@method" "@authority" "@path" "@query" "content-digest" "date" "agent-did";key="sig1" "agent-did-capability";key="sig1")';
const signatureParams = `${components};created=${created};expires=${created + 30};nonce="0123456789abcdef0123456789abcdef";keyid="${BOB}#key-1";alg="ed25519";tag="agent-did"`;
const signatureBase = [
  '"@method": GET',
  '"@authority": api.example.com',
  '"@path": /files/reports/q1',
  '"@query": ?format=csv',
  `"content-digest": ${contentDigest}`,
  `"date": ${invocationHeaders.Date}`,
  `"agent-did";key="sig1": "${BOB}"`,
  `"agent-did-capability";key="sig1": ${member(c2).slice('sig1='.length)}`,
  `"@signature-params": ${signatureParams}`
].join('\n');
const invocationSignature = sign(`${BOB}#key-1`, Buffer.from(signatureBase, 'utf8'));
const invocation = {
  request: {
    method: 'GET',
    url: invocationUrl,
    headers: {
      ...invocationHeaders,
      'Signature-Input': `sig1=${signatureParams}`,
      Signature: `sig1=:${invocationSignature.toString('base64')}:`
    }
  },
  keyId: `${BOB}#key-1`,
  capabilityId: c2.id,
  signatureBase
};

// ---------------------------------------------------------------------------
// OAuth client assertions
// ---------------------------------------------------------------------------

function jws(keyId, header, claims) {
  const input = `${b64url(Buffer.from(jcs(header)))}.${b64url(Buffer.from(jcs(claims)))}`;
  return `${input}.${b64url(sign(keyId, Buffer.from(input, 'ascii')))}`;
}

const bobKey = `${BOB}#key-1`;
const baseHeader = { alg: 'EdDSA', kid: bobKey, typ: 'client-authentication+jwt' };
const baseClaims = { iss: CLIENT_ID, sub: CLIENT_ID, aud: ISSUER, jti: 'vector-jti-1', iat: IAT, exp: IAT + 60 };
const assertionSign = [
  { name: 'EdDSA, default lifetime', params: { clientId: CLIENT_ID, issuer: ISSUER, verificationMethodId: bobKey, issuedAt: IAT, jti: 'vector-jti-1', lifetimeSeconds: 60, jwsAlg: 'EdDSA' }, assertion: jws(bobKey, baseHeader, baseClaims) },
  { name: 'Ed25519, 300 s', params: { clientId: CLIENT_ID, issuer: ISSUER, verificationMethodId: bobKey, issuedAt: IAT, jti: 'vector-jti-2', lifetimeSeconds: 300, jwsAlg: 'Ed25519' }, assertion: jws(bobKey, { ...baseHeader, alg: 'Ed25519' }, { ...baseClaims, jti: 'vector-jti-2', exp: IAT + 300 }) }
];

const expectation = { clientId: CLIENT_ID, issuer: ISSUER, did: BOB, now: IAT + 10, maxClockSkewSeconds: 30 };
const verify = (name, header, claims, expected, extra = {}) => ({
  name,
  assertion: extra.assertion ?? jws(extra.signWith ?? bobKey, header, claims),
  ...expectation,
  ...(extra.expectation ?? {}),
  expected
});
const { typ: _typ, ...untypedHeader } = baseHeader;
const otherKey = `${CAROL}#key-1`;
const valid = jws(bobKey, baseHeader, baseClaims);
const [vh, vc] = valid.split('.');
const assertionVerify = [
  verify('typed EdDSA', baseHeader, baseClaims, 'ok'),
  verify('alg Ed25519', { ...baseHeader, alg: 'Ed25519' }, baseClaims, 'ok'),
  verify('untyped', untypedHeader, baseClaims, 'ok'),
  verify('application/ typ in another case', { ...baseHeader, typ: 'application/Client-Authentication+JWT' }, baseClaims, 'ok'),
  verify('nbf within the skew', baseHeader, { ...baseClaims, nbf: IAT + 30 }, 'ok'),
  verify('aud as a one-element list', baseHeader, { ...baseClaims, aud: [ISSUER] }, 'audience_invalid'),
  verify('aud is the token endpoint', baseHeader, { ...baseClaims, aud: `${ISSUER}/token` }, 'audience_invalid'),
  verify('sub is another client', baseHeader, { ...baseClaims, sub: 'other' }, 'client_id_mismatch'),
  verify('iss is another client', baseHeader, { ...baseClaims, iss: 'other' }, 'client_id_mismatch'),
  verify('lifetime 301 s', baseHeader, { ...baseClaims, exp: IAT + 301 }, 'lifetime_exceeded'),
  verify('exp equals iat', baseHeader, { ...baseClaims, exp: IAT }, 'lifetime_exceeded'),
  verify('iat in the future beyond the skew', baseHeader, { ...baseClaims, iat: IAT + 100, exp: IAT + 160 }, 'not_yet_valid'),
  verify('nbf in the future beyond the skew', baseHeader, { ...baseClaims, nbf: IAT + 100 }, 'not_yet_valid'),
  verify('expired beyond the skew', baseHeader, baseClaims, 'expired', { expectation: { now: IAT + 91 } }),
  verify('typ JWT', { ...baseHeader, typ: 'JWT' }, baseClaims, 'type_invalid'),
  verify('alg ES256', { ...baseHeader, alg: 'ES256' }, baseClaims, 'alg_unsupported'),
  verify('alg none', { ...baseHeader, alg: 'none' }, baseClaims, 'alg_unsupported'),
  verify('crit header', { ...baseHeader, crit: ['exp'] }, baseClaims, 'malformed_assertion'),
  verify('kid of another DID', { ...baseHeader, kid: otherKey }, baseClaims, 'kid_not_bound', { signWith: otherKey }),
  verify('kid without fragment', { ...baseHeader, kid: BOB }, baseClaims, 'kid_not_bound'),
  verify('jti is a number', baseHeader, { ...baseClaims, jti: 7 }, 'malformed_assertion'),
  verify('jti with a space', baseHeader, { ...baseClaims, jti: 'a b' }, 'malformed_assertion'),
  verify('iat is a string', baseHeader, { ...baseClaims, iat: String(IAT) }, 'malformed_assertion'),
  verify('two segments', baseHeader, baseClaims, 'malformed_assertion', { assertion: `${vh}.${vc}` }),
  verify('padded base64url', baseHeader, baseClaims, 'malformed_assertion', { assertion: `${vh}=.${vc}.${valid.split('.')[2]}` }),
  verify('signature by another key', baseHeader, baseClaims, 'signature_invalid', { signWith: otherKey }),
  verify('claims changed after signing', baseHeader, baseClaims, 'signature_invalid', {
    assertion: `${vh}.${b64url(Buffer.from(jcs({ ...baseClaims, jti: 'changed' })))}.${valid.split('.')[2]}`
  })
];

const keys = Object.fromEntries(Object.keys(SEEDS).map((keyId) => [keyId, { seedHex: SEEDS[keyId], publicKeyMultibase: publicKeyMultibase(keyId) }]));

const output = {
  description:
    'Shared vectors of capabilities (RFC-001 §6.7) and OAuth client assertions (RFC-001 §6.8), ADR-008 D-12f. ' +
    'Regenerate with node scripts/regenerate-delegation-vectors.js. The seeds are TEST-ONLY keys.',
  keys,
  capabilities: {
    rootId: ROOT_ID,
    sign: capabilitySign,
    chains,
    targets,
    headers,
    invocation
  },
  clientAssertions: {
    sign: assertionSign,
    verify: assertionVerify
  }
};

fs.writeFileSync(OUTPUT, `${JSON.stringify(output, null, 2)}\n`);
console.log(`Wrote ${path.relative(process.cwd(), OUTPUT)}: ${chains.length} chains, ${assertionVerify.length} assertion cases`);
