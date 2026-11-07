#!/usr/bin/env node
/**
 * Regenerates fixtures/http-verification-vectors.json: the Agent-DID HTTP verification vectors
 * of RFC-001 §6.5. Unlike fixtures/interop-vectors.json (one valid request), this set pins the
 * rejection rules: every negative vector differs from the valid request by ONE change and is
 * re-signed when the change touches signed material, so the rule under test is the only reason
 * to reject.
 *
 * The output is deterministic. The two Ed25519 seeds below are TEST-ONLY keys. They are public
 * on purpose so that anyone can re-create and extend the vectors; they sign nothing real.
 * The signature base is built here independently of the SDKs (RFC 9421 §2.5).
 *
 * Usage: node scripts/regenerate-http-verification-vectors.js
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const KEY1_SEED = '7958271424af3c751ae144db07922b9d56e8a4a7d8f5e373389d015ff6e752b2';
const KEY2_SEED = 'c7a8e4fffc86dadfc9f4818635119d8409ac8636155da999e981b9c821dd6ca8';
const NONCE = 'a36ac89f07c664f989ce3dab9eeecb2b';

const PKCS8_PREFIX = Buffer.from('302e020100300506032b657004220420', 'hex');

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

function sign(message, seedHex) {
  return crypto.sign(null, Buffer.from(message, 'utf-8'), privateKeyObject(seedHex));
}

const B58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
function base58Encode(bytes) {
  let num = BigInt('0x' + Buffer.from(bytes).toString('hex'));
  let result = '';
  while (num > 0n) {
    result = B58_ALPHABET[Number(num % 58n)] + result;
    num /= 58n;
  }
  for (const b of bytes) {
    if (b === 0) result = '1' + result;
    else break;
  }
  return result;
}

function multibase(seedHex) {
  return `z${base58Encode(Buffer.concat([Buffer.from([0xed, 0x01]), publicKeyBytes(seedHex)]))}`;
}

function contentDigest(body) {
  return `sha-256=:${crypto.createHash('sha256').update(body || '', 'utf-8').digest().toString('base64')}:`;
}

const FULL_COMPONENTS = ['@method', '@authority', '@path', '@query', 'content-digest', 'date', 'signature-agent'];

// --- Fixture identities -------------------------------------------------------------------
const DID = 'did:webvh:QmHttpVerifyFixtureScid:verify.example:agents:fixture-bot';
const OTHER_DID = 'did:webvh:QmHttpVerifyOtherScid:verify.example:agents:other-bot';
const CONTROLLER = 'did:webvh:QmHttpVerifyControllerScid:verify.example:organizations:fixture-controller';
const KEY1 = `${DID}#key-1`;
const KEY2 = `${DID}#key-2`;

const NOW = 1704067230; // 2024-01-01T00:00:30Z
const CREATED = NOW - 10;
const EXPIRES = NOW + 50;
const DATE = 'Mon, 01 Jan 2024 00:00:20 GMT';
const REQUEST = {
  method: 'POST',
  url: 'https://api.example.com/v1/verify?mode=fixture',
  body: '{"fixture":true}'
};

// --- Independent RFC 9421 §2.5 signature base ---------------------------------------------
function authorityOf(url) {
  const u = new URL(url);
  return u.host; // the WHATWG URL parser drops the scheme's default port
}

function componentValue(name, request, headers) {
  const u = new URL(request.url);
  switch (name) {
    case '@method': return request.method;
    case '@authority': return authorityOf(request.url);
    case '@path': return u.pathname || '/';
    case '@query': return u.search || '?';
    default: {
      const key = Object.keys(headers).find((k) => k.toLowerCase() === name);
      if (key === undefined) throw new Error(`missing header for component ${name}`);
      return headers[key];
    }
  }
}

function signatureParams({ components, created, expires, nonce, keyid, alg, tag }) {
  const parts = [];
  if (created !== undefined) parts.push(`created=${created}`);
  if (expires !== undefined) parts.push(`expires=${expires}`);
  if (nonce !== undefined) parts.push(`nonce="${nonce}"`);
  if (keyid !== undefined) parts.push(`keyid="${keyid}"`);
  if (alg !== undefined) parts.push(`alg="${alg}"`);
  if (tag !== undefined) parts.push(`tag="${tag}"`);
  return `(${components.map((c) => `"${c}"`).join(' ')})${parts.map((p) => `;${p}`).join('')}`;
}

/**
 * Builds a request's headers. `signedRequest` is what the signer saw; the vector's `request`
 * can differ from it (the "request differs" vectors).
 */
function buildHeaders({ signedRequest = REQUEST, agent = DID, seed = KEY1_SEED, headers = {}, params = {}, signOverride }) {
  const allHeaders = {
    'Signature-Agent': agent,
    'Date': DATE,
    'Content-Digest': contentDigest(signedRequest.body),
    ...headers
  };
  const p = {
    components: FULL_COMPONENTS,
    created: CREATED,
    expires: EXPIRES,
    nonce: NONCE,
    keyid: KEY1,
    alg: 'ed25519',
    tag: 'agent-did',
    ...params
  };
  const sp = signatureParams(p);
  const lines = p.components.map((c) => `"${c}": ${componentValue(c, signedRequest, allHeaders)}`);
  lines.push(`"@signature-params": ${sp}`);
  const base = lines.join('\n');
  const signature = signOverride ? signOverride(base) : sign(base, seed);
  return {
    headers: {
      'Signature': `sig1=:${signature.toString('base64')}:`,
      'Signature-Input': `sig1=${sp}`,
      ...allHeaders
    },
    signatureBase: base
  };
}

// --- Vectors ------------------------------------------------------------------------------
const vectors = [];

function add(id, rule, description, { request = REQUEST, expected, now, maxCreatedSkewSeconds, maxSignatureLifetimeSeconds, build, headersTransform, expectedSequence }) {
  const built = build ? build : buildHeaders({});
  const headers = headersTransform ? headersTransform({ ...built.headers }) : built.headers;
  const vector = { id, rule, description, request };
  if (now !== undefined) vector.now = now;
  if (maxCreatedSkewSeconds !== undefined) vector.maxCreatedSkewSeconds = maxCreatedSkewSeconds;
  if (maxSignatureLifetimeSeconds !== undefined) vector.maxSignatureLifetimeSeconds = maxSignatureLifetimeSeconds;
  vector.headers = headers;
  if (built.signatureBase !== undefined) vector.signatureBase = built.signatureBase;
  if (expectedSequence !== undefined) vector.expectedSequence = expectedSequence;
  else vector.expected = expected;
  vectors.push(vector);
}

const dropHeader = (name) => (h) => {
  delete h[name];
  return h;
};

// Accepted requests
add('valid', '§6.5', 'The baseline request: every rule holds.', { expected: true });

{
  const req = { ...REQUEST, url: 'https://api.example.com/v1/verify' };
  add('accept-no-query', '§6.5 item 4 (@query)', 'A request without a query signs `@query` as `?`.', {
    request: req,
    build: buildHeaders({ signedRequest: req }),
    expected: true
  });
}
{
  const req = { ...REQUEST, url: 'https://api.example.com:443/v1/verify?mode=fixture' };
  add('accept-explicit-default-port', '§6.5 item 4 (@authority)', 'An explicit default port (:443) is dropped from `@authority`.', {
    request: req,
    build: buildHeaders({ signedRequest: { ...REQUEST, url: 'https://api.example.com/v1/verify?mode=fixture' } }),
    expected: true
  });
}
{
  const req = { ...REQUEST, url: 'https://api.example.com:8443/v1/verify?mode=fixture' };
  add('accept-non-default-port', '§6.5 item 4 (@authority)', 'A non-default port stays in `@authority`.', {
    request: req,
    build: buildHeaders({ signedRequest: req }),
    expected: true
  });
}
add('accept-additional-component', '§6.5 item 2', 'Additional covered components MAY follow the seven required ones.', {
  build: buildHeaders({
    headers: { 'Content-Type': 'application/json' },
    params: { components: [...FULL_COMPONENTS, 'content-type'] }
  }),
  expected: true
});
{
  const built = buildHeaders({});
  add('accept-reserialized-signature-params', '§6.5 item 4', 'The `@signature-params` line is re-serialized from the parsed `Signature-Input`: extra spaces between the covered components do not change the signature base.', {
    build: built,
    headersTransform: (h) => {
      h['Signature-Input'] = h['Signature-Input'].replace('("@method" "@authority"', '("@method"   "@authority"');
      return h;
    },
    expected: true
  });
}
add('accept-header-names-case-insensitive', '§6.5 item 1', 'Header field names are matched case-insensitively.', {
  headersTransform: (h) => {
    const out = {};
    for (const [k, v] of Object.entries(h)) out[k.toLowerCase()] = v;
    return out;
  },
  expected: true
});

// Missing headers
add('reject-missing-signature', '§6.5 item 5', 'No `Signature` header.', { headersTransform: dropHeader('Signature'), expected: false });
add('reject-missing-signature-input', '§6.5 item 5', 'No `Signature-Input` header.', { headersTransform: dropHeader('Signature-Input'), expected: false });
add('reject-missing-signature-agent', '§6.5 item 1', 'No `Signature-Agent` header.', { headersTransform: dropHeader('Signature-Agent'), expected: false });
add('reject-missing-date', '§6.5 item 1', 'No `Date` header (the signature covers it).', { headersTransform: dropHeader('Date'), expected: false });
add('reject-missing-content-digest', '§6.5 item 1', 'No `Content-Digest` header.', { headersTransform: dropHeader('Content-Digest'), expected: false });

// Content-Digest
add('reject-digest-mismatch', '§6.5 item 5 (Content-Digest)', 'The body differs from the one `Content-Digest` was computed over.', {
  request: { ...REQUEST, body: '{"fixture":false}' },
  expected: false
});
add('reject-digest-other-algorithm', '§6.5 item 1', '`Content-Digest` uses `sha-512` instead of `sha-256`.', {
  build: buildHeaders({
    headers: { 'Content-Digest': `sha-512=:${crypto.createHash('sha512').update(REQUEST.body, 'utf-8').digest().toString('base64')}:` }
  }),
  expected: false
});

add('reject-digest-with-additional-algorithm', '§6.5 item 1', '`Content-Digest` is a dictionary with `sha-256` and `sha-512`; the profile allows exactly one member, `sha-256`.', {
  build: buildHeaders({
    headers: { 'Content-Digest': `${contentDigest(REQUEST.body)}, sha-512=:${crypto.createHash('sha512').update(REQUEST.body, 'utf-8').digest().toString('base64')}:` }
  }),
  expected: false
});

// Signature parameters
add('reject-foreign-tag', '§6.5 item 3 (tag)', '`tag="web-bot-auth"`: another profile must not be accepted as an Agent-DID signature.', {
  build: buildHeaders({ params: { tag: 'web-bot-auth' } }), expected: false
});
add('reject-missing-tag', '§6.5 item 3 (tag)', 'No `tag` parameter.', { build: buildHeaders({ params: { tag: undefined } }), expected: false });
add('reject-other-alg', '§6.5 item 3 (alg)', '`alg="ecdsa-p256-sha256"` on an Ed25519 signature.', { build: buildHeaders({ params: { alg: 'ecdsa-p256-sha256' } }), expected: false });
add('reject-missing-alg', '§6.5 item 3 (alg)', 'No `alg` parameter.', { build: buildHeaders({ params: { alg: undefined } }), expected: false });
add('reject-missing-nonce', '§6.5 item 3 (nonce)', 'No `nonce` parameter.', { build: buildHeaders({ params: { nonce: undefined } }), expected: false });
add('reject-empty-nonce', '§6.5 item 3 (nonce)', 'An empty `nonce`.', { build: buildHeaders({ params: { nonce: '' } }), expected: false });
add('reject-missing-created', '§6.5 item 3 (created)', 'No `created` parameter.', { build: buildHeaders({ params: { created: undefined } }), expected: false });
add('reject-missing-expires', '§6.5 item 3 (expires)', 'No `expires` parameter.', { build: buildHeaders({ params: { expires: undefined } }), expected: false });
add('reject-missing-keyid', '§6.5 item 3 (keyid)', 'No `keyid` parameter.', { build: buildHeaders({ params: { keyid: undefined } }), expected: false });

// Time
add('reject-expired', '§6.5 item 5 (now <= expires)', '`now` is after `expires`.', {
  now: EXPIRES + 1, expected: false
});
add('accept-at-expires', '§6.5 item 5 (now <= expires)', '`now` equals `expires`.', {
  now: EXPIRES, expected: true
});
add('reject-created-in-the-future', '§6.5 item 5 (created skew)', '`created` is later than `now` by more than the allowed skew.', {
  now: NOW, maxCreatedSkewSeconds: 5,
  build: buildHeaders({ params: { created: NOW + 10, expires: NOW + 40 } }), expected: false
});
add('reject-created-in-the-past', '§6.5 item 5 (created skew)', '`created` is earlier than `now` by more than the allowed skew.', {
  now: NOW, maxCreatedSkewSeconds: 5,
  build: buildHeaders({ params: { created: NOW - 10, expires: NOW + 20 } }), expected: false
});
add('accept-created-within-skew', '§6.5 item 5 (created skew)', '`created` is earlier than `now` by exactly the allowed skew.', {
  now: NOW, maxCreatedSkewSeconds: 10,
  build: buildHeaders({ params: { created: NOW - 10, expires: NOW + 20 } }), expected: true
});
add('reject-expires-before-created', '§6.5 item 3 (expires >= created)', '`expires` is earlier than `created` while `now` is still before `expires`.', {
  now: NOW, maxCreatedSkewSeconds: 5,
  build: buildHeaders({ params: { created: NOW + 3, expires: NOW + 2 } }), expected: false
});
add('reject-lifetime-exceeded', 'verifier policy (maxSignatureLifetimeSeconds, default 300)', '`expires - created` is 301 seconds with the default lifetime cap.', {
  now: NOW,
  build: buildHeaders({ params: { created: NOW, expires: NOW + 301 } }), expected: false
});
add('accept-lifetime-at-cap', 'verifier policy (maxSignatureLifetimeSeconds, default 300)', '`expires - created` is exactly 300 seconds.', {
  now: NOW,
  build: buildHeaders({ params: { created: NOW, expires: NOW + 300 } }), expected: true
});

// Key binding and purpose
add('reject-keyid-under-other-did', '§6.5 item 3 (keyid)', '`keyid` is a key of another DID, not of the `Signature-Agent` DID. The Signature-Agent document even lists that key under assertionMethod and the signature is valid for it, so only the binding rule can reject it.', {
  build: buildHeaders({ params: { keyid: `${OTHER_DID}#key-1` } }), expected: false
});
add('reject-keyid-not-in-document', '§6.5 item 3 (keyid)', '`keyid` names a fragment the `Signature-Agent` DID document does not have.', {
  build: buildHeaders({ params: { keyid: `${DID}#key-9` } }), expected: false
});
add('reject-keyagreement-only-key', '§6.5 item 5 / §6.2.1 (assertionMethod)', '`keyid` is a key listed only under `keyAgreement`, and the signature is valid for it.', {
  build: buildHeaders({ seed: KEY2_SEED, params: { keyid: KEY2 } }), expected: false
});
add('reject-signature-by-other-key', '§6.5 item 5', 'The signature verifies under key-2, not under the `keyid` key-1.', {
  build: buildHeaders({ seed: KEY2_SEED }), expected: false
});
add('reject-tampered-signature', '§6.5 item 5', 'The last byte of the signature is changed.', {
  headersTransform: (h) => {
    const m = /^sig1=:(.+):$/u.exec(h['Signature']);
    const bytes = Buffer.from(m[1], 'base64');
    bytes[bytes.length - 1] ^= 0x01;
    h['Signature'] = `sig1=:${bytes.toString('base64')}:`;
    return h;
  },
  expected: false
});
add('reject-malformed-signature-input', 'RFC 8941', '`Signature-Input` is not a Structured Field dictionary.', {
  headersTransform: (h) => {
    h['Signature-Input'] = h['Signature-Input'].replace('sig1=(', 'sig1=[');
    return h;
  },
  expected: false
});

// Required components, one dropped at a time (re-signed, so only the profile check can reject)
for (const component of FULL_COMPONENTS) {
  add(`reject-component-dropped-${component.replace('@', '')}`, '§6.5 item 2', `The signature does not cover \`${component}\`.`, {
    build: buildHeaders({ params: { components: FULL_COMPONENTS.filter((c) => c !== component) } }),
    expected: false
  });
}

// Required components must come in the order of §6.5 item 2 (re-signed: only the order is wrong)
const swapped = [...FULL_COMPONENTS];
[swapped[1], swapped[2]] = [swapped[2], swapped[1]];
add('reject-components-reordered', '§6.5 item 2', 'Two required components are swapped (`@path` before `@authority`).', {
  build: buildHeaders({ params: { components: swapped } }), expected: false
});
add('reject-components-reversed', '§6.5 item 2', 'The seven required components in reverse order.', {
  build: buildHeaders({ params: { components: [...FULL_COMPONENTS].reverse() } }), expected: false
});
add('reject-additional-component-first', '§6.5 item 2', 'An additional component comes before the required ones; additional components may only follow.', {
  build: buildHeaders({
    headers: { 'Content-Type': 'application/json' },
    params: { components: ['content-type', ...FULL_COMPONENTS] }
  }),
  expected: false
});

// The verified request differs from the signed one
const request2 = (change) => ({ ...REQUEST, ...change });
add('reject-method-differs', '§6.5 item 4', 'The request method differs from the signed one.', { request: request2({ method: 'PUT' }), expected: false });
add('reject-authority-differs', '§6.5 item 4', 'The request host differs from the signed one.', { request: request2({ url: 'https://evil.example.com/v1/verify?mode=fixture' }), expected: false });
add('reject-path-differs', '§6.5 item 4', 'The request path differs from the signed one.', { request: request2({ url: 'https://api.example.com/v1/admin?mode=fixture' }), expected: false });
add('reject-query-differs', '§6.5 item 4', 'The request query differs from the signed one.', { request: request2({ url: 'https://api.example.com/v1/verify?mode=other' }), expected: false });

// Replay
add('reject-replayed-nonce', '§6.5 item 6', 'The same request is verified twice with one nonce store: the second `(keyid, nonce)` is a replay.', {
  expectedSequence: [true, false]
});

// --- Output -------------------------------------------------------------------------------
// --- Rejection reasons (HttpSignatureRejection) ---------------------------------------------
const REASONS = {
  'reject-missing-signature': 'missing_headers',
  'reject-missing-signature-input': 'missing_headers',
  'reject-missing-signature-agent': 'missing_headers',
  'reject-missing-date': 'signed_component_missing',
  'reject-missing-content-digest': 'digest_mismatch',
  'reject-digest-mismatch': 'digest_mismatch',
  'reject-digest-other-algorithm': 'digest_mismatch',
  'reject-digest-with-additional-algorithm': 'digest_mismatch',
  'reject-foreign-tag': 'tag_mismatch',
  'reject-missing-tag': 'tag_mismatch',
  'reject-other-alg': 'alg_unsupported',
  'reject-missing-alg': 'alg_unsupported',
  'reject-missing-nonce': 'params_missing',
  'reject-empty-nonce': 'params_missing',
  'reject-missing-created': 'params_missing',
  'reject-missing-expires': 'params_missing',
  'reject-missing-keyid': 'params_missing',
  'reject-expired': 'expired',
  'reject-created-in-the-future': 'created_skew',
  'reject-created-in-the-past': 'created_skew',
  'reject-expires-before-created': 'expires_before_created',
  'reject-lifetime-exceeded': 'lifetime_exceeded',
  'reject-keyid-under-other-did': 'keyid_not_bound',
  'reject-keyid-not-in-document': 'keyid_not_authorized',
  'reject-keyagreement-only-key': 'keyid_not_authorized',
  'reject-signature-by-other-key': 'signature_invalid',
  'reject-tampered-signature': 'signature_invalid',
  'reject-malformed-signature-input': 'malformed_headers',
  'reject-components-reordered': 'components_order',
  'reject-components-reversed': 'components_order',
  'reject-additional-component-first': 'components_order',
  'reject-method-differs': 'signature_invalid',
  'reject-authority-differs': 'signature_invalid',
  'reject-path-differs': 'signature_invalid',
  'reject-query-differs': 'signature_invalid'
};
for (const component of FULL_COMPONENTS) {
  REASONS[`reject-component-dropped-${component.replace('@', '')}`] = 'components_missing';
}
for (const vector of vectors) {
  if (vector.expectedSequence) {
    vector.expectedReasons = vector.expectedSequence.map((ok) => (ok ? null : 'nonce_replayed'));
  } else if (vector.expected === false) {
    if (!REASONS[vector.id]) throw new Error(`no reason for ${vector.id}`);
    vector.reason = REASONS[vector.id];
  }
}

const fixture = {
  formatVersion: 1,
  description: 'Agent-DID HTTP verification vectors (RFC-001 §6.5): accepted and rejected requests. Each rejected vector differs from the valid one by a single change and is re-signed when that change touches signed material. Generated by scripts/regenerate-http-verification-vectors.js.',
  usage: 'For each vector: build the Signature-Agent DID document from `keys` (every key is a verification method listed under its `relationships`), register it in a resolver, create a client whose clock returns `now` (the vector\'s own, else `clock`), and verify `request` with `headers` and a fresh nonce store whose own clock returns the same time.`expected` is the verdict and, for a rejection, `reason` is the `HttpSignatureRejection` a detailed verifier reports; `expectedSequence` is the sequence of verdicts (and `expectedReasons` the reasons, null for an accepted one) when the same request is verified repeatedly with ONE nonce store. Unless a vector gives its own, use the default verifier policy (skew 300 s, lifetime 300 s).',
  keysNote: 'TEST-ONLY Ed25519 keys. The seeds are public on purpose; they sign nothing real.',
  clock: NOW,
  did: DID,
  otherDid: OTHER_DID,
  controller: CONTROLLER,
  keys: {
    'key-1': { id: KEY1, seedHex: KEY1_SEED, publicKeyMultibase: multibase(KEY1_SEED), relationships: ['authentication', 'assertionMethod'] },
    'key-2': { id: KEY2, seedHex: KEY2_SEED, publicKeyMultibase: multibase(KEY2_SEED), relationships: ['keyAgreement'] },
    'foreign-key': { id: `${OTHER_DID}#key-1`, seedHex: KEY1_SEED, publicKeyMultibase: multibase(KEY1_SEED), relationships: ['assertionMethod'] }
  },
  vectors
};

const out = JSON.stringify(fixture, null, 2) + '\n';
const outPath = path.join(__dirname, '..', 'fixtures', 'http-verification-vectors.json');
fs.writeFileSync(outPath, out);
console.log(`Wrote ${outPath} (${vectors.length} vectors: ${vectors.filter((v) => v.expected === true).length} accepted)`);
