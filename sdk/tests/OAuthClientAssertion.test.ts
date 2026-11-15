/**
 * The OAuth bridge (RFC-001 §6.8, ADR-008 D-12c/e): a JWT client assertion signed with the agent's DID key, its
 * check against the DID, and the JWKS / Client ID Metadata Document for authorization servers without DID support.
 * Python parity: sdk-python/tests/test_oauth_client.py.
 */
import { ed25519 } from '@noble/curves/ed25519';
import {
  AgentDidClient,
  AgentIdentity,
  buildClientJwks,
  buildClientMetadataDocument,
  CLIENT_ASSERTION_TYPE,
  createClientAssertion,
  LocalKeySigner
} from '../src';
import { base64UrlToBytes, bytesToBase64Url } from '../src/crypto/base64';

const ISSUER = 'https://auth.example.com';
const CLIENT_ID = 'https://agents.example.com/bob/client.json';
const NOW = 1_800_000_000;

async function setup() {
  const client = new AgentDidClient({ clock: () => new Date(NOW * 1000) });
  const [controllerSigner] = LocalKeySigner.generate();
  const identity = new AgentIdentity({ controllerSigner, client });
  const created = await identity.create({ name: 'Bob' });
  const did = created.document.id;
  return { client, identity, created, did, keyId: `${did}#key-1`, signer: new LocalKeySigner(created.agentPrivateKey) };
}

function decode(segment: string): Record<string, unknown> {
  return JSON.parse(new TextDecoder().decode(base64UrlToBytes(segment))) as Record<string, unknown>;
}

function resign(parts: { header?: Record<string, unknown>; claims?: Record<string, unknown> }, assertion: string, privateKeyHex: string): string {
  const [h, c] = assertion.split('.');
  const header = parts.header ?? decode(h);
  const claims = parts.claims ?? decode(c);
  const input = `${bytesToBase64Url(new TextEncoder().encode(JSON.stringify(header)))}.${bytesToBase64Url(new TextEncoder().encode(JSON.stringify(claims)))}`;
  const signature = ed25519.sign(new TextEncoder().encode(input), Buffer.from(privateKeyHex, 'hex'));
  return `${input}.${bytesToBase64Url(signature)}`;
}

type Change = { header?: Record<string, unknown>; claims?: Record<string, unknown> };

describe('OAuth client assertion (RFC-001 §6.8)', () => {
  it('creates a typed assertion with aud = issuer and verifies it against the DID', async () => {
    const { client, did, keyId, signer } = await setup();
    const assertion = await createClientAssertion({ clientId: CLIENT_ID, issuer: ISSUER, verificationMethodId: keyId, signer, issuedAt: NOW, jti: 'j-1' });
    const [header, claims] = assertion.split('.').map((part, index) => (index < 2 ? decode(part) : part));
    expect(header).toEqual({ alg: 'EdDSA', kid: keyId, typ: CLIENT_ASSERTION_TYPE });
    expect(claims).toEqual({ iss: CLIENT_ID, sub: CLIENT_ID, aud: ISSUER, jti: 'j-1', iat: NOW, exp: NOW + 60 });

    const result = await client.verifyClientAssertion({ assertion, issuer: ISSUER, clientId: CLIENT_ID, did });
    expect(result).toEqual({ ok: true, did, keyId, clientId: CLIENT_ID, jti: 'j-1', expiresAt: NOW + 60, controllers: expect.any(Array) });
    expect(await client.verifyClientAssertion({ assertion, issuer: ISSUER, clientId: CLIENT_ID, did }))
      .toEqual({ ok: false, reason: 'jti_replayed' });
  });

  it('signs with alg Ed25519 on request, byte-exact and deterministic', async () => {
    const { client, did, keyId, signer } = await setup();
    const params = { clientId: CLIENT_ID, issuer: ISSUER, verificationMethodId: keyId, signer, issuedAt: NOW, jti: 'j-2', jwsAlg: 'Ed25519' as const };
    const first = await createClientAssertion(params);
    expect(await createClientAssertion(params)).toBe(first);
    expect(decode(first.split('.')[0]).alg).toBe('Ed25519');
    expect(await client.verifyClientAssertion({ assertion: first, issuer: ISSUER, clientId: CLIENT_ID, did })).toMatchObject({ ok: true });
  });

  it('refuses bad creation parameters', async () => {
    const { keyId, signer } = await setup();
    const base = { clientId: CLIENT_ID, issuer: ISSUER, verificationMethodId: keyId, signer };
    await expect(createClientAssertion({ ...base, lifetimeSeconds: 301 })).rejects.toThrow(RangeError);
    await expect(createClientAssertion({ ...base, verificationMethodId: 'did:example:x' })).rejects.toThrow(/DID URL/u);
    await expect(createClientAssertion({ ...base, issuer: '' })).rejects.toThrow(/issuer/u);
    await expect(createClientAssertion({ ...base, jwsAlg: 'ES256' as never })).rejects.toThrow(/jwsAlg/u);
  });

  it.each([
    ['audience as a list', { claims: { aud: [ISSUER] } }, 'audience_invalid'],
    ['the token endpoint as audience', { claims: { aud: `${ISSUER}/token` } }, 'audience_invalid'],
    ['another sub', { claims: { sub: 'other' } }, 'client_id_mismatch'],
    ['another iss', { claims: { iss: 'other' } }, 'client_id_mismatch'],
    ['a lifetime over 300 s', { claims: { exp: NOW + 301 } }, 'lifetime_exceeded'],
    ['exp before iat', { claims: { exp: NOW - 1 } }, 'lifetime_exceeded'],
    ['iat in the future', { claims: { iat: NOW + 100, exp: NOW + 160 } }, 'not_yet_valid'],
    ['nbf in the future', { claims: { nbf: NOW + 100 } }, 'not_yet_valid'],
    ['an expired assertion', { claims: { iat: NOW - 200, exp: NOW - 100 } }, 'expired'],
    ['a wrong typ', { header: { typ: 'JWT' } }, 'type_invalid'],
    ['alg ES256', { header: { alg: 'ES256' } }, 'alg_unsupported'],
    ['alg none', { header: { alg: 'none' } }, 'alg_unsupported'],
    ['a crit header', { header: { crit: ['exp'] } }, 'malformed_assertion'],
    ['a kid of another DID', { header: { kid: 'did:webvh:other:example.com#key-1' } }, 'kid_not_bound'],
    ['a jti that is not a string', { claims: { jti: 7 } }, 'malformed_assertion']
  ] as Array<[string, Change, string]>)('rejects %s', async (_name, change, reason) => {
    const { client, did, keyId, signer, created } = await setup();
    const assertion = await createClientAssertion({ clientId: CLIENT_ID, issuer: ISSUER, verificationMethodId: keyId, signer, issuedAt: NOW, jti: 'j-3' });
    const [h, c] = assertion.split('.');
    const forged = resign({
      header: change.header ? { ...decode(h), ...change.header } : undefined,
      claims: change.claims ? { ...decode(c), ...change.claims } : undefined
    }, assertion, created.agentPrivateKey);
    expect(await client.verifyClientAssertion({ assertion: forged, issuer: ISSUER, clientId: CLIENT_ID, did }))
      .toEqual({ ok: false, reason });
  });

  it('accepts an untyped assertion and application/ typ, and rejects a bad signature', async () => {
    const { client, did, keyId, signer, created } = await setup();
    const assertion = await createClientAssertion({ clientId: CLIENT_ID, issuer: ISSUER, verificationMethodId: keyId, signer, issuedAt: NOW, jti: 'j-4' });
    const [h] = assertion.split('.');
    const { typ: _typ, ...untypedHeader } = decode(h);
    const untyped = resign({ header: untypedHeader }, assertion, created.agentPrivateKey);
    expect(await client.verifyClientAssertion({ assertion: untyped, issuer: ISSUER, clientId: CLIENT_ID, did })).toMatchObject({ ok: true });
    const app = resign({ header: { ...decode(h), typ: 'application/Client-Authentication+JWT', }, claims: { ...decode(assertion.split('.')[1]), jti: 'j-5' } }, assertion, created.agentPrivateKey);
    expect(await client.verifyClientAssertion({ assertion: app, issuer: ISSUER, clientId: CLIENT_ID, did })).toMatchObject({ ok: true });
    const [a, b] = assertion.split('.');
    const badSignature = `${a}.${b}.${bytesToBase64Url(new Uint8Array(64))}`;
    expect(await client.verifyClientAssertion({ assertion: badSignature, issuer: ISSUER, clientId: CLIENT_ID, did }))
      .toEqual({ ok: false, reason: 'signature_invalid' });
    expect(await client.verifyClientAssertion({ assertion: 'a.b', issuer: ISSUER, clientId: CLIENT_ID, did }))
      .toEqual({ ok: false, reason: 'malformed_assertion' });
  });

  it('rejects a key that is not under authentication', async () => {
    const { client, did, signer } = await setup();
    const assertion = await createClientAssertion({ clientId: CLIENT_ID, issuer: ISSUER, verificationMethodId: `${did}#key-9`, signer, issuedAt: NOW, jti: 'j-6' });
    expect(await client.verifyClientAssertion({ assertion, issuer: ISSUER, clientId: CLIENT_ID, did }))
      .toEqual({ ok: false, reason: 'key_not_authorized' });
  });

  it('exports the authentication keys as a JWKS and a Client ID Metadata Document', async () => {
    const { created, did, keyId, signer } = await setup();
    const jwks = buildClientJwks(created.document);
    expect(jwks).toEqual({
      keys: [{ kty: 'OKP', crv: 'Ed25519', x: bytesToBase64Url(await signer.getPublicKey()), kid: keyId, use: 'sig' }]
    });
    const metadata = buildClientMetadataDocument({ clientId: CLIENT_ID, clientName: 'Bob', didDocument: created.document });
    expect(metadata).toEqual({
      client_id: CLIENT_ID,
      client_name: 'Bob',
      grant_types: ['client_credentials'],
      token_endpoint_auth_method: 'private_key_jwt',
      token_endpoint_auth_signing_alg: 'EdDSA',
      agent_did: did,
      jwks
    });
    expect(buildClientMetadataDocument({ clientId: CLIENT_ID, clientName: 'Bob', didDocument: created.document, jwksUri: `${CLIENT_ID}.jwks` }))
      .toMatchObject({ jwks_uri: `${CLIENT_ID}.jwks` });
    expect(() => buildClientMetadataDocument({ clientId: 'http://agents.example.com/c', clientName: 'Bob', didDocument: created.document }))
      .toThrow(/https/u);
    expect(() => buildClientMetadataDocument({ clientId: 'https://agents.example.com/', clientName: 'Bob', didDocument: created.document }))
      .toThrow(/path/u);
  });
});

describe('OAuth client assertion: cross-check with an independent JOSE implementation (jose)', () => {
  it('verifies our assertion with jose against the exported JWKS', async () => {
    const jose = await import('jose');
    const { created, keyId, signer } = await setup();
    const assertion = await createClientAssertion({ clientId: CLIENT_ID, issuer: ISSUER, verificationMethodId: keyId, signer, issuedAt: NOW, jti: 'x-1' });
    const jwk = buildClientJwks(created.document).keys[0];
    const key = await jose.importJWK({ ...jwk }, 'EdDSA');
    const { payload, protectedHeader } = await jose.jwtVerify(assertion, key, {
      issuer: CLIENT_ID,
      subject: CLIENT_ID,
      audience: ISSUER,
      typ: CLIENT_ASSERTION_TYPE,
      algorithms: ['EdDSA'],
      currentDate: new Date((NOW + 10) * 1000)
    });
    expect(protectedHeader.kid).toBe(keyId);
    expect(payload.jti).toBe('x-1');
  });

  it('accepts an assertion that jose signed with the agent key', async () => {
    const jose = await import('jose');
    const { client, created, did, keyId } = await setup();
    const jwk = buildClientJwks(created.document).keys[0];
    const privateJwk = { ...jwk, d: bytesToBase64Url(Buffer.from(created.agentPrivateKey, 'hex')) };
    const key = await jose.importJWK(privateJwk, 'EdDSA');
    const assertion = await new jose.SignJWT({ jti: 'x-2' })
      .setProtectedHeader({ alg: 'EdDSA', kid: keyId, typ: CLIENT_ASSERTION_TYPE })
      .setIssuer(CLIENT_ID)
      .setSubject(CLIENT_ID)
      .setAudience(ISSUER)
      .setIssuedAt(NOW)
      .setExpirationTime(NOW + 60)
      .sign(key);
    expect(await client.verifyClientAssertion({ assertion, issuer: ISSUER, clientId: CLIENT_ID, did }))
      .toMatchObject({ ok: true, keyId, jti: 'x-2' });
  });
});
