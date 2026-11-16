/**
 * The OAuth bridge (RFC-001 §6.8, ADR-008 D-12c/e): the agent's DID key as an OAuth client credential.
 *
 * - `createClientAssertion`: a JWT client assertion (`private_key_jwt`, RFC 7523 as updated by
 *   draft-ietf-oauth-rfc7523bis): `typ: client-authentication+jwt`, `iss` = `sub` = client id, `aud` = the
 *   authorization server's issuer identifier as its only value, signed by an `authentication` key of the DID.
 * - `buildClientJwks` / `buildClientMetadataDocument`: the keys and the OAuth Client ID Metadata Document an
 *   authorization server that does not know DIDs reads.
 * - The check of an assertion against the DID is `AgentDidClient.verifyClientAssertion`; `parseClientAssertion` here
 *   holds the checks that need no resolution.
 *
 * The SDK runs no OAuth flow: no discovery, no token request. Aligned with RFC 7523, draft-ietf-oauth-rfc7523bis and
 * draft-ietf-oauth-client-id-metadata-document; no conformance is claimed.
 *
 * Python parity: `sdk-python/src/agent_did_sdk/core/oauth_client.py`.
 */
import { bytesToHex, hexToBytes, randomBytes } from '@noble/hashes/utils';
import { canonicalizeJson } from '../crypto/hash';
import { base64UrlToBytes, bytesToBase64Url } from '../crypto/base64';
import { didOfKeyId } from './agent-card';
import { AgentSigner, LocalKeySigner } from './signer';
import { activeEd25519PublicKey, relationshipMethods } from './verification-method';
import { ClientAssertionRejection, DidDocument, JwsEd25519Alg } from './types';

/** `typ` of a client assertion (draft-ietf-oauth-rfc7523bis). */
export const CLIENT_ASSERTION_TYPE = 'client-authentication+jwt';

/** `client_assertion_type` of a token request that carries a JWT client assertion (RFC 7523 §2.2). */
export const CLIENT_ASSERTION_TYPE_JWT_BEARER = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer';

/** Default lifetime of a client assertion, in seconds. */
export const DEFAULT_CLIENT_ASSERTION_LIFETIME_SECONDS = 60;

/** Longest lifetime (`exp - iat`) a client assertion may have, in seconds. */
export const MAX_CLIENT_ASSERTION_LIFETIME_SECONDS = 300;

/** Upper bound, in characters, on an assertion a verifier parses. */
export const MAX_CLIENT_ASSERTION_LENGTH = 8192;

const JWS_ALGS: readonly JwsEd25519Alg[] = ['EdDSA', 'Ed25519'];
const JTI_PATTERN = /^[\x21-\x7e]{1,256}$/u;

type JsonObject = Record<string, unknown>;

function isJsonObject(value: unknown): value is JsonObject {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function isIntegerSeconds(value: unknown): value is number {
  return typeof value === 'number' && Number.isSafeInteger(value) && value >= 0;
}

function encodeSegment(value: JsonObject): string {
  return bytesToBase64Url(new TextEncoder().encode(canonicalizeJson(value)));
}

/** Parameters of `createClientAssertion`. */
export interface CreateClientAssertionParams {
  /** The OAuth `client_id` (a Client ID Metadata Document URL or a pre-registered id). `iss` and `sub`. */
  clientId: string;
  /** The authorization server's issuer identifier (RFC 8414), never its token endpoint. The only `aud` value. */
  issuer: string;
  /** DID URL of an Ed25519 `authentication` key of the agent DID; the JWS `kid`. */
  verificationMethodId: string;
  /** Signer that holds the key. Either this or `agentPrivateKey`. */
  signer?: AgentSigner;
  /** Ed25519 private key hex. */
  agentPrivateKey?: string;
  /** Lifetime in seconds (default 60, at most 300). */
  lifetimeSeconds?: number;
  /** JWS `alg` (default `EdDSA`; `Ed25519` per RFC 9864). */
  jwsAlg?: JwsEd25519Alg;
  /** `iat` in seconds since the epoch (default: now). For tests and vectors. */
  issuedAt?: number;
  /** `jti` (default: 128 random bits, hex). For tests and vectors. */
  jti?: string;
}

/**
 * A JWT client assertion signed with the agent's DID key (RFC-001 §6.8). The caller checks that
 * `verificationMethodId` is under the DID's `authentication`: `AgentDidClient.verifyClientAssertion` rejects any
 * other key. Send it as `client_assertion` with `client_assertion_type` = `CLIENT_ASSERTION_TYPE_JWT_BEARER`.
 */
export async function createClientAssertion(params: CreateClientAssertionParams): Promise<string> {
  if (typeof params.clientId !== 'string' || params.clientId.length === 0) {
    throw new TypeError('clientId is required');
  }
  if (typeof params.issuer !== 'string' || params.issuer.length === 0) {
    throw new TypeError('issuer (the authorization server issuer identifier) is required');
  }
  if (didOfKeyId(params.verificationMethodId) === undefined) {
    throw new TypeError(`verificationMethodId must be a DID URL with a fragment: ${String(params.verificationMethodId)}`);
  }
  const alg = params.jwsAlg ?? 'EdDSA';
  if (!JWS_ALGS.includes(alg)) {
    throw new TypeError(`jwsAlg must be one of ${JWS_ALGS.join(', ')}`);
  }
  const lifetime = params.lifetimeSeconds ?? DEFAULT_CLIENT_ASSERTION_LIFETIME_SECONDS;
  if (!Number.isSafeInteger(lifetime) || lifetime < 1 || lifetime > MAX_CLIENT_ASSERTION_LIFETIME_SECONDS) {
    throw new RangeError(`lifetimeSeconds must be an integer from 1 to ${MAX_CLIENT_ASSERTION_LIFETIME_SECONDS}`);
  }
  const issuedAt = params.issuedAt ?? Math.floor(Date.now() / 1000);
  if (!isIntegerSeconds(issuedAt)) {
    throw new TypeError('issuedAt must be a non-negative integer number of seconds');
  }
  const jti = params.jti ?? bytesToHex(randomBytes(16));
  if (!JTI_PATTERN.test(jti)) {
    throw new TypeError('jti must be 1 to 256 printable ASCII characters');
  }
  const signer = params.signer ?? (params.agentPrivateKey ? new LocalKeySigner(params.agentPrivateKey) : undefined);
  if (signer === undefined) {
    throw new Error('Either signer or agentPrivateKey must be provided');
  }
  const header = { alg, kid: params.verificationMethodId, typ: CLIENT_ASSERTION_TYPE };
  const claims = {
    iss: params.clientId,
    sub: params.clientId,
    aud: params.issuer,
    jti,
    iat: issuedAt,
    exp: issuedAt + lifetime
  };
  const signingInput = `${encodeSegment(header)}.${encodeSegment(claims)}`;
  const signature = hexToBytes(await signer.sign(new TextEncoder().encode(signingInput)));
  if (signature.length !== 64) {
    throw new Error('An Ed25519 signature is 64 bytes');
  }
  return `${signingInput}.${bytesToBase64Url(signature)}`;
}

/** A client assertion that passed the checks needing no resolution. */
export interface ParsedClientAssertion {
  alg: JwsEd25519Alg;
  keyId: string;
  did: string;
  jti: string;
  issuedAt: number;
  expiresAt: number;
  signingInput: string;
  signature: Uint8Array;
}

/** What `parseClientAssertion` checks the claims against. */
export interface ClientAssertionExpectations {
  clientId: string;
  issuer: string;
  did: string;
  nowSeconds: number;
  maxClockSkewSeconds: number;
}

function decodeJsonSegment(segment: string): JsonObject | undefined {
  const bytes = base64UrlToBytes(segment);
  if (bytes === undefined) {
    return undefined;
  }
  try {
    const value: unknown = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes));
    return isJsonObject(value) ? value : undefined;
  } catch {
    return undefined;
  }
}

function typeAccepted(typ: unknown): boolean {
  if (typ === undefined) {
    return true; // draft-ietf-oauth-rfc7523bis: servers should not reject an untyped assertion
  }
  if (typeof typ !== 'string') {
    return false;
  }
  const lowered = typ.toLowerCase();
  return lowered === CLIENT_ASSERTION_TYPE || lowered === `application/${CLIENT_ASSERTION_TYPE}`;
}

/**
 * The checks of RFC-001 §6.8 that need no resolution, in order: compact JWS form (`malformed_assertion`), `alg`
 * (`alg_unsupported`), `typ` (`type_invalid`), `kid` a DID URL of the expected DID (`kid_not_bound`), `iss` and
 * `sub` (`client_id_mismatch`), `aud` (`audience_invalid`), times (`lifetime_exceeded`, `not_yet_valid`, `expired`).
 * Never throws.
 */
export function parseClientAssertion(
  assertion: unknown,
  expected: ClientAssertionExpectations
): { ok: true; value: ParsedClientAssertion } | { ok: false; reason: ClientAssertionRejection } {
  const malformed = { ok: false as const, reason: 'malformed_assertion' as const };
  if (typeof assertion !== 'string' || assertion.length > MAX_CLIENT_ASSERTION_LENGTH) return malformed;
  const parts = assertion.split('.');
  if (parts.length !== 3) return malformed;
  const header = decodeJsonSegment(parts[0]);
  const claims = decodeJsonSegment(parts[1]);
  const signature = base64UrlToBytes(parts[2]);
  if (header === undefined || claims === undefined || signature === undefined || signature.length !== 64) {
    return malformed;
  }
  if (header.crit !== undefined || header.b64 !== undefined) return malformed;
  if (!JWS_ALGS.includes(header.alg as JwsEd25519Alg)) return { ok: false, reason: 'alg_unsupported' };
  if (!typeAccepted(header.typ)) return { ok: false, reason: 'type_invalid' };
  const keyId = header.kid;
  if (didOfKeyId(keyId) !== expected.did) return { ok: false, reason: 'kid_not_bound' };
  if (claims.iss !== expected.clientId || claims.sub !== expected.clientId) {
    return { ok: false, reason: 'client_id_mismatch' };
  }
  if (typeof claims.aud !== 'string' || claims.aud !== expected.issuer) return { ok: false, reason: 'audience_invalid' };
  const { iat, exp, nbf, jti } = claims;
  if (!isIntegerSeconds(iat) || !isIntegerSeconds(exp) || (nbf !== undefined && !isIntegerSeconds(nbf))) {
    return malformed;
  }
  if (typeof jti !== 'string' || !JTI_PATTERN.test(jti)) return malformed;
  if (exp <= iat || exp - iat > MAX_CLIENT_ASSERTION_LIFETIME_SECONDS) return { ok: false, reason: 'lifetime_exceeded' };
  const skew = expected.maxClockSkewSeconds;
  if (iat > expected.nowSeconds + skew || (nbf !== undefined && nbf > expected.nowSeconds + skew)) {
    return { ok: false, reason: 'not_yet_valid' };
  }
  if (expected.nowSeconds > exp + skew) return { ok: false, reason: 'expired' };
  return {
    ok: true,
    value: {
      alg: header.alg as JwsEd25519Alg,
      keyId: keyId as string,
      did: expected.did,
      jti,
      issuedAt: iat,
      expiresAt: exp,
      signingInput: `${parts[0]}.${parts[1]}`,
      signature
    }
  };
}

/** A JSON Web Key of an Ed25519 public key (RFC 8037). */
export interface Ed25519Jwk {
  kty: 'OKP';
  crv: 'Ed25519';
  x: string;
  kid: string;
  use: 'sig';
  alg?: JwsEd25519Alg;
}

/**
 * The JWKS of the active Ed25519 `authentication` keys of `document`, `kid` = the key's DID URL, for a Client ID
 * Metadata Document (`jwks` or `jwks_uri`) or a pre-registration. Republish it when the agent rotates a key: an
 * authorization server caches it.
 */
export function buildClientJwks(document: DidDocument, options: { alg?: JwsEd25519Alg } = {}): { keys: Ed25519Jwk[] } {
  const keys: Ed25519Jwk[] = [];
  const seen = new Set<string>();
  for (const method of relationshipMethods(document, 'authentication')) {
    const publicKey = activeEd25519PublicKey(method);
    if (publicKey === undefined || seen.has(method.id)) {
      continue;
    }
    seen.add(method.id);
    keys.push({
      kty: 'OKP',
      crv: 'Ed25519',
      x: bytesToBase64Url(publicKey),
      kid: method.id,
      use: 'sig',
      ...(options.alg !== undefined ? { alg: options.alg } : {})
    });
  }
  return { keys };
}

/** Parameters of `buildClientMetadataDocument`. */
export interface ClientMetadataDocumentParams {
  /** The `https` URL the document is served at; it is also the `client_id`. */
  clientId: string;
  clientName: string;
  /** The agent's DID document: its `authentication` keys become `jwks`, its `id` the `agent_did` member. */
  didDocument: DidDocument;
  /** OAuth grant types (default `["client_credentials"]`). */
  grantTypes?: readonly string[];
  /** Redirect URIs, for an `authorization_code` client. */
  redirectUris?: readonly string[];
  /** `client_uri`, a page about the client. */
  clientUri?: string;
  /** `jwks_uri` instead of embedding `jwks`. */
  jwksUri?: string;
  /** `token_endpoint_auth_signing_alg` (default `EdDSA`). */
  jwsAlg?: JwsEd25519Alg;
}

/**
 * An OAuth Client ID Metadata Document (draft-ietf-oauth-client-id-metadata-document) for an agent that
 * authenticates with `private_key_jwt` and its DID key. `agent_did` names the DID; an authorization server that does
 * not know it ignores it.
 */
export function buildClientMetadataDocument(params: ClientMetadataDocumentParams): Record<string, unknown> {
  let url: URL;
  try {
    url = new URL(params.clientId);
  } catch {
    throw new TypeError('clientId must be an https URL');
  }
  if (url.protocol !== 'https:' || url.pathname === '/' || url.hash !== '' || url.href !== params.clientId) {
    throw new TypeError('clientId must be an https URL with a path, without a fragment, in normalized form');
  }
  if (typeof params.clientName !== 'string' || params.clientName.length === 0) {
    throw new TypeError('clientName is required');
  }
  const alg = params.jwsAlg ?? 'EdDSA';
  const document: Record<string, unknown> = {
    client_id: params.clientId,
    client_name: params.clientName,
    ...(params.clientUri !== undefined ? { client_uri: params.clientUri } : {}),
    grant_types: [...(params.grantTypes ?? ['client_credentials'])],
    ...(params.redirectUris !== undefined ? { redirect_uris: [...params.redirectUris] } : {}),
    token_endpoint_auth_method: 'private_key_jwt',
    token_endpoint_auth_signing_alg: alg,
    agent_did: params.didDocument.id
  };
  if (params.jwksUri !== undefined) {
    document.jwks_uri = params.jwksUri;
  } else {
    const jwks = buildClientJwks(params.didDocument);
    if (jwks.keys.length === 0) {
      throw new Error(`${params.didDocument.id} has no active Ed25519 authentication key`);
    }
    document.jwks = jwks;
  }
  return document;
}
