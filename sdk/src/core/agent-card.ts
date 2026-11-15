/**
 * Signed A2A Agent Cards for the identity composition contract (`docs/RFC-001-A2A-Identity-Composition-Contract.md`).
 *
 * A card is signed as A2A 1.0 §8.4 describes: each entry of `signatures` is a JWS (RFC 7515) whose payload is the RFC
 * 8785 (JCS) form of the card without `signatures`. Agent-DID fixes the profile: protected header
 * `{"alg":"EdDSA","kid":"<DID URL>","typ":"JOSE"}`, an Ed25519 `assertionMethod` key of the agent DID as `kid`. The
 * keys a card publishes are the `kid`s of its signatures and the `keyIds` of the Agent-DID extension in
 * `capabilities.extensions`. This is aligned with A2A 1.0, not verified against an independent implementation.
 *
 * Python parity: `sdk-python/src/agent_did_sdk/core/agent_card.py`.
 */
import { hexToBytes } from '@noble/hashes/utils';
import { canonicalizeJson } from '../crypto/hash';
import { base64UrlToBytes, bytesToBase64Url } from '../crypto/base64';
import { AgentSigner } from './signer';

/** `uri` of the A2A extension through which a card names its agent DID and the keys it publishes. */
export const AGENT_DID_A2A_EXTENSION_URI = 'https://agent-did.org/a2a/identity/v1';

/** The JWS `alg` of an Agent-DID card signature (RFC 8037). */
export const AGENT_CARD_SIGNATURE_ALG = 'EdDSA';

/** Upper bound on `signatures` entries a verifier reads. */
export const MAX_AGENT_CARD_SIGNATURES = 16;

/** An entry of an Agent Card's `signatures` (A2A 1.0 `AgentCardSignature`). */
export interface AgentCardSignature {
  /** Base64url of the JWS protected header (a JSON object). */
  protected: string;
  /** Base64url of the signature over `protected + "." + base64url(JCS(card without signatures))`. */
  signature: string;
  /** Unprotected JWS header members. Not covered by the signature; the SDK does not read them. */
  header?: Record<string, unknown>;
}

/** An A2A Agent Card: any JSON object, optionally with `signatures`. */
export type AgentCard = Record<string, unknown> & { signatures?: AgentCardSignature[] };

/** The parts of a card a verifier checks, once its format is right. */
export interface ParsedAgentCard {
  /** The agent DID every signature `kid` and the extension name. */
  did: string;
  /** One entry per signature, in order. */
  signatures: Array<{ keyId: string; signingInput: string; signature: Uint8Array }>;
  /** Keys the card publishes: signature `kid`s, then extension `keyIds`, without repeats. */
  publishedKeyIds: string[];
}

const isObject = (value: unknown): value is Record<string, unknown> =>
  typeof value === 'object' && value !== null && !Array.isArray(value);

/** The DID of a DID URL with a non-empty fragment and nothing else (`did:method:id#fragment`), else `undefined`. */
export function didOfKeyId(keyId: unknown): string | undefined {
  if (typeof keyId !== 'string') {
    return undefined;
  }
  const match = /^(did:[a-z0-9]+:[^#?/\x00-\x20\x7f]+)#[^#?\x00-\x20\x7f]+$/u.exec(keyId);
  return match ? match[1] : undefined;
}

/** The JWS payload of a card: base64url of the JCS form of the card without `signatures`. */
function cardPayload(card: Record<string, unknown>): string {
  const { signatures: _signatures, ...unsigned } = card;
  return bytesToBase64Url(new TextEncoder().encode(canonicalizeJson(unsigned)));
}

/**
 * Returns a copy of `card` with one more `signatures` entry, signed by `signer` as `keyId` (a DID URL of an
 * `assertionMethod` key of the agent). Signatures already on the card are kept and are not covered.
 */
export async function signAgentCard(card: AgentCard, signer: AgentSigner, keyId: string): Promise<AgentCard> {
  if (!isObject(card)) {
    throw new TypeError('An Agent Card must be a JSON object');
  }
  if (didOfKeyId(keyId) === undefined) {
    throw new TypeError(`keyId must be a DID URL with a fragment: ${String(keyId)}`);
  }
  const existing = card.signatures === undefined ? [] : card.signatures;
  if (!Array.isArray(existing)) {
    throw new TypeError('signatures must be a list');
  }
  const protectedHeader = bytesToBase64Url(
    new TextEncoder().encode(canonicalizeJson({ alg: AGENT_CARD_SIGNATURE_ALG, kid: keyId, typ: 'JOSE' }))
  );
  const signingInput = `${protectedHeader}.${cardPayload(card)}`;
  const signatureBytes = hexToBytes(await signer.sign(new TextEncoder().encode(signingInput)));
  return {
    ...JSON.parse(JSON.stringify(card)),
    signatures: [...existing, { protected: protectedHeader, signature: bytesToBase64Url(signatureBytes) }]
  };
}

/** The Agent-DID extension of a card: absent, or `{ did, keyIds }`; `null` when it is malformed or repeated. */
function agentDidExtension(card: Record<string, unknown>): { did: string; keyIds: string[] } | undefined | null {
  const capabilities = card.capabilities;
  if (capabilities === undefined) {
    return undefined;
  }
  if (!isObject(capabilities)) {
    return null;
  }
  const extensions = capabilities.extensions;
  if (extensions === undefined) {
    return undefined;
  }
  if (!Array.isArray(extensions)) {
    return null;
  }
  const ours = extensions.filter((extension) => isObject(extension) && extension.uri === AGENT_DID_A2A_EXTENSION_URI);
  if (ours.length === 0) {
    return undefined;
  }
  const params = (ours[0] as Record<string, unknown>).params;
  if (ours.length > 1 || !isObject(params) || typeof params.did !== 'string') {
    return null;
  }
  const keyIds = params.keyIds;
  if (!Array.isArray(keyIds) || keyIds.some((keyId) => didOfKeyId(keyId) !== params.did)) {
    return null;
  }
  return { did: params.did, keyIds: keyIds as string[] };
}

/**
 * Checks the format of a signed card without resolving anything: every `signatures` entry is an Agent-DID JWS
 * (protected header with `alg` `EdDSA`, a DID URL `kid`, `typ` `JOSE` when present, no `crit`; a 64-byte
 * signature), every `kid` and the extension name one DID. Returns `undefined` when the card does not have that
 * format (`format_drift`).
 */
export function parseSignedAgentCard(card: unknown): ParsedAgentCard | undefined {
  if (!isObject(card)) {
    return undefined;
  }
  const entries = card.signatures;
  if (!Array.isArray(entries) || entries.length === 0 || entries.length > MAX_AGENT_CARD_SIGNATURES) {
    return undefined;
  }
  let payload: string;
  try {
    payload = cardPayload(card);
  } catch {
    return undefined;
  }
  const signatures: ParsedAgentCard['signatures'] = [];
  const dids = new Set<string>();
  for (const entry of entries) {
    if (!isObject(entry) || typeof entry.protected !== 'string' || typeof entry.signature !== 'string') {
      return undefined;
    }
    if (Object.keys(entry).some((name) => !['protected', 'signature', 'header'].includes(name))) {
      return undefined;
    }
    if (entry.header !== undefined && !isObject(entry.header)) {
      return undefined;
    }
    const headerBytes = base64UrlToBytes(entry.protected);
    const signature = base64UrlToBytes(entry.signature);
    if (headerBytes === undefined || signature === undefined || signature.length !== 64) {
      return undefined;
    }
    let header: unknown;
    try {
      header = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(headerBytes));
    } catch {
      return undefined;
    }
    if (
      !isObject(header) ||
      header.alg !== AGENT_CARD_SIGNATURE_ALG ||
      (header.typ !== undefined && header.typ !== 'JOSE') ||
      header.crit !== undefined
    ) {
      return undefined;
    }
    const did = didOfKeyId(header.kid);
    if (did === undefined) {
      return undefined;
    }
    dids.add(did);
    signatures.push({ keyId: header.kid as string, signingInput: `${entry.protected}.${payload}`, signature });
  }
  const extension = agentDidExtension(card);
  if (extension === null || dids.size !== 1 || (extension !== undefined && !dids.has(extension.did))) {
    return undefined;
  }
  const did = [...dids][0];
  const publishedKeyIds = Array.from(
    new Set([...signatures.map((signature) => signature.keyId), ...(extension?.keyIds ?? [])])
  );
  return { did, signatures, publishedKeyIds };
}
