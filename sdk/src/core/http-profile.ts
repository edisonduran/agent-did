import { sha256 } from '@noble/hashes/sha256';
import { bytesToHex, randomBytes } from '@noble/hashes/utils';
import { parseDictionary, serializeDictionary } from 'structured-headers';
import { bytesToBase64 } from '../crypto/base64';
import { ComponentIdentifier, HttpSignatureError } from './http-signatures';

/** Header field that carries the agent DID, as a Structured Field Dictionary keyed by signature label. */
export const AGENT_DID_HTTP_HEADER = 'Agent-DID';

/** Signature label the SDK signs with. */
export const AGENT_DID_HTTP_SIGNATURE_LABEL = 'sig1';

/**
 * Components an Agent-DID HTTP Message Signature labelled `label` covers, in this order (RFC-001 §6.5 item 2):
 * `"@method" "@authority" "@path" "@query" "content-digest" "date" "agent-did";key="<label>"`.
 */
export function agentDidHttpSignatureComponents(label: string): ComponentIdentifier[] {
  return ['@method', '@authority', '@path', '@query', 'content-digest', 'date', { name: 'agent-did', key: label }];
}

/** Serializes an `Agent-DID` field value with one member: `<label>="<did>"`. */
export function serializeAgentDidHeader(label: string, did: string): string {
  try {
    return serializeDictionary(new Map([[label, [did, new Map()]]]));
  } catch (error) {
    throw new HttpSignatureError(`Cannot serialize the Agent-DID field: ${error instanceof Error ? error.message : String(error)}`);
  }
}

/**
 * Parses an `Agent-DID` field value: label -> DID. A member that is not a String, or that has parameters, maps to
 * `undefined`. Throws `HttpSignatureError` when the field is not a Structured Field Dictionary.
 */
export function parseAgentDidHeader(value: string): Map<string, string | undefined> {
  let dictionary: ReturnType<typeof parseDictionary>;
  try {
    dictionary = parseDictionary(value.trim());
  } catch (error) {
    throw new HttpSignatureError(`Malformed Agent-DID field: ${error instanceof Error ? error.message : String(error)}`);
  }
  const result = new Map<string, string | undefined>();
  for (const [label, [bare, params]] of dictionary) {
    result.set(label, typeof bare === 'string' && params.size === 0 ? bare : undefined);
  }
  return result;
}

/** RFC 9421 `tag` parameter of Agent-DID HTTP Message Signatures. */
export const AGENT_DID_HTTP_SIGNATURE_TAG = 'agent-did';

/** RFC 9530 `Content-Digest` with SHA-256 of the body bytes (a string is hashed as UTF-8). */
export function computeContentDigest(body?: string | Uint8Array): string {
  const bytes = typeof body === 'string' ? new TextEncoder().encode(body) : (body ?? new Uint8Array());
  const digest = sha256(bytes);
  return `sha-256=:${bytesToBase64(digest)}:`;
}

/** 128-bit random nonce, hex encoded. */
export function generateNonce(): string {
  return bytesToHex(randomBytes(16));
}
