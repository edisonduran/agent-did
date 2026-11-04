import { sha256 } from '@noble/hashes/sha256';
import { bytesToHex, randomBytes } from '@noble/hashes/utils';

/** Components every Agent-DID HTTP Message Signature covers (RFC 9421). */
export const AGENT_DID_HTTP_SIGNATURE_COMPONENTS: readonly string[] = [
  '@method',
  '@authority',
  '@path',
  '@query',
  'content-digest',
  'date',
  'signature-agent'
];

/** RFC 9421 `tag` parameter of Agent-DID HTTP Message Signatures. */
export const AGENT_DID_HTTP_SIGNATURE_TAG = 'agent-did';

/** RFC 9530 `Content-Digest` with SHA-256. */
export function computeContentDigest(body?: string): string {
  const digest = sha256(new TextEncoder().encode(body || ''));
  return `sha-256=:${Buffer.from(digest).toString('base64')}:`;
}

/** 128-bit random nonce, hex encoded. */
export function generateNonce(): string {
  return bytesToHex(randomBytes(16));
}
