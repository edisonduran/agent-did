/**
 * Domain separation for payload signatures (RFC-001 §7).
 *
 * `signMessage` signs `AGENT_DID_MESSAGE_SIGNING_PREFIX + payload`, and `verifySignature` /
 * `verifySignatureAtTime` verify against that same input. The agent key also signs HTTP requests (RFC 9421
 * signature bases, which start with `"@method"`) and the controller key signs did:webvh log proofs (JSON
 * documents): the prefix keeps a payload signature, which a caller may let an agent produce over text it does
 * not control, from being valid as one of those. Python parity: `sdk-python/src/agent_did_sdk/core/message_signing.py`.
 */

/** Domain tag signed in front of every `signMessage` payload. */
export const AGENT_DID_MESSAGE_SIGNING_PREFIX = 'agent-did/v1/message\n';

/** The bytes a payload signature covers: the UTF-8 prefix followed by the UTF-8 payload. */
export function messageSigningInput(payload: string): Uint8Array {
  return new TextEncoder().encode(`${AGENT_DID_MESSAGE_SIGNING_PREFIX}${payload}`);
}
