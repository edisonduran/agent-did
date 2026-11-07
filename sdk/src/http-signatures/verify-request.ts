/**
 * Agent-DID RFC 9421 request verification (profile checks, signature base, replay).
 * The cryptographic check is injected so this module never resolves DIDs itself.
 */
import { bytesToHex } from '@noble/hashes/utils';
import { VerificationRelationship, VerifyHttpRequestSignatureParams } from '../core/types';
import {
  buildSignatureBase,
  getSignatureParam,
  parseSignatureHeader,
  parseSignatureInputHeader,
  SignatureInput
} from '../core/http-signatures';
import { IdentityCompositionError } from '../core/identity-composition';
import { NonceStore } from '../core/nonce-store';
import { AGENT_DID_HTTP_SIGNATURE_COMPONENTS, AGENT_DID_HTTP_SIGNATURE_TAG, computeContentDigest } from '../core/http-profile';

export interface VerifyRequestDeps {
  /** Verifies `signatureHex` over `payload` by `keyId` under the DID `did`. */
  verifySignature: (
    did: string,
    payload: string,
    signatureHex: string,
    keyId: string,
    purpose: VerificationRelationship
  ) => Promise<boolean>;
  nonceStore: NonceStore;
  now: Date;
}

/** RFC-001 §6.5 item 2: the required components, in this order; additional ones may follow. */
function startsWithComponents(components: readonly string[], required: readonly string[]): boolean {
  return required.every((component, index) => components[index] === component);
}

export async function verifyAgentDidHttpRequest(
  params: VerifyHttpRequestSignatureParams,
  deps: VerifyRequestDeps
): Promise<boolean> {
  const headers = Object.fromEntries(
    Object.entries(params.headers).map(([key, value]) => [key.toLowerCase(), value])
  );
  const signatureAgent = headers['signature-agent'];
  if (!headers['signature'] || !headers['signature-input'] || !signatureAgent) {
    return false;
  }
  if (headers['content-digest'] !== computeContentDigest(params.body)) {
    return false;
  }

  let inputs: Map<string, SignatureInput>;
  let signatures: Map<string, Uint8Array>;
  try {
    inputs = parseSignatureInputHeader(headers['signature-input']);
    signatures = parseSignatureHeader(headers['signature']);
  } catch {
    return false;
  }

  const now = Math.floor(deps.now.getTime() / 1000);
  const maxSkew = params.maxCreatedSkewSeconds ?? 300;
  const maxLifetime = params.maxSignatureLifetimeSeconds ?? 300;
  const nonceStore = params.nonceStore ?? deps.nonceStore;
  const request = { method: params.method.toUpperCase(), url: params.url, headers };

  for (const [label, input] of inputs) {
    const signature = signatures.get(label);
    if (!signature) {
      continue;
    }

    const created = getSignatureParam(input, 'created');
    const expires = getSignatureParam(input, 'expires');
    const nonce = getSignatureParam(input, 'nonce');
    const keyId = getSignatureParam(input, 'keyid');
    if (
      getSignatureParam(input, 'tag') !== AGENT_DID_HTTP_SIGNATURE_TAG ||
      getSignatureParam(input, 'alg') !== 'ed25519' ||
      typeof created !== 'number' ||
      typeof expires !== 'number' ||
      typeof nonce !== 'string' || nonce.length === 0 ||
      typeof keyId !== 'string' ||
      !keyId.startsWith(`${signatureAgent}#`) ||
      !startsWithComponents(input.components, AGENT_DID_HTTP_SIGNATURE_COMPONENTS) ||
      Math.abs(now - created) > maxSkew ||
      expires < created ||
      expires - created > maxLifetime ||
      now > expires
    ) {
      continue;
    }

    let signatureBase: string;
    try {
      signatureBase = buildSignatureBase(request, input);
    } catch {
      continue;
    }

    // A `keyid` that is not an `assertionMethod` of the DID is an untrusted input, so it is a
    // rejection (`false`), not an exception.
    let signatureValid: boolean;
    try {
      signatureValid = await deps.verifySignature(signatureAgent, signatureBase, bytesToHex(signature), keyId, 'assertionMethod');
    } catch (error) {
      if (error instanceof IdentityCompositionError) {
        continue;
      }
      throw error;
    }
    if (!signatureValid) {
      continue;
    }

    // Record the nonce only for a valid signature, so forged requests cannot burn nonces.
    return nonceStore.checkAndStore(`${keyId} ${nonce}`, expires);
  }

  return false;
}
