/**
 * Agent-DID RFC 9421 request verification (profile checks, signature base, replay).
 * The cryptographic check is injected so this module never resolves DIDs itself.
 *
 * Python parity: `agent_did_sdk.http_signatures.verify_request`.
 */
import { bytesToHex } from '@noble/hashes/utils';
import { REQUIRED_RELATIONSHIP_BY_ARTIFACT } from '../core/identity-composition';
import {
  HttpSignatureRejection,
  VerificationRelationship,
  VerifyHttpRequestSignatureParams,
  VerifyHttpRequestSignatureResult
} from '../core/types';
import {
  buildSignatureBase,
  getSignatureParam,
  parseSignatureHeader,
  parseSignatureInputHeader,
  SignatureInput
} from '../core/http-signatures';
import { NonceStore } from '../core/nonce-store';
import { AGENT_DID_HTTP_SIGNATURE_COMPONENTS, AGENT_DID_HTTP_SIGNATURE_TAG, computeContentDigest } from '../core/http-profile';

/** What the injected cryptographic check found. */
export type SignatureCheckOutcome = 'valid' | 'invalid' | 'key_not_authorized' | 'did_resolution_failed';

export interface VerifyRequestDeps {
  /** Verifies `signatureHex` over `payload` by `keyId` under the DID `did`. */
  verifySignature: (
    did: string,
    payload: string,
    signatureHex: string,
    keyId: string,
    purpose: VerificationRelationship
  ) => Promise<SignatureCheckOutcome>;
  nonceStore: NonceStore;
  now: Date;
}

const OK: VerifyHttpRequestSignatureResult = { ok: true };
const reject = (reason: HttpSignatureRejection): VerifyHttpRequestSignatureResult => ({ ok: false, reason });

/** RFC-001 §6.5 item 2: the required components, in this order; additional ones may follow. */
function startsWithComponents(components: readonly string[], required: readonly string[]): boolean {
  return required.every((component, index) => components[index] === component);
}

export async function verifyAgentDidHttpRequest(
  params: VerifyHttpRequestSignatureParams,
  deps: VerifyRequestDeps
): Promise<VerifyHttpRequestSignatureResult> {
  const headers = Object.fromEntries(
    Object.entries(params.headers).map(([key, value]) => [key.toLowerCase(), value])
  );
  const signatureAgent = headers['signature-agent'];
  if (!headers['signature'] || !headers['signature-input'] || !signatureAgent) {
    return reject('missing_headers');
  }
  if (headers['content-digest'] !== computeContentDigest(params.body)) {
    return reject('digest_mismatch');
  }

  let inputs: Map<string, SignatureInput>;
  let signatures: Map<string, Uint8Array>;
  try {
    inputs = parseSignatureInputHeader(headers['signature-input']);
    signatures = parseSignatureHeader(headers['signature']);
  } catch {
    return reject('malformed_headers');
  }

  const now = Math.floor(deps.now.getTime() / 1000);
  const maxSkew = params.maxCreatedSkewSeconds ?? 300;
  const maxLifetime = params.maxSignatureLifetimeSeconds ?? 300;
  const nonceStore = params.nonceStore ?? deps.nonceStore;
  const request = { method: params.method.toUpperCase(), url: params.url, headers };

  // The reason reported is the first one of a signature with the Agent-DID tag, else the first one.
  const failures: Array<{ reason: HttpSignatureRejection; tagged: boolean }> = [];
  const fail = (reason: HttpSignatureRejection, tagged: boolean): void => {
    failures.push({ reason, tagged });
  };

  for (const [label, input] of inputs) {
    const signature = signatures.get(label);
    if (!signature) {
      fail('malformed_headers', false);
      continue;
    }
    if (getSignatureParam(input, 'tag') !== AGENT_DID_HTTP_SIGNATURE_TAG) {
      fail('tag_mismatch', false);
      continue;
    }

    const created = getSignatureParam(input, 'created');
    const expires = getSignatureParam(input, 'expires');
    const nonce = getSignatureParam(input, 'nonce');
    const keyId = getSignatureParam(input, 'keyid');
    if (getSignatureParam(input, 'alg') !== 'ed25519') {
      fail('alg_unsupported', true);
      continue;
    }
    if (
      typeof created !== 'number' ||
      typeof expires !== 'number' ||
      typeof nonce !== 'string' || nonce.length === 0 ||
      typeof keyId !== 'string'
    ) {
      fail('params_missing', true);
      continue;
    }
    if (!keyId.startsWith(`${signatureAgent}#`)) {
      fail('keyid_not_bound', true);
      continue;
    }
    if (!startsWithComponents(input.components, AGENT_DID_HTTP_SIGNATURE_COMPONENTS)) {
      const allCovered = AGENT_DID_HTTP_SIGNATURE_COMPONENTS.every((component) => input.components.includes(component));
      fail(allCovered ? 'components_order' : 'components_missing', true);
      continue;
    }
    if (Math.abs(now - created) > maxSkew) {
      fail('created_skew', true);
      continue;
    }
    if (expires < created) {
      fail('expires_before_created', true);
      continue;
    }
    if (expires - created > maxLifetime) {
      fail('lifetime_exceeded', true);
      continue;
    }
    if (now > expires) {
      fail('expired', true);
      continue;
    }

    let signatureBase: string;
    try {
      signatureBase = buildSignatureBase(request, input);
    } catch {
      fail('signed_component_missing', true);
      continue;
    }

    const outcome = await deps.verifySignature(signatureAgent, signatureBase, bytesToHex(signature), keyId, REQUIRED_RELATIONSHIP_BY_ARTIFACT.http_request);
    if (outcome !== 'valid') {
      fail(
        outcome === 'did_resolution_failed' ? 'did_resolution_failed'
          : outcome === 'key_not_authorized' ? 'keyid_not_authorized'
            : 'signature_invalid',
        true
      );
      continue;
    }

    // Record the nonce only for a valid signature, so forged requests cannot burn nonces.
    return await nonceStore.checkAndStore(`${keyId} ${nonce}`, expires) ? OK : reject('nonce_replayed');
  }

  const chosen = failures.find((failure) => failure.tagged) ?? failures[0];
  return reject(chosen ? chosen.reason : 'malformed_headers');
}
