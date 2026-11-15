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
  ComponentIdentifier,
  getSignatureParam,
  parseSignatureHeader,
  parseSignatureInputHeader,
  requestUrlFormProblem,
  serializeComponentIdentifier,
  SignatureInput
} from '../core/http-signatures';
import { NONCE_PATTERN, NonceStore } from '../core/nonce-store';
import {
  AGENT_DID_HTTP_SIGNATURE_TAG,
  agentDidHttpSignatureComponents,
  computeContentDigest,
  parseAgentDidHeader
} from '../core/http-profile';

/** What the injected cryptographic check found. */
export type SignatureCheckOutcome =
  | 'valid'
  | 'invalid'
  | 'key_not_authorized'
  | 'did_resolution_failed'
  | 'controller_not_bound';

/** What the injected check found and, for a valid signature, the controller chain of the DID (nearest first). */
export interface SignatureCheck {
  outcome: SignatureCheckOutcome;
  controllers?: string[];
}

export interface VerifyRequestDeps {
  /** Verifies `signatureHex` over `payload` by `keyId` under the DID `did`. */
  verifySignature: (
    did: string,
    payload: string,
    signatureHex: string,
    keyId: string,
    purpose: VerificationRelationship
  ) => Promise<SignatureCheck>;
  nonceStore: NonceStore;
  now: Date;
}

/**
 * Extra checks of a profile built on the §6.5 request profile (capability invocation, RFC-001 §6.7). `beforeSignature`
 * runs once the profile checks pass and before any resolution; `afterSignature` after the signature verifies and
 * before the nonce is recorded.
 */
export interface VerifyRequestExtension<State, Extra> {
  /** The relationship the signing key must be listed under. */
  relationship: VerificationRelationship;
  beforeSignature(
    label: string,
    input: SignatureInput,
    agentDid: string
  ): { ok: true; state: State } | { ok: false; reason: string; capabilityId?: string };
  afterSignature(
    state: State
  ): Promise<{ ok: true; extra: Extra } | { ok: false; reason: string; capabilityId?: string }>;
}

type CoreResult<Extra> =
  | { ok: true; did: string; keyId: string; controllers: string[]; extra?: Extra }
  | { ok: false; reason: string; capabilityId?: string };

/** RFC-001 §6.5 item 2: the required components, in this order; additional ones may follow. */
function startsWithComponents(components: readonly ComponentIdentifier[], required: readonly ComponentIdentifier[]): boolean {
  return required.every((component, index) =>
    components[index] !== undefined && serializeComponentIdentifier(components[index]) === serializeComponentIdentifier(component));
}

function coversAll(components: readonly ComponentIdentifier[], required: readonly ComponentIdentifier[]): boolean {
  const covered = new Set(components.map(serializeComponentIdentifier));
  return required.every((component) => covered.has(serializeComponentIdentifier(component)));
}

export async function verifyAgentDidHttpRequest(
  params: VerifyHttpRequestSignatureParams,
  deps: VerifyRequestDeps
): Promise<VerifyHttpRequestSignatureResult> {
  const result = await verifyAgentDidHttpRequestWith<never, never>(params, deps);
  return result.ok
    ? { ok: true, did: result.did, keyId: result.keyId, controllers: result.controllers }
    : { ok: false, reason: result.reason as HttpSignatureRejection };
}

/** `verifyAgentDidHttpRequest` with the checks of a profile built on it. */
export async function verifyAgentDidHttpRequestWith<State, Extra>(
  params: VerifyHttpRequestSignatureParams,
  deps: VerifyRequestDeps,
  extension?: VerifyRequestExtension<State, Extra>
): Promise<CoreResult<Extra>> {
  const reject = (reason: string, capabilityId?: string): CoreResult<Extra> =>
    capabilityId === undefined ? { ok: false, reason } : { ok: false, reason, capabilityId };
  const headers = Object.fromEntries(
    Object.entries(params.headers).map(([key, value]) => [key.toLowerCase(), value])
  );
  if (!headers['signature'] || !headers['signature-input'] || !headers['agent-did']) {
    return reject('missing_headers');
  }
  if (requestUrlFormProblem(params.url) !== undefined) {
    return reject('url_not_normalized');
  }
  if (headers['content-digest'] !== computeContentDigest(params.body)) {
    return reject('digest_mismatch');
  }

  let inputs: Map<string, SignatureInput>;
  let signatures: Map<string, Uint8Array>;
  let agentDids: Map<string, string | undefined>;
  try {
    inputs = parseSignatureInputHeader(headers['signature-input']);
    signatures = parseSignatureHeader(headers['signature']);
    agentDids = parseAgentDidHeader(headers['agent-did']);
  } catch {
    return reject('malformed_headers');
  }

  const now = Math.floor(deps.now.getTime() / 1000);
  const maxSkew = params.maxCreatedSkewSeconds ?? 300;
  const maxLifetime = params.maxSignatureLifetimeSeconds ?? 300;
  const nonceStore = params.nonceStore ?? deps.nonceStore;
  const request = { method: params.method.toUpperCase(), url: params.url, headers };

  // The reason reported is the first one of a signature with the Agent-DID tag, else the first one.
  const failures: Array<{ reason: string; tagged: boolean; capabilityId?: string }> = [];
  const fail = (reason: string, tagged: boolean, capabilityId?: string): void => {
    failures.push({ reason, tagged, ...(capabilityId !== undefined ? { capabilityId } : {}) });
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
      typeof nonce !== 'string' || !NONCE_PATTERN.test(nonce) ||
      typeof keyId !== 'string'
    ) {
      fail('params_missing', true);
      continue;
    }
    const required = agentDidHttpSignatureComponents(label);
    if (!startsWithComponents(input.components, required)) {
      fail(coversAll(input.components, required) ? 'components_order' : 'components_missing', true);
      continue;
    }
    // The agent DID is the Agent-DID member keyed by this signature's label: a String without parameters
    if (!agentDids.has(label)) {
      fail('signed_component_missing', true);
      continue;
    }
    const agentDid = agentDids.get(label);
    if (agentDid === undefined) {
      fail('malformed_headers', true);
      continue;
    }
    // Before any resolution: a DID outside the list costs no network call
    if (params.allowedDids !== undefined && !params.allowedDids.includes(agentDid)) {
      fail('did_not_allowed', true);
      continue;
    }
    if (!keyId.startsWith(`${agentDid}#`)) {
      fail('keyid_not_bound', true);
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

    let state: State | undefined;
    if (extension !== undefined) {
      const before = extension.beforeSignature(label, input, agentDid);
      if (!before.ok) {
        fail(before.reason, true, before.capabilityId);
        continue;
      }
      state = before.state;
    }

    const { outcome, controllers = [] } = await deps.verifySignature(
      agentDid,
      signatureBase,
      bytesToHex(signature),
      keyId,
      extension?.relationship ?? REQUIRED_RELATIONSHIP_BY_ARTIFACT.http_request
    );
    if (outcome !== 'valid') {
      fail(
        outcome === 'did_resolution_failed' ? 'did_resolution_failed'
          : outcome === 'controller_not_bound' ? 'controller_not_bound'
            : outcome === 'key_not_authorized' ? 'keyid_not_authorized'
              : 'signature_invalid',
        true
      );
      continue;
    }

    if (
      params.allowedControllers !== undefined &&
      !controllers.some((controller) => params.allowedControllers?.includes(controller))
    ) {
      fail('controller_not_allowed', true);
      continue;
    }

    let extra: Extra | undefined;
    if (extension !== undefined) {
      const after = await extension.afterSignature(state as State);
      if (!after.ok) {
        fail(after.reason, true, after.capabilityId);
        continue;
      }
      extra = after.extra;
    }

    // Record the nonce only for an accepted signature, so forged or refused requests cannot burn nonces.
    if (!(await nonceStore.checkAndStore(`${keyId} ${nonce}`, expires))) {
      return reject('nonce_replayed');
    }
    return extension === undefined
      ? { ok: true, did: agentDid, keyId, controllers }
      : { ok: true, did: agentDid, keyId, controllers, extra };
  }

  const chosen = failures.find((failure) => failure.tagged) ?? failures[0];
  return chosen ? reject(chosen.reason, chosen.capabilityId) : reject('malformed_headers');
}
