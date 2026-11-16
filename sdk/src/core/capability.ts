/**
 * Agent-DID capabilities (RFC-001 §6.7, ADR-008 D-12a/b): delegations of authority shaped as Authorization
 * Capabilities (ZCAP v0.4 data model) and secured with one `eddsa-jcs-2022` Data Integrity proof with
 * `proofPurpose: capabilityDelegation`. Aligned with the ZCAP data model; no conformance with it is claimed.
 *
 * This module holds the checks that need no resolution: form, chain structure, root, attenuation and validity
 * period. Key checks and proof verification are in `AgentDidClient.verifyCapabilityChain`.
 *
 * Python parity: `sdk-python/src/agent_did_sdk/core/capability.py`.
 */
import { canonicalizeJson } from '../crypto/hash';
import { DATA_INTEGRITY_PROOF_TYPE, decodeEddsaProofValue, EDDSA_JCS_2022_CRYPTOSUITE } from '../crypto/data-integrity';
import { parseDictionary } from 'structured-headers';
import { bytesToBase64 } from '../crypto/base64';
import { parseRfc3339Millis } from '../verification/key-at-time';
import { didOfKeyId } from './agent-card';
import { requestUrlFormProblem } from './http-signatures';
import { AgentCapability, CapabilityRejection } from './types';

/** The only `@context` of a delegated capability. */
export const ZCAP_CONTEXT = 'https://w3id.org/zcap/v1';

/** Prefix of a root capability `id`; the rest is the percent-encoded `invocationTarget`. */
export const ZCAP_ROOT_PREFIX = 'urn:zcap:root:';

/** `proofPurpose` of a delegation proof. */
export const CAPABILITY_DELEGATION_PURPOSE = 'capabilityDelegation';

/** Delegated capabilities after the root a verifier accepts by default. */
export const DEFAULT_MAX_CAPABILITY_CHAIN_LENGTH = 5;

/** Upper bound on `maxChainLength`. */
export const MAX_CAPABILITY_CHAIN_LENGTH = 10;

/** Header field that carries an invoked capability, a Structured Field Dictionary keyed by signature label. */
export const AGENT_DID_CAPABILITY_HTTP_HEADER = 'Agent-DID-Capability';

/** Upper bound, in bytes, on an `Agent-DID-Capability` field value a verifier parses. */
export const MAX_CAPABILITY_HEADER_BYTES = 8192;

const CAPABILITY_MEMBERS = new Set([
  '@context',
  'id',
  'parentCapability',
  'invocationTarget',
  'controller',
  'allowedAction',
  'expires',
  'proof'
]);
const PROOF_MEMBERS = new Set([
  '@context',
  'type',
  'cryptosuite',
  'created',
  'verificationMethod',
  'proofPurpose',
  'capabilityChain',
  'proofValue'
]);
const UUID_URN = /^urn:uuid:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/u;
const DID_PATTERN = /^did:[a-z0-9]+:[A-Za-z0-9._%:-]+$/u;

type JsonObject = Record<string, unknown>;

function isJsonObject(value: unknown): value is JsonObject {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

/**
 * Percent-encodes as ECMAScript `encodeURIComponent` does: every UTF-8 octet except `A-Z a-z 0-9 - _ . ! ~ * ' ( )`.
 */
function encodeComponent(value: string): string {
  return encodeURIComponent(value);
}

/** The `id` of the root capability of `invocationTarget`: `urn:zcap:root:` + its percent-encoded form. */
export function rootCapabilityId(invocationTarget: string): string {
  return `${ZCAP_ROOT_PREFIX}${encodeComponent(invocationTarget)}`;
}

/**
 * `undefined` when `target` is a valid `invocationTarget`: an `https` URL in the normalized form of RFC-001 §6.5
 * item 4, with no query.
 */
export function invocationTargetProblem(target: unknown): string | undefined {
  if (typeof target !== 'string' || !target.startsWith('https://')) {
    return 'invocationTarget must be an https URL';
  }
  if (target.includes('?')) {
    return 'invocationTarget must not have a query';
  }
  const problem = requestUrlFormProblem(target);
  return problem === undefined ? undefined : `invocationTarget is not in normalized form: ${problem}`;
}

/**
 * True when `target` is `parentTarget` or extends its path after a `/` (`https://a.example/files` covers
 * `https://a.example/files/reports`, not `https://a.example/filesystem`).
 */
export function targetWithin(target: string, parentTarget: string): boolean {
  if (target === parentTarget) {
    return true;
  }
  const prefix = parentTarget.endsWith('/') ? parentTarget : `${parentTarget}/`;
  return target.startsWith(prefix) && target.length > prefix.length;
}

/** True when `action` is allowed by a capability whose `allowedAction` is `allowed` (absent = every action). */
export function actionAllowed(action: string, allowed: readonly string[] | undefined): boolean {
  return allowed === undefined || allowed.includes(action);
}

function isStringList(value: unknown): value is string[] {
  return Array.isArray(value) && value.length > 0 && value.every((item) => typeof item === 'string' && item.length > 0);
}

/** The form checks of one delegated capability, without its chain (`undefined` when it has the form). */
export function capabilityFormProblem(capability: unknown): CapabilityRejection | undefined {
  if (!isJsonObject(capability)) return 'malformed_capability';
  if (Object.keys(capability).some((member) => !CAPABILITY_MEMBERS.has(member))) return 'malformed_capability';
  if (canonicalizeJson(capability['@context'] ?? null) !== canonicalizeJson([ZCAP_CONTEXT])) return 'malformed_capability';
  if (typeof capability.id !== 'string' || !UUID_URN.test(capability.id)) return 'malformed_capability';
  if (typeof capability.parentCapability !== 'string' || capability.parentCapability.length === 0) {
    return 'malformed_capability';
  }
  if (invocationTargetProblem(capability.invocationTarget) !== undefined) return 'malformed_capability';
  if (typeof capability.controller !== 'string' || !DID_PATTERN.test(capability.controller)) return 'malformed_capability';
  if (capability.allowedAction !== undefined) {
    if (!isStringList(capability.allowedAction) || new Set(capability.allowedAction).size !== capability.allowedAction.length) {
      return 'malformed_capability';
    }
  }
  if (parseRfc3339Millis(capability.expires) === undefined) return 'malformed_capability';

  const proof = capability.proof;
  if (!isJsonObject(proof) || Object.keys(proof).some((member) => !PROOF_MEMBERS.has(member))) return 'unsupported_proof';
  if (
    proof.type !== DATA_INTEGRITY_PROOF_TYPE ||
    proof.cryptosuite !== EDDSA_JCS_2022_CRYPTOSUITE ||
    proof.proofPurpose !== CAPABILITY_DELEGATION_PURPOSE ||
    didOfKeyId(proof.verificationMethod) === undefined ||
    parseRfc3339Millis(proof.created) === undefined ||
    !Array.isArray(proof.capabilityChain) ||
    proof.capabilityChain.length === 0 ||
    decodeEddsaProofValue(proof.proofValue) === undefined ||
    (proof['@context'] !== undefined && canonicalizeJson(proof['@context']) !== canonicalizeJson([ZCAP_CONTEXT]))
  ) {
    return 'unsupported_proof';
  }
  return undefined;
}

/** A capability chain that passed the checks needing no resolution. */
export interface CheckedCapabilityChain {
  /** The root capability `id`. */
  rootId: string;
  /** The target the root names. */
  rootTarget: string;
  /** The root controllers the verifier configured for `rootTarget`. */
  rootControllers: readonly string[];
  /** Delegated capabilities from the one under the root to the leaf. */
  capabilities: AgentCapability[];
  /** The actions the leaf allows: the last `allowedAction` in the chain (absent = every action). */
  allowedAction?: string[];
}

/** The ids of a `capabilityChain`, with an embedded parent replaced by its `id`. */
function chainIds(chain: readonly unknown[]): string[] | undefined {
  const ids: string[] = [];
  for (const [index, entry] of chain.entries()) {
    if (typeof entry === 'string') {
      ids.push(entry);
    } else if (index === chain.length - 1 && isJsonObject(entry) && typeof entry.id === 'string') {
      ids.push(entry.id);
    } else {
      return undefined;
    }
  }
  return ids;
}

/**
 * The checks of RFC-001 §6.7 that need no resolution, in order: form of every capability in the chain
 * (`malformed_capability`, `unsupported_proof`), chain length (`chain_too_long`), chain structure
 * (`malformed_capability`), root controller configured (`root_controller_unknown`), attenuation at every link
 * (`attenuation_violation`) and validity at `nowMillis` (`expired`). Never throws.
 */
export function checkCapabilityChain(
  capability: unknown,
  rootControllers: Readonly<Record<string, readonly string[]>>,
  nowMillis: number,
  maxChainLength: number = DEFAULT_MAX_CAPABILITY_CHAIN_LENGTH
): { ok: true; value: CheckedCapabilityChain } | { ok: false; reason: CapabilityRejection; capabilityId?: string } {
  try {
    return checkChain(capability, rootControllers, nowMillis, maxChainLength);
  } catch {
    // A value JCS cannot represent (not JSON) is a malformed capability
    return { ok: false, reason: 'malformed_capability' };
  }
}

function checkChain(
  capability: unknown,
  rootControllers: Readonly<Record<string, readonly string[]>>,
  nowMillis: number,
  maxChainLength: number
): { ok: true; value: CheckedCapabilityChain } | { ok: false; reason: CapabilityRejection; capabilityId?: string } {
  const limit = Math.min(Math.max(1, Math.floor(maxChainLength)), MAX_CAPABILITY_CHAIN_LENGTH);
  const leafProblem = capabilityFormProblem(capability);
  if (leafProblem !== undefined) {
    return { ok: false, reason: leafProblem };
  }
  const leaf = capability as unknown as AgentCapability;
  // capabilityChain: ancestor ids from the root, the last one embedded in full when it is not the root
  const leafChain = leaf.proof.capabilityChain;
  if (leafChain.length > limit) {
    return { ok: false, reason: 'chain_too_long', capabilityId: leaf.id };
  }

  // Walk up through the embedded parents
  const capabilities: AgentCapability[] = [leaf];
  let current = leaf;
  while (current.proof.capabilityChain.length > 1) {
    const chain = current.proof.capabilityChain;
    const parent = chain[chain.length - 1];
    const problem = capabilityFormProblem(parent);
    if (problem !== undefined) {
      return { ok: false, reason: problem, capabilityId: current.id };
    }
    const parentCapability = parent as unknown as AgentCapability;
    if (parentCapability.id !== current.parentCapability) {
      return { ok: false, reason: 'malformed_capability', capabilityId: current.id };
    }
    // The parent's chain, with its embedded parent as an id, is this chain without its last entry
    const parentIds = chainIds(parentCapability.proof.capabilityChain);
    const ownIds = chainIds(chain);
    if (
      parentIds === undefined ||
      ownIds === undefined ||
      canonicalizeJson(parentIds) !== canonicalizeJson(ownIds.slice(0, -1))
    ) {
      return { ok: false, reason: 'malformed_capability', capabilityId: current.id };
    }
    capabilities.unshift(parentCapability);
    current = parentCapability;
  }
  const first = capabilities[0];
  const rootId = first.proof.capabilityChain[0];
  if (typeof rootId !== 'string' || rootId !== first.parentCapability || !rootId.startsWith(ZCAP_ROOT_PREFIX)) {
    return { ok: false, reason: 'malformed_capability', capabilityId: first.id };
  }
  if (new Set(capabilities.map((item) => item.id)).size !== capabilities.length) {
    return { ok: false, reason: 'malformed_capability', capabilityId: leaf.id };
  }
  let rootTarget: string;
  try {
    rootTarget = decodeURIComponent(rootId.slice(ZCAP_ROOT_PREFIX.length));
  } catch {
    return { ok: false, reason: 'malformed_capability', capabilityId: first.id };
  }
  if (invocationTargetProblem(rootTarget) !== undefined || rootCapabilityId(rootTarget) !== rootId) {
    return { ok: false, reason: 'malformed_capability', capabilityId: first.id };
  }
  const configured = Object.prototype.hasOwnProperty.call(rootControllers, rootTarget)
    ? rootControllers[rootTarget]
    : undefined;
  if (configured === undefined || configured.length === 0) {
    return { ok: false, reason: 'root_controller_unknown', capabilityId: first.id };
  }

  // Attenuation: target, actions and expiry never widen down the chain
  let parentTarget = rootTarget;
  let parentActions: readonly string[] | undefined;
  let parentExpires = Number.POSITIVE_INFINITY;
  for (const item of capabilities) {
    const expires = parseRfc3339Millis(item.expires) as number;
    if (
      !targetWithin(item.invocationTarget, parentTarget) ||
      // An absent allowedAction inherits the parent's actions; a present one must be a subset of them
      (parentActions !== undefined &&
        item.allowedAction !== undefined &&
        !item.allowedAction.every((action) => parentActions?.includes(action))) ||
      expires > parentExpires
    ) {
      return { ok: false, reason: 'attenuation_violation', capabilityId: item.id };
    }
    parentTarget = item.invocationTarget;
    parentActions = item.allowedAction ?? parentActions;
    parentExpires = expires;
  }
  for (const item of capabilities) {
    if (nowMillis > (parseRfc3339Millis(item.expires) as number)) {
      return { ok: false, reason: 'expired', capabilityId: item.id };
    }
  }
  return {
    ok: true,
    value: {
      rootId,
      rootTarget,
      rootControllers: configured,
      capabilities,
      ...(parentActions !== undefined ? { allowedAction: [...parentActions] } : {})
    }
  };
}

/** The capability without its proof, as `createCapability` signs it. */
export function buildUnsignedCapability(params: {
  id: string;
  parentCapability: string;
  invocationTarget: string;
  controller: string;
  expires: string;
  allowedAction?: readonly string[];
}): Omit<AgentCapability, 'proof'> {
  return {
    '@context': [ZCAP_CONTEXT],
    id: params.id,
    parentCapability: params.parentCapability,
    invocationTarget: params.invocationTarget,
    controller: params.controller,
    ...(params.allowedAction !== undefined ? { allowedAction: [...params.allowedAction] } : {}),
    expires: params.expires
  };
}

/** The `capabilityChain` of a capability delegated from `parent` (or from the root `rootId`). */
export function childCapabilityChain(parent: AgentCapability | string): unknown[] {
  if (typeof parent === 'string') {
    return [parent];
  }
  const parentIds = chainIds(parent.proof.capabilityChain);
  if (parentIds === undefined) {
    throw new TypeError('The parent capability has a malformed capabilityChain');
  }
  return [...parentIds, JSON.parse(JSON.stringify(parent))];
}

/** The `Agent-DID-Capability` member value: the JCS bytes of `capability`, as a Structured Field Byte Sequence. */
export function serializeCapabilityHeader(label: string, capability: AgentCapability): string {
  const bytes = new TextEncoder().encode(canonicalizeJson(capability));
  const value = `${label}=:${bytesToBase64(bytes)}:`;
  if (value.length > MAX_CAPABILITY_HEADER_BYTES) {
    throw new RangeError(`The Agent-DID-Capability field would exceed ${MAX_CAPABILITY_HEADER_BYTES} bytes`);
  }
  return value;
}

/**
 * The capability in the `Agent-DID-Capability` member of `label`: `'missing'` when the field has no member for it,
 * `undefined` when the field or the member is malformed (not a Dictionary, not a Byte Sequence without parameters,
 * not the JCS form of a JSON object). The form of the capability itself is checked by `verifyCapabilityChain`.
 */
export function parseCapabilityHeader(value: string, label: string): AgentCapability | 'missing' | undefined {
  let dictionary: ReturnType<typeof parseDictionary>;
  try {
    dictionary = parseDictionary(value.trim());
  } catch {
    return undefined;
  }
  const member = dictionary.get(label);
  if (member === undefined) {
    return 'missing';
  }
  const [bare, params] = member;
  if (!(bare instanceof ArrayBuffer) || params.size !== 0) {
    return undefined;
  }
  try {
    const text = new TextDecoder('utf-8', { fatal: true }).decode(new Uint8Array(bare));
    const parsed: unknown = JSON.parse(text);
    if (!isJsonObject(parsed) || canonicalizeJson(parsed) !== text) {
      return undefined;
    }
    return parsed as unknown as AgentCapability;
  } catch {
    return undefined;
  }
}
