/**
 * The `AgentMetadataCredential` profile (RFC-001 §4.4, ADR-006 D-8d): form checks and the unsigned credential. The
 * signing and the resolution checks are in `AgentDidClient.issueAgentMetadataCredential` /
 * `verifyAgentMetadataCredential`. Python parity: `sdk-python/src/agent_did_sdk/core/agent_metadata_credential.py`.
 */
import { canonicalizeJson } from '../crypto/hash';
import {
  DATA_INTEGRITY_PROOF_TYPE,
  decodeEddsaProofValue,
  EDDSA_JCS_2022_CRYPTOSUITE
} from '../crypto/data-integrity';
import { parseRfc3339Millis } from '../verification/key-at-time';
import { AgentMetadata, AgentMetadataCredential, AgentMetadataCredentialRejection } from './types';

export const VC_V2_CONTEXT = 'https://www.w3.org/ns/credentials/v2';
export const AGENT_METADATA_CREDENTIAL_TYPE = 'AgentMetadataCredential';

/**
 * The `@context` of every `AgentMetadataCredential`: VC 2.0, the Agent-DID context (it defines `agentMetadata` and its
 * members) and the credential type, which the published Agent-DID context v1 does not define.
 */
export const AGENT_METADATA_CREDENTIAL_CONTEXT: readonly unknown[] = Object.freeze([
  VC_V2_CONTEXT,
  'https://agent-did.org/v1',
  Object.freeze({ [AGENT_METADATA_CREDENTIAL_TYPE]: `https://agent-did.org/vocab#${AGENT_METADATA_CREDENTIAL_TYPE}` })
]);

const CREDENTIAL_TYPES = ['VerifiableCredential', AGENT_METADATA_CREDENTIAL_TYPE];
const CREDENTIAL_MEMBERS = new Set(['@context', 'id', 'type', 'issuer', 'validFrom', 'validUntil', 'credentialSubject', 'proof']);
const STRING_METADATA_MEMBERS = new Set(['name', 'description', 'version', 'coreModelHash', 'systemPromptHash', 'memberOf']);

type JsonObject = Record<string, unknown>;

function isJsonObject(value: unknown): value is JsonObject {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

/** A DID without path, query or fragment (DID Core §3.1 characters). */
const DID_PATTERN = /^did:[a-z0-9]+:[A-Za-z0-9._%:-]+$/u;

function isDid(value: unknown): value is string {
  return typeof value === 'string' && DID_PATTERN.test(value);
}

/** `undefined` when `metadata` is a non-empty object of known `agentMetadata` members with valid values. */
export function agentMetadataProblem(metadata: unknown): string | undefined {
  if (!isJsonObject(metadata)) {
    return 'agentMetadata must be an object';
  }
  const entries = Object.entries(metadata).filter(([, value]) => value !== undefined);
  if (entries.length === 0) {
    return 'agentMetadata must state at least one member';
  }
  for (const [member, value] of entries) {
    if (STRING_METADATA_MEMBERS.has(member)) {
      if (typeof value !== 'string') return `agentMetadata.${member} must be a string`;
    } else if (member === 'capabilities') {
      if (!Array.isArray(value) || !value.every((item) => typeof item === 'string')) {
        return 'agentMetadata.capabilities must be an array of strings';
      }
    } else {
      return `agentMetadata.${member} is not an agentMetadata member`;
    }
  }
  return undefined;
}

/** A copy of `metadata` without `undefined` members (JSON has no `undefined`). */
export function cleanAgentMetadata(metadata: Partial<AgentMetadata>): Partial<AgentMetadata> {
  const out: JsonObject = {};
  for (const [member, value] of Object.entries(metadata)) {
    if (value !== undefined) {
      out[member] = Array.isArray(value) ? [...value] : value;
    }
  }
  return out as Partial<AgentMetadata>;
}

/** The credential without its proof, as `issueAgentMetadataCredential` signs it. */
export function buildUnsignedAgentMetadataCredential(params: {
  issuer: string;
  agentDid: string;
  agentMetadata: Partial<AgentMetadata>;
  validFrom: string;
  validUntil?: string;
  id?: string;
}): Omit<AgentMetadataCredential, 'proof'> {
  return {
    '@context': JSON.parse(JSON.stringify(AGENT_METADATA_CREDENTIAL_CONTEXT)),
    ...(params.id !== undefined ? { id: params.id } : {}),
    type: [...CREDENTIAL_TYPES],
    issuer: params.issuer,
    validFrom: params.validFrom,
    ...(params.validUntil !== undefined ? { validUntil: params.validUntil } : {}),
    credentialSubject: { id: params.agentDid, agentMetadata: cleanAgentMetadata(params.agentMetadata) }
  };
}

/** A credential that passed the form checks. */
export interface CheckedAgentMetadataCredential {
  credential: AgentMetadataCredential;
  issuer: string;
  agentDid: string;
  verificationMethod: string;
  agentMetadata: Partial<AgentMetadata>;
}

/**
 * The checks that need no resolution, in order: form, proof form, validity period at `nowMillis`. Returns the
 * rejection reason, or the checked credential.
 */
export function checkAgentMetadataCredentialForm(
  credential: unknown,
  nowMillis: number
): { ok: true; value: CheckedAgentMetadataCredential } | { ok: false; reason: AgentMetadataCredentialRejection } {
  const malformed = { ok: false as const, reason: 'malformed_credential' as const };
  const unsupported = { ok: false as const, reason: 'unsupported_proof' as const };
  if (!isJsonObject(credential)) return malformed;
  if (Object.keys(credential).some((member) => !CREDENTIAL_MEMBERS.has(member))) return malformed;
  if (canonicalizeJson(credential['@context'] ?? null) !== canonicalizeJson(AGENT_METADATA_CREDENTIAL_CONTEXT)) {
    return malformed;
  }
  if (canonicalizeJson(credential.type ?? null) !== canonicalizeJson(CREDENTIAL_TYPES)) return malformed;
  if (credential.id !== undefined && (typeof credential.id !== 'string' || credential.id.length === 0)) return malformed;
  const issuer = credential.issuer;
  if (!isDid(issuer)) return malformed;
  const subject = credential.credentialSubject;
  if (!isJsonObject(subject) || Object.keys(subject).some((member) => member !== 'id' && member !== 'agentMetadata')) {
    return malformed;
  }
  if (!isDid(subject.id) || agentMetadataProblem(subject.agentMetadata) !== undefined) return malformed;
  const validFrom = parseRfc3339Millis(credential.validFrom);
  const validUntil = credential.validUntil === undefined ? undefined : parseRfc3339Millis(credential.validUntil);
  if (validFrom === undefined || (credential.validUntil !== undefined && validUntil === undefined)) return malformed;
  if (validUntil !== undefined && validUntil < validFrom) return malformed;

  const proof = credential.proof;
  if (!isJsonObject(proof)) return unsupported;
  if (
    proof.type !== DATA_INTEGRITY_PROOF_TYPE ||
    proof.cryptosuite !== EDDSA_JCS_2022_CRYPTOSUITE ||
    proof.proofPurpose !== 'assertionMethod' ||
    typeof proof.verificationMethod !== 'string' ||
    !proof.verificationMethod.startsWith(`${issuer}#`) ||
    proof.verificationMethod.length === issuer.length + 1 ||
    decodeEddsaProofValue(proof.proofValue) === undefined
  ) {
    return unsupported;
  }
  if (proof.created !== undefined && parseRfc3339Millis(proof.created) === undefined) return unsupported;
  const proofExpires = proof.expires === undefined ? undefined : parseRfc3339Millis(proof.expires);
  if (proof.expires !== undefined && proofExpires === undefined) return unsupported;

  if (nowMillis < validFrom) return { ok: false, reason: 'not_yet_valid' };
  if ((validUntil !== undefined && nowMillis > validUntil) || (proofExpires !== undefined && nowMillis > proofExpires)) {
    return { ok: false, reason: 'expired' };
  }
  return {
    ok: true,
    value: {
      credential: credential as unknown as AgentMetadataCredential,
      issuer,
      agentDid: subject.id as string,
      verificationMethod: proof.verificationMethod,
      agentMetadata: cleanAgentMetadata(subject.agentMetadata as Partial<AgentMetadata>)
    }
  };
}
