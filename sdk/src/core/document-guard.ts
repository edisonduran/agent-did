/**
 * Runtime check of documents that come from outside the process (a did:webvh log, an HTTP or JSON-RPC answer, a
 * file): the TypeScript types say nothing about them. It accepts and rejects what the Python SDK's
 * `AgentDIDDocument` model does, so both SDKs fail the same way on a malformed document.
 */
import { AgentDIDDocument } from './types';
import { isEd25519VerificationMethodType, isRevokedContextTerm } from './verification-method';

type Check = (value: unknown, path: string) => string | undefined;

const isObject = (value: unknown): value is Record<string, unknown> =>
  typeof value === 'object' && value !== null && !Array.isArray(value);

const string: Check = (value, path) => (typeof value === 'string' ? undefined : `${path} must be a string`);
const optionalString: Check = (value, path) => (value === undefined || value === null ? undefined : string(value, path));
const stringList: Check = (value, path) => {
  if (!Array.isArray(value)) {
    return `${path} must be a list of strings`;
  }
  const bad = value.findIndex((item) => typeof item !== 'string');
  return bad === -1 ? undefined : `${path}[${bad}] must be a string`;
};
const optionalStringList: Check = (value, path) =>
  value === undefined || value === null ? undefined : stringList(value, path);

function fields(value: unknown, path: string, checks: Record<string, Check>): string | undefined {
  if (!isObject(value)) {
    return `${path} must be an object`;
  }
  for (const [name, check] of Object.entries(checks)) {
    const problem = check(value[name], `${path}.${name}`);
    if (problem) {
      return problem;
    }
  }
  return undefined;
}

function list(value: unknown, path: string, item: Check, optional = false): string | undefined {
  if (optional && (value === undefined || value === null)) {
    return undefined;
  }
  if (!Array.isArray(value)) {
    return `${path} must be a list`;
  }
  for (let index = 0; index < value.length; index += 1) {
    const problem = item(value[index], `${path}[${index}]`);
    if (problem) {
      return problem;
    }
  }
  return undefined;
}

const verificationMethod: Check = (value, path) =>
  fields(value, path, {
    id: string,
    type: string,
    controller: string,
    publicKeyMultibase: optionalString,
    blockchainAccountId: optionalString,
    deactivated: optionalString,
    revoked: optionalString
  }) ??
  revokedIsRetired(value as Record<string, unknown>, path) ??
  ed25519KeyType(value as Record<string, unknown>, path);

const absent = (value: unknown): boolean => value === undefined || value === null;

/** A revoked key is a retired key: `revoked` without `deactivated` is malformed. */
function revokedIsRetired(method: Record<string, unknown>, path: string): string | undefined {
  return !absent(method.revoked) && absent(method.deactivated) ? `${path}.revoked requires deactivated` : undefined;
}

/** A `publicKeyMultibase` key is an Ed25519 key here, so its method must have one of the Ed25519 types. */
function ed25519KeyType(method: Record<string, unknown>, path: string): string | undefined {
  if (method.publicKeyMultibase === undefined || method.publicKeyMultibase === null) {
    return undefined;
  }
  return isEd25519VerificationMethodType(method.type)
    ? undefined
    : `${path}.type must be Multikey or Ed25519VerificationKey2020 for a publicKeyMultibase key`;
}

const credentialLink: Check = (value, path) =>
  fields(value, path, { type: string, issuer: string, credentialSubject: string, proofHash: string });

const agentMetadata: Check = (value, path) =>
  fields(value, path, {
    name: string,
    description: optionalString,
    version: string,
    coreModelHash: optionalString,
    systemPromptHash: optionalString,
    capabilities: optionalStringList,
    memberOf: optionalString
  });

/**
 * `@context`: context URLs, then the inline `revoked` term as the last entry when a key carries `revoked` (and only
 * then).
 */
function contextProblem(document: Record<string, unknown>): string | undefined {
  const context = document['@context'];
  if (!Array.isArray(context)) {
    return 'document.@context must be a list';
  }
  const bad = context.findIndex(
    (entry, index) => typeof entry !== 'string' && (!isRevokedContextTerm(entry) || index !== context.length - 1)
  );
  if (bad !== -1) {
    return `document.@context[${bad}] must be a string (or the inline revoked term, last)`;
  }
  const hasTerm = context.length > 0 && typeof context[context.length - 1] !== 'string';
  const methods = Array.isArray(document.verificationMethod) ? (document.verificationMethod as unknown[]) : [];
  const hasRevoked = methods.some(
    (method) => typeof method === 'object' && method !== null && !absent((method as Record<string, unknown>).revoked)
  );
  if (hasRevoked && !hasTerm) {
    return 'document.@context must end with the inline revoked term when a key is revoked';
  }
  if (!hasRevoked && hasTerm) {
    return 'document.@context has the inline revoked term but no key is revoked';
  }
  return undefined;
}

/** Why `value` is not an Agent-DID document, or `undefined` when it is one. */
export function agentDidDocumentProblem(value: unknown): string | undefined {
  return fields(value, 'document', {
    '@context': (item, path) => (Array.isArray(item) ? undefined : `${path} must be a list`),
    id: string,
    controller: string,
    created: string,
    updated: string,
    agentMetadata,
    complianceCertifications: (item, path) => list(item, path, credentialLink, true),
    verificationMethod: (item, path) => list(item, path, verificationMethod),
    authentication: stringList,
    assertionMethod: optionalStringList,
    capabilityDelegation: optionalStringList,
    capabilityInvocation: optionalStringList,
    keyAgreement: optionalStringList
  }) ?? contextProblem(value as Record<string, unknown>);
}

/** Throws unless `value` is an Agent-DID document; `source` says where it came from in the message. */
export function assertAgentDidDocument(value: unknown, source: string): asserts value is AgentDIDDocument {
  const problem = agentDidDocumentProblem(value);
  if (problem !== undefined) {
    throw new Error(`${source} is not an Agent-DID document: ${problem}`);
  }
}
