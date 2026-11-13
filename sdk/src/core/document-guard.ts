/**
 * Runtime check of documents that come from outside the process (a did:webvh log, an HTTP or JSON-RPC answer, a
 * file): the TypeScript types say nothing about them. It accepts and rejects what the Python SDK's
 * `AgentDIDDocument` model does, so both SDKs fail the same way on a malformed document.
 */
import { AgentDIDDocument } from './types';

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
    deactivated: optionalString
  });

const credentialLink: Check = (value, path) =>
  fields(value, path, { type: string, issuer: string, credentialSubject: string, proofHash: string });

const agentMetadata: Check = (value, path) =>
  fields(value, path, {
    name: string,
    description: optionalString,
    version: string,
    coreModelHash: string,
    systemPromptHash: string,
    capabilities: optionalStringList,
    memberOf: optionalString
  });

/** Why `value` is not an Agent-DID document, or `undefined` when it is one. */
export function agentDidDocumentProblem(value: unknown): string | undefined {
  return fields(value, 'document', {
    '@context': stringList,
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
  });
}

/** Throws unless `value` is an Agent-DID document; `source` says where it came from in the message. */
export function assertAgentDidDocument(value: unknown, source: string): asserts value is AgentDIDDocument {
  const problem = agentDidDocumentProblem(value);
  if (problem !== undefined) {
    throw new Error(`${source} is not an Agent-DID document: ${problem}`);
  }
}
