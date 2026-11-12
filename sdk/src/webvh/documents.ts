/**
 * Pure helpers that build the documents and history derived from did:webvh logs.
 * No state and no I/O: `AgentDidClient` owns the stores and calls these.
 */
import {
  AdditionalVerificationRelationship,
  AgentDIDDocument,
  AgentDocumentHistoryAction,
  AgentDocumentHistoryEntry
} from '../core/types';
import { ADDITIONAL_VERIFICATION_RELATIONSHIPS } from '../core/identity-composition';
import { generateAgentMetadataHash, generateCanonicalDocumentHash } from '../crypto/hash';
import { encodePublicKeyMultibase } from '../crypto/multibase';
import { DID_WEBVH_PLACEHOLDER } from './adapter';

const AGENT_DID_CONTEXT = ['https://www.w3.org/ns/did/v1', 'https://agent-did.org/v1'];

export function cloneDocument(document: AgentDIDDocument): AgentDIDDocument {
  return JSON.parse(JSON.stringify(document)) as AgentDIDDocument;
}

export function computeDocumentReference(document: AgentDIDDocument): string {
  return generateCanonicalDocumentHash(document);
}

export function normalizeDidPathSegment(value: string): string {
  const normalized = value.trim().toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '');
  return normalized || 'agent';
}

/**
 * The extra relationship entries for a new agent key (`CreateAgentParams.additionalVerificationRelationships`),
 * in a fixed order so the document does not depend on the order of the request. Throws `TypeError` for a
 * value that is not an `AdditionalVerificationRelationship`.
 */
export function additionalRelationshipEntries(
  requested: readonly AdditionalVerificationRelationship[] | undefined,
  verificationMethodId: string
): Partial<Record<AdditionalVerificationRelationship, string[]>> {
  if (requested === undefined) {
    return {};
  }
  if (!Array.isArray(requested)) {
    throw new TypeError('additionalVerificationRelationships must be an array');
  }
  for (const relationship of requested) {
    if (!ADDITIONAL_VERIFICATION_RELATIONSHIPS.includes(relationship)) {
      throw new TypeError(
        `Unsupported additional verification relationship: ${String(relationship)} (allowed: ${ADDITIONAL_VERIFICATION_RELATIONSHIPS.join(', ')})`
      );
    }
  }
  return Object.fromEntries(
    ADDITIONAL_VERIFICATION_RELATIONSHIPS.filter((relationship) => requested.includes(relationship)).map(
      (relationship) => [relationship, [verificationMethodId]]
    )
  );
}

/** Genesis document of an agent, with the did:webvh placeholder in place of the DID. */
export function buildAgentDocumentTemplate(params: {
  controllerDid: string;
  timestamp: string;
  agentMetadata: AgentDIDDocument['agentMetadata'];
  publicKeyBytes: Uint8Array;
  additionalVerificationRelationships?: readonly AdditionalVerificationRelationship[];
}): Record<string, unknown> {
  const verificationMethodId = `${DID_WEBVH_PLACEHOLDER}#key-1`;
  return {
    '@context': AGENT_DID_CONTEXT,
    id: DID_WEBVH_PLACEHOLDER,
    controller: params.controllerDid,
    created: params.timestamp,
    updated: params.timestamp,
    agentMetadata: params.agentMetadata,
    verificationMethod: [{
      id: verificationMethodId,
      type: 'Ed25519VerificationKey2020',
      controller: params.controllerDid,
      publicKeyMultibase: encodePublicKeyMultibase(params.publicKeyBytes)
    }],
    authentication: [verificationMethodId],
    assertionMethod: [verificationMethodId],
    ...additionalRelationshipEntries(params.additionalVerificationRelationships, verificationMethodId)
  };
}

/** Genesis document of a self-controlled local bootstrap controller. */
export function buildBootstrapControllerTemplate(params: {
  creatorKeyDid: string;
  timestamp: string;
  publicKeyBytes: Uint8Array;
}): Record<string, unknown> {
  const keyId = params.creatorKeyDid.replace(/^did:key:/u, '');
  const verificationMethodId = `${DID_WEBVH_PLACEHOLDER}#key-1`;
  return {
    '@context': AGENT_DID_CONTEXT,
    id: DID_WEBVH_PLACEHOLDER,
    controller: DID_WEBVH_PLACEHOLDER,
    created: params.timestamp,
    updated: params.timestamp,
    agentMetadata: {
      name: `controller-${normalizeDidPathSegment(keyId)}`,
      description: 'Local bootstrap controller root for canonical did:webvh flows.',
      version: '1.0.0',
      coreModelHash: generateAgentMetadataHash(`controller:${params.creatorKeyDid}`),
      systemPromptHash: generateAgentMetadataHash('controller-bootstrap-root')
    },
    verificationMethod: [{
      id: verificationMethodId,
      type: 'Ed25519VerificationKey2020',
      controller: DID_WEBVH_PLACEHOLDER,
      publicKeyMultibase: encodePublicKeyMultibase(params.publicKeyBytes)
    }],
    authentication: [verificationMethodId],
    assertionMethod: [verificationMethodId],
    // The bootstrap key endorses the agents it controls (RFC-001 §6.6 item 7)
    capabilityInvocation: [verificationMethodId]
  };
}

/** History entries for a verified did:webvh log, one per log entry. */
export function historyFromDidWebvhLog(log: string): AgentDocumentHistoryEntry[] {
  let previous: AgentDIDDocument | undefined;
  return log
    .split(/\r?\n/u)
    .filter((line) => line.trim().length > 0)
    .map((line, index) => {
      const entry = JSON.parse(line) as {
        versionTime: string;
        parameters?: { deactivated?: boolean };
        state: AgentDIDDocument;
      };
      const document = cloneDocument(entry.state);
      let action: AgentDocumentHistoryAction = 'updated';
      if (index === 0 || !previous) {
        action = 'created';
      } else if (entry.parameters?.deactivated === true) {
        action = 'revoked';
      } else if (document.verificationMethod.length !== previous.verificationMethod.length) {
        action = 'rotated-key';
      }
      previous = document;
      return {
        did: document.id,
        revision: index + 1,
        action,
        timestamp: entry.versionTime,
        version: document.agentMetadata?.version,
        documentRef: computeDocumentReference(document)
      };
    });
}
