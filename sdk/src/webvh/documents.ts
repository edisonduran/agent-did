/**
 * Pure helpers that build the documents and history derived from did:webvh logs.
 * No state and no I/O: `AgentDidClient` owns the stores and calls these.
 */
import { AgentDIDDocument, AgentDocumentHistoryAction, AgentDocumentHistoryEntry } from '../core/types';
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

/** Genesis document of an agent, with the did:webvh placeholder in place of the DID. */
export function buildAgentDocumentTemplate(params: {
  controllerDid: string;
  timestamp: string;
  agentMetadata: AgentDIDDocument['agentMetadata'];
  publicKeyBytes: Uint8Array;
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
    assertionMethod: [verificationMethodId]
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
    assertionMethod: [verificationMethodId]
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
