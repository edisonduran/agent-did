/**
 * Pure builders for the lifecycle operations (update, rotate). They compute the next
 * document from the current one; authorization, did:webvh log entries, registry and
 * history are handled by `AgentDidClient`.
 */
import { ed25519 } from '@noble/curves/ed25519';
import { bytesToHex } from '@noble/hashes/utils';
import { ADDITIONAL_VERIFICATION_RELATIONSHIPS } from '../core/identity-composition';
import { AgentDIDDocument, UpdateAgentDocumentParams, VerificationMethod } from '../core/types';
import { createMetadataCommitment } from '../crypto/hash';
import { encodePublicKeyMultibase } from '../crypto/multibase';
import { normalizeTimestampToIso } from '../core/time';

/** Timestamp strictly after `previousTimestamp`, using `now` unless it is not later. */
export function nextDocumentTimestamp(now: Date, previousTimestamp?: string): string {
  const previous = previousTimestamp ? Date.parse(previousTimestamp) : Number.NaN;
  if (!Number.isNaN(previous) && now.getTime() <= previous) {
    return normalizeTimestampToIso(new Date(previous + 1).toISOString()) as string;
  }
  return normalizeTimestampToIso(now.toISOString()) as string;
}

export function assertUpdatePatch(did: string, patch: UpdateAgentDocumentParams): void {
  if (!did?.trim()) {
    throw new Error('DID is required');
  }
  if (patch.coreModel && !patch.coreModelSalt) {
    throw new Error('coreModelSalt is required when updating coreModel (use generateCommitmentSalt() and keep it private)');
  }
  if (patch.systemPrompt && !patch.systemPromptSalt) {
    throw new Error('systemPromptSalt is required when updating systemPrompt (use generateCommitmentSalt() and keep it private)');
  }
}

export function buildUpdatedDocument(
  existing: AgentDIDDocument,
  patch: UpdateAgentDocumentParams,
  updated: string
): AgentDIDDocument {
  return {
    ...existing,
    updated,
    agentMetadata: {
      ...existing.agentMetadata,
      description: patch.description ?? existing.agentMetadata.description,
      version: patch.version ?? existing.agentMetadata.version,
      coreModelHash: patch.coreModel
        ? createMetadataCommitment(patch.coreModel, patch.coreModelSalt as string)
        : existing.agentMetadata.coreModelHash,
      systemPromptHash: patch.systemPrompt
        ? createMetadataCommitment(patch.systemPrompt, patch.systemPromptSalt as string)
        : existing.agentMetadata.systemPromptHash,
      capabilities: patch.capabilities ?? existing.agentMetadata.capabilities,
      memberOf: patch.memberOf ?? existing.agentMetadata.memberOf
    },
    complianceCertifications: patch.complianceCertifications ?? existing.complianceCertifications
  };
}

type CapabilityRelationshipLists = Partial<Pick<AgentDIDDocument, 'capabilityDelegation' | 'capabilityInvocation'>>;

/**
 * `capabilityDelegation` / `capabilityInvocation` lists for a rotated document: the new key joins each one
 * that lists a key this rotation deactivates, so an agent that could delegate or invoke still can. A list
 * that names no active key (for example only another party's key) is left as it is.
 */
function carriedCapabilityRelationships(
  existing: AgentDIDDocument,
  newVerificationMethodId: string
): CapabilityRelationshipLists {
  const activeKeyIds = new Set(
    existing.verificationMethod.filter((method) => !method.deactivated).map((method) => method.id)
  );
  const carried: CapabilityRelationshipLists = {};
  for (const relationship of ADDITIONAL_VERIFICATION_RELATIONSHIPS) {
    const keyIds = existing[relationship];
    if (keyIds?.some((keyId) => activeKeyIds.has(keyId))) {
      carried[relationship] = Array.from(new Set([...keyIds, newVerificationMethodId]));
    }
  }
  return carried;
}

/** Deactivates every current key and adds a fresh Ed25519 key as the active one. */
export function buildRotatedDocument(
  did: string,
  existing: AgentDIDDocument,
  updated: string
): { document: AgentDIDDocument; verificationMethodId: string; agentPrivateKey: string } {
  const keyIndexes = existing.verificationMethod.map((method) => {
    const match = method.id.match(/#key-(\d+)$/);
    return match ? Number(match[1]) : 0;
  });
  const nextIndex = (keyIndexes.length ? Math.max(...keyIndexes) : 0) + 1;
  const verificationMethodId = `${did}#key-${nextIndex}`;

  const privateKeyBytes = ed25519.utils.randomPrivateKey();
  const newVerificationMethod: VerificationMethod = {
    id: verificationMethodId,
    type: 'Ed25519VerificationKey2020',
    controller: existing.controller,
    publicKeyMultibase: encodePublicKeyMultibase(ed25519.getPublicKey(privateKeyBytes))
  };
  const deactivatedMethods = existing.verificationMethod.map((method) => ({
    ...method,
    deactivated: method.deactivated || updated
  }));

  return {
    document: {
      ...existing,
      updated,
      verificationMethod: [...deactivatedMethods, newVerificationMethod],
      authentication: [verificationMethodId],
      assertionMethod: Array.from(new Set([...(existing.assertionMethod || []), verificationMethodId])),
      ...carriedCapabilityRelationships(existing, verificationMethodId)
    },
    verificationMethodId,
    agentPrivateKey: bytesToHex(privateKeyBytes)
  };
}
