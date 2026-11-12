/**
 * Pure builders for the lifecycle operations (update, rotate). They compute the next
 * document from the current one; authorization, did:webvh log entries, registry and
 * history are handled by `AgentDidClient`.
 */
import { ed25519 } from '@noble/curves/ed25519';
import { bytesToHex } from '@noble/hashes/utils';
import { ADDITIONAL_VERIFICATION_RELATIONSHIPS } from '../core/identity-composition';
import {
  AddedKeyRelationship,
  AgentDIDDocument,
  UpdateAgentDocumentParams,
  VerificationMethod
} from '../core/types';
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

/**
 * Removes the keys of `document` that carry a `deactivated` time from every verification relationship
 * (they stay in `verificationMethod` as the record of the retired key). Idempotent; an optional
 * relationship (everything but `authentication`) that ends up empty is omitted. A key id that is not a verification method of the document
 * is left alone.
 */
function withoutRetiredKeysInRelationships(document: AgentDIDDocument): AgentDIDDocument {
  const retired = new Set(document.verificationMethod.filter((method) => method.deactivated).map((method) => method.id));
  if (retired.size === 0) {
    return document;
  }
  const result: AgentDIDDocument = { ...document };
  result.authentication = document.authentication.filter((keyId) => !retired.has(keyId));
  for (const relationship of ['assertionMethod', ...ADDITIONAL_VERIFICATION_RELATIONSHIPS] as const) {
    const keyIds = document[relationship];
    if (!keyIds) {
      continue;
    }
    const kept = keyIds.filter((keyId) => !retired.has(keyId));
    if (kept.length > 0) {
      result[relationship] = kept;
    } else {
      delete result[relationship];
    }
  }
  return result;
}

export function buildUpdatedDocument(
  existing: AgentDIDDocument,
  patch: UpdateAgentDocumentParams,
  updated: string
): AgentDIDDocument {
  // Any update also normalizes a document written by an earlier release that still listed retired keys
  return withoutRetiredKeysInRelationships({
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
  });
}

type CapabilityRelationshipLists = Partial<Pick<AgentDIDDocument, 'capabilityDelegation' | 'capabilityInvocation'>>;

/**
 * `capabilityDelegation` / `capabilityInvocation` lists for a rotated document: the new key joins each one
 * that lists a key this rotation deactivates, so an agent that could delegate or invoke still can. The keys
 * of this document are removed from every list (a rotated-out key is no longer a verification relationship
 * of any kind); another party's key stays, and a list left empty is omitted.
 */
function carriedCapabilityRelationships(
  existing: AgentDIDDocument,
  newVerificationMethodId: string
): CapabilityRelationshipLists {
  const activeKeyIds = new Set(
    existing.verificationMethod.filter((method) => !method.deactivated).map((method) => method.id)
  );
  const ownKeyIds = new Set(existing.verificationMethod.map((method) => method.id));
  const carried: CapabilityRelationshipLists = {};
  for (const relationship of ADDITIONAL_VERIFICATION_RELATIONSHIPS) {
    const keyIds = existing[relationship];
    if (!keyIds) {
      continue;
    }
    const kept = keyIds.filter((keyId) => !ownKeyIds.has(keyId));
    const next = keyIds.some((keyId) => activeKeyIds.has(keyId)) ? [...kept, newVerificationMethodId] : kept;
    if (next.length > 0) {
      carried[relationship] = Array.from(new Set(next));
    }
  }
  return carried;
}

/**
 * Adds an Ed25519 key to the document without retiring any other key, listed under `relationships`: `newPublicKey`
 * when the caller holds the key elsewhere (`agentPrivateKey` is then empty), otherwise a freshly generated local key.
 */
export function buildAddedKeyDocument(
  did: string,
  existing: AgentDIDDocument,
  updated: string,
  relationships: readonly AddedKeyRelationship[],
  newPublicKey?: Uint8Array
): { document: AgentDIDDocument; verificationMethodId: string; agentPrivateKey: string } {
  if (relationships.length === 0) {
    throw new Error('At least one relationship is required for the new key');
  }
  const keyIndexes = existing.verificationMethod.map((method) => {
    const match = method.id.match(/#key-(\d+)$/);
    return match ? Number(match[1]) : 0;
  });
  const verificationMethodId = `${did}#key-${(keyIndexes.length ? Math.max(...keyIndexes) : 0) + 1}`;
  if (newPublicKey !== undefined && newPublicKey.length !== 32) {
    throw new Error('The new verification method key must be a 32-byte Ed25519 public key');
  }
  const privateKeyBytes = newPublicKey ? undefined : ed25519.utils.randomPrivateKey();
  const document: AgentDIDDocument = {
    ...existing,
    updated,
    verificationMethod: [
      ...existing.verificationMethod,
      {
        id: verificationMethodId,
        type: 'Ed25519VerificationKey2020',
        controller: existing.controller,
        publicKeyMultibase: encodePublicKeyMultibase(newPublicKey ?? ed25519.getPublicKey(privateKeyBytes as Uint8Array))
      }
    ]
  };
  for (const relationship of new Set(relationships)) {
    document[relationship] = [...(document[relationship] ?? []), verificationMethodId];
  }
  return { document, verificationMethodId, agentPrivateKey: privateKeyBytes ? bytesToHex(privateKeyBytes) : '' };
}

/**
 * Deactivates every current key and adds an Ed25519 key as the active one: `newPublicKey` when the caller holds
 * the key elsewhere (`agentPrivateKey` is then empty), otherwise a freshly generated local key.
 */
export function buildRotatedDocument(
  did: string,
  existing: AgentDIDDocument,
  updated: string,
  newPublicKey?: Uint8Array
): { document: AgentDIDDocument; verificationMethodId: string; agentPrivateKey: string } {
  const keyIndexes = existing.verificationMethod.map((method) => {
    const match = method.id.match(/#key-(\d+)$/);
    return match ? Number(match[1]) : 0;
  });
  const nextIndex = (keyIndexes.length ? Math.max(...keyIndexes) : 0) + 1;
  const verificationMethodId = `${did}#key-${nextIndex}`;

  if (newPublicKey !== undefined && newPublicKey.length !== 32) {
    throw new Error('The new verification method key must be a 32-byte Ed25519 public key');
  }
  const privateKeyBytes = newPublicKey ? undefined : ed25519.utils.randomPrivateKey();
  const newVerificationMethod: VerificationMethod = {
    id: verificationMethodId,
    type: 'Ed25519VerificationKey2020',
    controller: existing.controller,
    publicKeyMultibase: encodePublicKeyMultibase(newPublicKey ?? ed25519.getPublicKey(privateKeyBytes as Uint8Array))
  };
  const deactivatedMethods = existing.verificationMethod.map((method) => ({
    ...method,
    deactivated: method.deactivated || updated
  }));

  // Every key of the previous document is retired: none of them stays in a verification relationship
  const { capabilityDelegation: _delegation, capabilityInvocation: _invocation, ...withoutCapabilities } = existing;
  return {
    document: {
      ...withoutCapabilities,
      updated,
      verificationMethod: [...deactivatedMethods, newVerificationMethod],
      authentication: [verificationMethodId],
      assertionMethod: [verificationMethodId],
      ...carriedCapabilityRelationships(existing, verificationMethodId)
    },
    verificationMethodId,
    agentPrivateKey: privateKeyBytes ? bytesToHex(privateKeyBytes) : ''
  };
}
