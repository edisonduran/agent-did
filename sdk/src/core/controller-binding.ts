/**
 * Controller binding of a did:webvh agent (RFC-001 §6.6 item 7).
 *
 * The controller's document is any DID Core document (RFC-001 §4.2.1); it does not need the Agent-DID members.
 * An agent whose document names a `controller` other than itself is bound to it only if the proof of the LAST entry of
 * its did:webvh log was made by a key that is active now under `capabilityInvocation` of the controller's document. The
 * last entry carries the full current document, so that proof is the controller's endorsement of the current state.
 * Listing a controller key in `updateKeys` is not enough (a public key can be listed without holding its private key,
 * and `updateKeys` can be handed over after the document was written).
 *
 * Python parity: `sdk-python/src/agent_did_sdk/core/controller_binding.py`.
 */
import { bytesToHex } from '@noble/hashes/utils';
import { decodePublicKeyMultibase } from '../crypto/multibase';
import { DidDocument } from './types';
import { activeEd25519PublicKey, relationshipMethods } from './verification-method';

/** The agent is not bound to its controller (see `assertBoundToController`). */
export class ControllerBindingError extends Error {
  public readonly did: string;
  public readonly controllerDid: string;

  constructor(did: string, controllerDid: string, detail: string) {
    super(`${did} is not bound to its controller ${controllerDid}: ${detail}`);
    this.name = 'ControllerBindingError';
    this.did = did;
    this.controllerDid = controllerDid;
  }
}

function rawKeyHex(multikey: string): string | undefined {
  try {
    return bytesToHex(decodePublicKeyMultibase(multikey));
  } catch {
    return undefined;
  }
}

/**
 * Raw public keys (hex) of the controller's keys that are active now under `capabilityInvocation`: references
 * (absolute or relative to the controller's `id`) and embedded methods, Ed25519 `publicKeyMultibase` keys only.
 */
export function activeCapabilityInvocationKeys(controller: DidDocument): Set<string> {
  const keys = new Set<string>();
  for (const method of relationshipMethods(controller, 'capabilityInvocation')) {
    const key = activeEd25519PublicKey(method);
    if (key !== undefined) {
      keys.add(bytesToHex(key));
    }
  }
  return keys;
}

/**
 * Throws `ControllerBindingError` unless one of `lastEntrySignerKeys` (multikeys of the proofs of the agent's last log
 * entry) is an active `capabilityInvocation` key of `controller`.
 */
export function assertBoundToController(
  agent: DidDocument,
  lastEntrySignerKeys: readonly string[],
  controller: DidDocument
): void {
  const active = activeCapabilityInvocationKeys(controller);
  if (active.size === 0) {
    throw new ControllerBindingError(agent.id, controller.id, 'the controller lists no active capabilityInvocation key');
  }
  const bound = lastEntrySignerKeys.some((multikey) => {
    const hex = rawKeyHex(multikey);
    return hex !== undefined && active.has(hex);
  });
  if (!bound) {
    throw new ControllerBindingError(
      agent.id,
      controller.id,
      'the last entry of its log was not signed by an active capabilityInvocation key of the controller'
    );
  }
}
