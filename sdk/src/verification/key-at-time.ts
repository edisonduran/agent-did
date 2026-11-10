/**
 * Key checks at a stated time against a verified did:webvh log (RFC-001 §6.2.2).
 *
 * The time a signed artifact states is asserted by the signer. It locates the DID state the signer claims, but
 * it cannot prove the signature was made before a later change: whoever holds a retired key can state any
 * earlier time. So a key that was authorized at the stated time and retired later is `indeterminate` unless
 * trusted time evidence places the signature before the retirement.
 *
 * Python parity: `sdk-python/src/agent_did_sdk/verification/key_at_time.py`.
 */
import { ed25519 } from '@noble/curves/ed25519';
import { hexToBytes } from '@noble/hashes/utils';
import {
  DID_VERIFICATION_RELATIONSHIPS,
  REQUIRED_RELATIONSHIP_BY_ARTIFACT
} from '../core/identity-composition';
import {
  CheckKeyAtTimeOptions,
  KeyAtTimeRejection,
  KeyAtTimeResult,
  VerificationRelationship,
  VerifySignatureAtTimeResult
} from '../core/types';
import { decodePublicKeyMultibase } from '../crypto/multibase';
import { resolveDidWebvhLog } from '../webvh/adapter';

const RFC3339 = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,9}))?(Z|[+-]\d{2}:\d{2})$/iu;

/**
 * Parses an RFC 3339 date-time into milliseconds since the epoch, truncating sub-millisecond digits.
 * Returns `undefined` for anything else (no other formats, no out-of-range fields).
 */
export function parseRfc3339Millis(value: unknown): number | undefined {
  if (typeof value !== 'string') {
    return undefined;
  }
  const match = RFC3339.exec(value);
  if (!match) {
    return undefined;
  }
  const [, year, month, day, hour, minute, second, fraction, offset] = match;
  const fields = [year, month, day, hour, minute, second].map(Number);
  const [y, mo, d, h, mi, s] = fields;
  if (y < 1 || mo < 1 || mo > 12 || d < 1 || h > 23 || mi > 59 || s > 59) {
    return undefined;
  }
  const daysInMonth = new Date(Date.UTC(y, mo, 0)).getUTCDate();
  if (d > daysInMonth) {
    return undefined;
  }
  const millis = fraction ? Number(fraction.padEnd(3, '0').slice(0, 3)) : 0;
  let offsetMinutes = 0;
  if (offset.toUpperCase() !== 'Z') {
    const sign = offset.startsWith('-') ? -1 : 1;
    const offsetHours = Number(offset.slice(1, 3));
    const offsetMins = Number(offset.slice(4, 6));
    if (offsetHours > 23 || offsetMins > 59) {
      return undefined;
    }
    offsetMinutes = sign * (offsetHours * 60 + offsetMins);
  }
  const utc = new Date(0);
  utc.setUTCFullYear(y, mo - 1, d);
  utc.setUTCHours(h, mi, s, millis);
  return utc.getTime() - offsetMinutes * 60_000;
}

interface LogEntry {
  versionId: string;
  versionTime: string;
  versionMillis: number;
  deactivated: boolean;
  state: Record<string, unknown>;
}

type KeyInState =
  | { ok: true; publicKeyMultibase: string; deactivatedMillis?: number; deactivated?: string }
  | { ok: false; reason: KeyAtTimeRejection; foundIn: VerificationRelationship[] };

function stringList(value: unknown): string[] {
  return Array.isArray(value) ? value.filter((item): item is string => typeof item === 'string') : [];
}

function relationshipsOf(state: Record<string, unknown>, keyId: string): VerificationRelationship[] {
  return DID_VERIFICATION_RELATIONSHIPS.filter((relationship) => stringList(state[relationship]).includes(keyId));
}

/** Whether `keyId` is an authorized `requiredPurpose` key in `state` at `atMillis`. */
function keyInState(
  state: Record<string, unknown>,
  keyId: string,
  requiredPurpose: VerificationRelationship,
  atMillis: number
): KeyInState {
  const foundIn = relationshipsOf(state, keyId);
  const methods = Array.isArray(state.verificationMethod) ? (state.verificationMethod as unknown[]) : [];
  const method = methods.find(
    (candidate): candidate is Record<string, unknown> =>
      typeof candidate === 'object' && candidate !== null && (candidate as Record<string, unknown>).id === keyId
  );
  if (!method || typeof method.publicKeyMultibase !== 'string' || method.publicKeyMultibase.length === 0) {
    return { ok: false, reason: 'key_not_found', foundIn };
  }
  let deactivatedMillis: number | undefined;
  if (method.deactivated !== undefined && method.deactivated !== null) {
    deactivatedMillis = parseRfc3339Millis(method.deactivated);
    // An unreadable deactivation time is treated as already deactivated (fail closed).
    if (deactivatedMillis === undefined || deactivatedMillis <= atMillis) {
      return { ok: false, reason: 'key_deactivated', foundIn };
    }
  }
  if (requiredPurpose === 'keyAgreement' || !foundIn.includes(requiredPurpose)) {
    return { ok: false, reason: 'key_purpose_violation', foundIn };
  }
  return {
    ok: true,
    publicKeyMultibase: method.publicKeyMultibase,
    ...(deactivatedMillis !== undefined ? { deactivatedMillis, deactivated: String(method.deactivated) } : {})
  };
}

/**
 * Checks whether `keyId` was authorized for `requiredPurpose` at `statedTime`, according to a did:webvh log.
 *
 * The whole log is verified first (`resolveDidWebvhLog`); a log that fails verification throws `DidWebvhError`.
 * Then the entry in effect at the stated time (the last one whose `versionTime` is not after it) decides
 * `authorized` / `not_authorized`, and any later entry that retires the key or deactivates the DID turns
 * `authorized` into `indeterminate`, unless `trustedTimeNotAfter` is earlier than that entry.
 */
export async function checkDidWebvhKeyAtTime(log: string, options: CheckKeyAtTimeOptions): Promise<KeyAtTimeResult> {
  const { keyId } = options;
  const requiredPurpose = options.requiredPurpose ?? REQUIRED_RELATIONSHIP_BY_ARTIFACT.assertion;
  let evidenceMillis: number | undefined;
  if (options.trustedTimeNotAfter !== undefined) {
    evidenceMillis = parseRfc3339Millis(options.trustedTimeNotAfter);
    if (evidenceMillis === undefined) {
      throw new TypeError(`trustedTimeNotAfter is not an RFC 3339 date-time: ${String(options.trustedTimeNotAfter)}`);
    }
  }

  const resolved = await resolveDidWebvhLog(log, options.did !== undefined ? { did: options.did } : {});

  const statedMillis = parseRfc3339Millis(options.statedTime);
  if (statedMillis === undefined) {
    return { status: 'not_authorized', keyId, reason: 'invalid_stated_time', foundIn: [] };
  }

  const entries: LogEntry[] = resolved.log
    .split('\n')
    .filter((line) => line.trim().length > 0)
    .map((line) => {
      const entry = JSON.parse(line) as {
        versionId: string;
        versionTime: string;
        parameters?: { deactivated?: boolean };
        state: Record<string, unknown>;
      };
      const versionMillis = parseRfc3339Millis(entry.versionTime);
      if (versionMillis === undefined) {
        // resolveDidWebvhLog already rejects such logs; this keeps the type honest.
        throw new TypeError(`did:webvh entry ${entry.versionId} has an unreadable versionTime`);
      }
      return {
        versionId: entry.versionId,
        versionTime: entry.versionTime,
        versionMillis,
        deactivated: entry.parameters?.deactivated === true,
        state: entry.state
      };
    });

  let index = -1;
  entries.forEach((entry, position) => {
    if (entry.versionMillis <= statedMillis) {
      index = position;
    }
  });
  if (index < 0) {
    return { status: 'not_authorized', keyId, reason: 'did_not_yet_created', foundIn: [] };
  }
  const current = entries[index];
  if (current.deactivated) {
    return { status: 'not_authorized', keyId, reason: 'did_deactivated', foundIn: relationshipsOf(current.state, keyId) };
  }
  const atStatedTime = keyInState(current.state, keyId, requiredPurpose, statedMillis);
  if (!atStatedTime.ok) {
    return { status: 'not_authorized', keyId, reason: atStatedTime.reason, foundIn: atStatedTime.foundIn };
  }

  // The first change after the stated time that ends the key's authorization, if any.
  let boundary: { millis: number; time: string; versionId?: string; didDeactivated: boolean } | undefined;
  if (atStatedTime.deactivatedMillis !== undefined) {
    boundary = { millis: atStatedTime.deactivatedMillis, time: atStatedTime.deactivated as string, didDeactivated: false };
  }
  for (const entry of entries.slice(index + 1)) {
    if (boundary && entry.versionMillis >= boundary.millis) {
      break;
    }
    if (entry.deactivated) {
      boundary = { millis: entry.versionMillis, time: entry.versionTime, versionId: entry.versionId, didDeactivated: true };
      break;
    }
    const later = keyInState(entry.state, keyId, requiredPurpose, entry.versionMillis);
    // An entry that gives the key a `deactivated` time retires it, even when that time is after the entry's
    // versionTime (the SDK's rotation writes the document clock, with milliseconds, next to a versionTime in
    // seconds). The entry is the change, so it is the boundary.
    const newlyDeactivated = later.ok && later.deactivatedMillis !== undefined && later.deactivatedMillis !== atStatedTime.deactivatedMillis;
    if (!later.ok || newlyDeactivated) {
      boundary = { millis: entry.versionMillis, time: entry.versionTime, versionId: entry.versionId, didDeactivated: false };
      break;
    }
  }

  if (!boundary) {
    return {
      status: 'authorized',
      keyId,
      publicKeyMultibase: atStatedTime.publicKeyMultibase,
      versionId: current.versionId,
      basis: 'no_later_change'
    };
  }
  if (evidenceMillis !== undefined && evidenceMillis < boundary.millis) {
    return {
      status: 'authorized',
      keyId,
      publicKeyMultibase: atStatedTime.publicKeyMultibase,
      versionId: current.versionId,
      basis: 'time_evidence'
    };
  }
  return {
    status: 'indeterminate',
    keyId,
    reason: boundary.didDeactivated ? 'did_deactivated_after_stated_time' : 'key_retired_after_stated_time',
    publicKeyMultibase: atStatedTime.publicKeyMultibase,
    ...(boundary.versionId !== undefined ? { boundaryVersionId: boundary.versionId } : {}),
    boundaryTime: boundary.time
  };
}

/** Combines a key check at a stated time with the Ed25519 check of `signature` (hex) over `payload` (UTF-8). */
export function signatureResultForKey(key: KeyAtTimeResult, payload: string, signature: string): VerifySignatureAtTimeResult {
  if (key.status === 'not_authorized') {
    return { status: 'invalid', reason: 'key_not_authorized', key };
  }
  if (key.publicKeyMultibase === undefined) {
    // Only `history_unavailable` has no key to check the signature with.
    return { status: 'indeterminate', key: key as Extract<KeyAtTimeResult, { status: 'indeterminate' }> };
  }
  let verified = false;
  try {
    verified = ed25519.verify(
      hexToBytes(signature),
      new TextEncoder().encode(payload),
      decodePublicKeyMultibase(key.publicKeyMultibase)
    );
  } catch {
    verified = false;
  }
  if (!verified) {
    return { status: 'invalid', reason: 'signature_invalid', key };
  }
  return key.status === 'authorized' ? { status: 'valid', key } : { status: 'indeterminate', key };
}
