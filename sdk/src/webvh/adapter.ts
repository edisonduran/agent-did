/**
 * did:webvh v1.0 adapter (ADR-002).
 *
 * This module is the only place in the SDK that imports the DIF reference
 * implementation (`didwebvh-ts`). It exposes Agent-DID operations over
 * `did.jsonl` text and never leaks library types to callers, so the backing
 * implementation can be replaced without touching `AgentIdentity` or the
 * resolvers.
 *
 * Transport stays with the SDK's own document sources (and their SSRF
 * guards): this module only creates, appends to and verifies log text that
 * the caller already holds.
 *
 * Python parity: `agent_did_sdk.webvh.adapter`.
 */
import bs58 from 'bs58';
import { hexToBytes } from '@noble/hashes/utils';
import {
  createDID,
  deactivateDID,
  defaultVerifier,
  prepareDataForSigning,
  resolveDIDFromLog,
  updateDID,
} from 'didwebvh-ts';
import type { DIDDocument, DIDLog, DIDLogEntry, Signer, SigningInput, SigningOutput } from 'didwebvh-ts';
import type { AgentSigner } from '../core/signer';
import { encodePublicKeyMultibase } from '../crypto/multibase';

/** Placeholder that `createDidWebvhLog` replaces with the generated DID. */
export const DID_WEBVH_PLACEHOLDER = '{DID}';

/** Error codes surfaced by the adapter. Resolution codes follow DID Core. */
export type DidWebvhErrorCode = 'invalidDid' | 'notFound' | 'invalidOptions' | 'invalidInput' | 'unauthorized';

export class DidWebvhError extends Error {
  public readonly code: DidWebvhErrorCode;

  constructor(code: DidWebvhErrorCode, message: string) {
    super(message);
    this.name = 'DidWebvhError';
    this.code = code;
  }
}

export type DidWebvhDocument = Record<string, unknown> & { id: string };

/**
 * Resolution metadata exposed by Agent-DID for a did:webvh log. Witness and
 * watcher configuration are deliberately not exposed until the SDK supports
 * them (ADR-002, condition 7).
 */
export interface DidWebvhMetadata {
  versionId: string;
  versionNumber: number;
  versionTime: string;
  created: string;
  updated: string;
  scid: string;
  updateKeys: string[];
  deactivated: boolean;
  /** Cache TTL in seconds; the did:webvh default (3600) when the log does not set one. */
  ttl: string;
}

export interface DidWebvhLogResult {
  did: string;
  document: DidWebvhDocument;
  metadata: DidWebvhMetadata;
  /** The full `did.jsonl` text, one entry per line, newline-terminated. */
  log: string;
}

export interface CreateDidWebvhLogParams {
  /** Lowercase ASCII fully qualified host name, optionally with `:port`. IP literals are rejected. */
  domain: string;
  pathSegments?: string[];
  /** Initial DID document. Every occurrence of `{DID}` is replaced with the generated DID. */
  document: Record<string, unknown>;
  /** Controller signer; its key becomes the only entry in `updateKeys`. */
  signer: AgentSigner;
  /** Optional `versionTime` of the genesis entry (UTC, second precision). Defaults to now. */
  created?: string;
}

export interface UpdateDidWebvhLogParams {
  log: string;
  signer: AgentSigner;
  /** Complete next DID document. When omitted, the current document is carried over. */
  document?: Record<string, unknown>;
  /** Replacement `updateKeys` (Ed25519 multikeys), e.g. for controller key rotation. */
  updateKeys?: string[];
  /** Optional `versionTime` for the new entry (UTC, second precision). Defaults to now. */
  updated?: string;
}

export interface DeactivateDidWebvhLogParams {
  log: string;
  signer: AgentSigner;
}

export interface ResolveDidWebvhLogOptions {
  /** When set, the log must belong to this DID. */
  did?: string;
  versionId?: string;
  versionNumber?: number;
  versionTime?: string;
}

// Labels must start with a letter and have at least two characters: the
// intersection of what didwebvh-ts and did-webvh (Python) accept, so a DID
// created by either SDK resolves in both.
const HOST_LABEL = /^[a-z](?:[a-z0-9-]{0,61}[a-z0-9])$/u;
const PATH_SEGMENT = /^[A-Za-z0-9._~-]+$/u;
const PORT = /^[1-9][0-9]{0,4}$/u;
const VERSION_TIME = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/u;
const MAX_FUTURE_SKEW_MS = 5 * 60 * 1000;
const DEFAULT_TTL = '3600';

/** Returns the did:webvh `updateKeys` entry (an Ed25519 multikey) for a signer. */
export async function didWebvhUpdateKeyFor(signer: AgentSigner): Promise<string> {
  return encodePublicKeyMultibase(await signer.getPublicKey());
}

export async function createDidWebvhLog(params: CreateDidWebvhLogParams): Promise<DidWebvhLogResult> {
  validateDomain(params.domain);
  const pathSegments = params.pathSegments ?? [];
  pathSegments.forEach(validatePathSegment);
  if (params.created !== undefined) {
    validateVersionTime(params.created, 'created', 0);
  }

  const updateKey = await didWebvhUpdateKeyFor(params.signer);
  const result = await runLibraryOperation(() =>
    createDID({
      address: params.domain,
      paths: pathSegments.length > 0 ? pathSegments : undefined,
      didDocument: params.document as unknown as DIDDocument,
      updateKeys: [updateKey],
      signer: toLibrarySigner(params.signer, updateKey),
      created: params.created,
      verifier: defaultVerifier,
    })
  );

  return resolveDidWebvhLog(serializeLog(result.log));
}

export async function updateDidWebvhLog(params: UpdateDidWebvhLogParams): Promise<DidWebvhLogResult> {
  const log = parseLog(params.log);
  const current = await resolveDidWebvhLog(params.log);
  const signerKey = await assertAuthorizedSigner(params.signer, current.metadata);
  if (params.updateKeys !== undefined) {
    if (params.updateKeys.length === 0) {
      throw new DidWebvhError('invalidInput', 'updateKeys must not be empty; use deactivateDidWebvhLog instead');
    }
    params.updateKeys.forEach(validateUpdateKey);
  }
  if (params.updated !== undefined) {
    validateVersionTime(params.updated, 'updated', MAX_FUTURE_SKEW_MS);
  }

  const result = await runLibraryOperation(() =>
    updateDID({
      log,
      signer: toLibrarySigner(params.signer, signerKey),
      didDocument: params.document as unknown as DIDDocument | undefined,
      updateKeys: params.updateKeys,
      updated: params.updated,
      verifier: defaultVerifier,
    })
  );

  return resolveDidWebvhLog(serializeLog(result.log));
}

export async function deactivateDidWebvhLog(params: DeactivateDidWebvhLogParams): Promise<DidWebvhLogResult> {
  const log = parseLog(params.log);
  const current = await resolveDidWebvhLog(params.log);
  const signerKey = await assertAuthorizedSigner(params.signer, current.metadata);

  const result = await runLibraryOperation(() =>
    deactivateDID({ log, signer: toLibrarySigner(params.signer, signerKey), verifier: defaultVerifier })
  );

  return resolveDidWebvhLog(serializeLog(result.log));
}

/**
 * Verifies a `did.jsonl` log (SCID, entry hash chain, `updateKeys` proofs,
 * version times) and returns the resolved document. Throws `DidWebvhError` on
 * any verification failure; it never returns a partially verified result.
 */
export async function resolveDidWebvhLog(
  logText: string,
  options: ResolveDidWebvhLogOptions = {}
): Promise<DidWebvhLogResult> {
  const log = parseLog(logText);

  let versionTime: Date | undefined;
  if (options.versionTime !== undefined) {
    versionTime = new Date(options.versionTime);
    if (Number.isNaN(versionTime.getTime())) {
      throw new DidWebvhError('invalidOptions', `Invalid versionTime: ${options.versionTime}`);
    }
  }

  const result = await resolveDIDFromLog(log, {
    versionId: options.versionId,
    versionNumber: options.versionNumber,
    versionTime,
  });

  const resolutionError = result.didResolutionMetadata?.error;
  const meta = result.didDocumentMetadata as Record<string, unknown>;
  // A deactivated DID resolves with metadata only; the document is the state
  // of the (already verified) deactivation entry.
  const resolvedDocument =
    result.didDocument ??
    (meta?.deactivated === true ? log.find((entry) => entry.versionId === meta.versionId)?.state : undefined);
  if (resolutionError || !resolvedDocument) {
    const problem = (result.didResolutionMetadata as { problemDetails?: { detail?: string } }).problemDetails;
    throw new DidWebvhError(
      mapResolutionError(resolutionError),
      `did:webvh log verification failed: ${problem?.detail ?? resolutionError ?? 'no document resolved'}`
    );
  }

  const document = resolvedDocument as unknown as DidWebvhDocument;
  if (options.did !== undefined && document.id !== options.did) {
    throw new DidWebvhError('invalidDid', `did:webvh log belongs to ${document.id}, not ${options.did}`);
  }

  const versionId = requireString(meta.versionId, 'versionId');
  const metadata: DidWebvhMetadata = {
    versionId,
    versionNumber: Number.parseInt(versionId.split('-', 1)[0], 10),
    versionTime: requireString(meta.versionTime ?? meta.updated, 'versionTime'),
    created: requireString(meta.created, 'created'),
    updated: requireString(meta.updated, 'updated'),
    scid: requireString(meta.scid, 'scid'),
    updateKeys: Array.isArray(meta.updateKeys) ? [...(meta.updateKeys as string[])] : [],
    deactivated: meta.deactivated === true,
    ttl: meta.ttl !== undefined && meta.ttl !== null ? String(meta.ttl) : DEFAULT_TTL,
  };

  return { did: document.id, document, metadata, log: serializeLog(log) };
}

function toLibrarySigner(signer: AgentSigner, updateKey: string): Signer {
  return {
    getVerificationMethodId: () => `did:key:${updateKey}#${updateKey}`,
    async sign(input: SigningInput): Promise<SigningOutput> {
      const data = await prepareDataForSigning(input.document, input.proof);
      const signature = hexToBytes(await signer.sign(data));
      return { proofValue: `z${bs58.encode(signature)}` };
    },
  };
}

async function assertAuthorizedSigner(signer: AgentSigner, metadata: DidWebvhMetadata): Promise<string> {
  if (metadata.deactivated) {
    throw new DidWebvhError('invalidInput', 'did:webvh DID is deactivated');
  }
  const signerKey = await didWebvhUpdateKeyFor(signer);
  if (!metadata.updateKeys.includes(signerKey)) {
    throw new DidWebvhError('unauthorized', 'Signer key is not in the active did:webvh updateKeys');
  }
  return signerKey;
}

async function runLibraryOperation<T>(operation: () => Promise<T>): Promise<T> {
  try {
    return await operation();
  } catch (error) {
    if (error instanceof DidWebvhError) {
      throw error;
    }
    const message = error instanceof Error ? error.message : String(error);
    throw new DidWebvhError('invalidInput', `did:webvh operation failed: ${message}`);
  }
}

function parseLog(logText: string): DIDLog {
  if (typeof logText !== 'string') {
    throw new DidWebvhError('invalidInput', 'did:webvh log must be a string');
  }
  const lines = logText.split(/\r?\n/u).filter((line) => line.trim().length > 0);
  if (lines.length === 0) {
    throw new DidWebvhError('notFound', 'did:webvh log is empty');
  }
  return lines.map((line, index) => {
    let entry: unknown;
    try {
      entry = JSON.parse(line);
    } catch {
      throw new DidWebvhError('invalidDid', `did:webvh log line ${index + 1} is not valid JSON`);
    }
    if (entry === null || typeof entry !== 'object' || Array.isArray(entry)) {
      throw new DidWebvhError('invalidDid', `did:webvh log line ${index + 1} is not a JSON object`);
    }
    return entry as DIDLogEntry;
  });
}

function serializeLog(log: DIDLog): string {
  return log.map((entry) => JSON.stringify(entry)).join('\n') + '\n';
}

function mapResolutionError(code: string | undefined): DidWebvhErrorCode {
  if (code === 'notFound' || code === 'invalidOptions') {
    return code;
  }
  return 'invalidDid';
}

function requireString(value: unknown, field: string): string {
  if (typeof value !== 'string' || value.length === 0) {
    throw new DidWebvhError('invalidDid', `did:webvh resolution metadata is missing ${field}`);
  }
  return value;
}

function validateDomain(domain: string): void {
  if (typeof domain !== 'string' || domain.length === 0) {
    throw new DidWebvhError('invalidInput', 'did:webvh domain is required');
  }
  const separator = domain.lastIndexOf(':');
  const host = separator === -1 ? domain : domain.slice(0, separator);
  const port = separator === -1 ? undefined : domain.slice(separator + 1);
  const labels = host.split('.');
  if (
    host.length > 253 ||
    labels.length < 2 ||
    !labels.every((label) => HOST_LABEL.test(label))
  ) {
    throw new DidWebvhError('invalidInput', `Invalid did:webvh domain: ${domain}`);
  }
  if (port !== undefined && (!PORT.test(port) || Number(port) > 65535)) {
    throw new DidWebvhError('invalidInput', `Invalid did:webvh port: ${domain}`);
  }
}

function validatePathSegment(segment: string): void {
  if (typeof segment !== 'string' || !PATH_SEGMENT.test(segment) || segment === '.' || segment === '..') {
    throw new DidWebvhError('invalidInput', `Invalid did:webvh path segment: ${String(segment)}`);
  }
}

function validateUpdateKey(key: string): void {
  let decoded: Uint8Array | undefined;
  if (typeof key === 'string' && key.startsWith('z')) {
    try {
      decoded = bs58.decode(key.slice(1));
    } catch {
      decoded = undefined;
    }
  }
  if (!decoded || decoded.length !== 34 || decoded[0] !== 0xed || decoded[1] !== 0x01) {
    throw new DidWebvhError('invalidInput', `updateKeys entries must be Ed25519 multikeys: ${String(key)}`);
  }
}

function validateVersionTime(value: string, name: string, maxFutureSkewMs: number): void {
  const parsed = typeof value === 'string' && VERSION_TIME.test(value) ? new Date(value) : undefined;
  if (!parsed || Number.isNaN(parsed.getTime()) || parsed.toISOString().replace('.000Z', 'Z') !== value) {
    throw new DidWebvhError('invalidInput', `${name} must be a UTC timestamp like 2026-01-01T00:00:00Z`);
  }
  if (parsed.getTime() > Date.now() + maxFutureSkewMs) {
    throw new DidWebvhError('invalidInput', `${name} must not be in the future`);
  }
}
