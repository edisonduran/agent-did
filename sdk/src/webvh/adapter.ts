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
  deriveNextKeyHash,
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
 * them (ADR-002, condition 7). Every value is a string, list or boolean, as
 * DID Core §7.3 requires of DID document metadata.
 */
export interface DidWebvhMetadata {
  versionId: string;
  versionTime: string;
  created: string;
  updated: string;
  scid: string;
  updateKeys: string[];
  /**
   * Pre-rotation commitments (`nextKeyHashes`) in force after this version: while non-empty, the next
   * entry must be signed by a key whose hash is listed here, and the current `updateKeys` can no longer
   * sign. Empty when pre-rotation is not active.
   */
  nextKeyHashes: string[];
  deactivated: boolean;
  /** Cache TTL in seconds; the did:webvh default (3600) when the log does not set one. */
  ttl: string;
}

export interface DidWebvhLogResult {
  did: string;
  /** Resolved DID document, including the implicit `#files` / `#whois` services. */
  document: DidWebvhDocument;
  /** The resolved version's `state` exactly as signed in the log (no implicit services). */
  state: DidWebvhDocument;
  metadata: DidWebvhMetadata;
  /** Number of the resolved version: the integer prefix of `metadata.versionId`. */
  versionNumber: number;
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
  /**
   * Public keys (Ed25519 multikeys) the next entry will be signed with. Only their hashes are written to the
   * log (`nextKeyHashes`, pre-rotation): keep the private keys offline, away from the signer in `signer`.
   * Must not include the current update key.
   */
  nextUpdateKeys?: string[];
  /** Optional `versionTime` of the genesis entry (UTC, second precision). Defaults to now. */
  created?: string;
}

export interface UpdateDidWebvhLogParams {
  log: string;
  signer: AgentSigner;
  /** Complete next DID document. When omitted, the current document is carried over. */
  document?: Record<string, unknown>;
  /**
   * Replacement `updateKeys` (Ed25519 multikeys), e.g. for controller key rotation. While pre-rotation is
   * active they must all be committed in `nextKeyHashes`, and they default to the signer's key.
   */
  updateKeys?: string[];
  /**
   * Public keys (Ed25519 multikeys) for the pre-rotation commitment of the NEXT entry. Omitted: the
   * commitments in force stay as they are. An empty array ends pre-rotation. Must not include any of the
   * `updateKeys` this entry sets.
   */
  nextUpdateKeys?: string[];
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

/**
 * Passed as `fetch` to every library call. The adapter never does network
 * I/O: logs are fetched by the SDK's document sources (with their SSRF
 * guards), and witness proofs are not supported yet (ADR-002, condition 7).
 * Without this, the library would fetch `did-witness.json` with the global
 * `fetch` for logs that declare witnesses.
 */
const noNetworkFetch = async (): Promise<Response> => {
  throw new DidWebvhError('invalidDid', 'did:webvh witnesses are not supported by Agent-DID yet');
};

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
  const nextKeyHashes = await nextKeyHashesFor(params.nextUpdateKeys, [updateKey]);
  const result = await runLibraryOperation(() =>
    createDID({
      address: params.domain,
      paths: pathSegments.length > 0 ? pathSegments : undefined,
      didDocument: params.document as unknown as DIDDocument,
      updateKeys: [updateKey],
      ...(nextKeyHashes !== undefined ? { nextKeyHashes } : {}),
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
  if (params.updateKeys !== undefined) {
    if (params.updateKeys.length === 0) {
      throw new DidWebvhError('invalidInput', 'updateKeys must not be empty; use deactivateDidWebvhLog instead');
    }
    params.updateKeys.forEach(validateUpdateKey);
  }
  const { signerKey, updateKeys } = await authorizeSigner(params.signer, current.metadata, params.updateKeys);
  const nextKeyHashes = await nextKeyHashesFor(params.nextUpdateKeys, updateKeys ?? current.metadata.updateKeys);
  if (params.updated !== undefined) {
    validateVersionTime(params.updated, 'updated', MAX_FUTURE_SKEW_MS);
  }

  const result = await runLibraryOperation(() =>
    updateDID({
      log,
      signer: toLibrarySigner(params.signer, signerKey),
      didDocument: params.document as unknown as DIDDocument | undefined,
      updateKeys,
      ...(nextKeyHashes !== undefined ? { nextKeyHashes } : {}),
      updated: params.updated,
      verifier: defaultVerifier,
      fetch: noNetworkFetch,
    })
  );

  return resolveDidWebvhLog(serializeLog(result.log));
}

export async function deactivateDidWebvhLog(params: DeactivateDidWebvhLogParams): Promise<DidWebvhLogResult> {
  let current = await resolveDidWebvhLog(params.log);
  // did:webvh v1.0 deactivates a pre-rotated DID in two entries: an entry under pre-rotation must carry the
  // committed keys, so it cannot also empty `updateKeys`. A committed key first ends pre-rotation.
  if (current.metadata.nextKeyHashes.length > 0) {
    current = await updateDidWebvhLog({ log: params.log, signer: params.signer, nextUpdateKeys: [] });
  }
  const { signerKey } = await authorizeSigner(params.signer, current.metadata, undefined);

  // The deactivation entry sets `updateKeys` to [] (the library default): no key can authorize a later entry.
  const result = await runLibraryOperation(() =>
    deactivateDID({
      log: parseLog(current.log),
      signer: toLibrarySigner(params.signer, signerKey),
      verifier: defaultVerifier,
      fetch: noNetworkFetch,
    })
  );

  return resolveDidWebvhLog(serializeLog(result.log));
}

/**
 * Verifies a `did.jsonl` log (SCID, entry hash chain, `updateKeys` proofs,
 * version times) and returns the resolved document. Throws `DidWebvhError` on
 * any verification failure; it never returns a partially verified result.
 *
 * With `versionId`, `versionNumber` or `versionTime` it returns that version of the log. The whole log is
 * still verified, and `metadata.deactivated` describes the DID, not the selected version: it is true for
 * every version of a deactivated DID (DID Core section 7.1.2).
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

  let result: Awaited<ReturnType<typeof resolveDIDFromLog>>;
  try {
    result = await resolveDIDFromLog(log, {
      versionId: options.versionId,
      versionNumber: options.versionNumber,
      versionTime,
      fetch: noNetworkFetch,
    });
  } catch (error) {
    // Fail closed: any unexpected library failure rejects the log.
    const message = error instanceof Error ? error.message : String(error);
    throw new DidWebvhError('invalidDid', `did:webvh log verification failed: ${message}`);
  }

  const resolutionError = result.didResolutionMetadata?.error;
  const meta = result.didDocumentMetadata as Record<string, unknown>;
  // The entry that deactivates the DID resolves to its raw (already verified) state. The library returns no
  // document for it without a version selector, and one with the implicit services when it is selected.
  const resolvedEntry = log.find((entry) => entry.versionId === meta?.versionId);
  const resolvedDocument = resolvedEntry?.parameters?.deactivated === true ? resolvedEntry.state : result.didDocument;
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
  const selectedEntry = log.find((entry) => entry.versionId === versionId);
  if (!selectedEntry) {
    throw new DidWebvhError('invalidDid', `did:webvh log has no entry for resolved version ${versionId}`);
  }
  const metadata: DidWebvhMetadata = {
    versionId,
    versionTime: requireString(meta.versionTime ?? meta.updated, 'versionTime'),
    created: requireString(meta.created, 'created'),
    updated: requireString(meta.updated, 'updated'),
    scid: requireString(meta.scid, 'scid'),
    updateKeys: Array.isArray(meta.updateKeys) ? [...(meta.updateKeys as string[])] : [],
    nextKeyHashes: Array.isArray(meta.nextKeyHashes) ? [...(meta.nextKeyHashes as string[])] : [],
    deactivated: meta.deactivated === true,
    ttl: meta.ttl !== undefined && meta.ttl !== null ? String(meta.ttl) : DEFAULT_TTL,
  };

  return {
    did: document.id,
    document,
    state: JSON.parse(JSON.stringify(selectedEntry.state)) as DidWebvhDocument,
    metadata,
    versionNumber: Number.parseInt(versionId.split('-', 1)[0], 10),
    log: serializeLog(log),
  };
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

/**
 * Decides whether `signer` may append the next entry, and with which `updateKeys`.
 *
 * Without pre-rotation, the signer must be in the active `updateKeys`. With pre-rotation active
 * (`nextKeyHashes` non-empty) the rule inverts, as in did:webvh v1.0: the entry must set `updateKeys` to
 * keys whose hashes were committed, it is signed by one of them, and the keys that were active before can
 * no longer sign. That is what makes the commitment a recovery path after a compromise of the active key.
 * Returns the `updateKeys` the entry must carry, or undefined when the entry keeps the active ones.
 */
async function authorizeSigner(
  signer: AgentSigner,
  metadata: DidWebvhMetadata,
  requestedUpdateKeys: string[] | undefined
): Promise<{ signerKey: string; updateKeys: string[] | undefined }> {
  if (metadata.deactivated) {
    throw new DidWebvhError('invalidInput', 'did:webvh DID is deactivated');
  }
  const signerKey = await didWebvhUpdateKeyFor(signer);
  if (metadata.nextKeyHashes.length === 0) {
    if (!metadata.updateKeys.includes(signerKey)) {
      throw new DidWebvhError('unauthorized', 'Signer key is not in the active did:webvh updateKeys');
    }
    return { signerKey, updateKeys: requestedUpdateKeys };
  }

  const updateKeys = requestedUpdateKeys ?? [signerKey];
  if (!updateKeys.includes(signerKey)) {
    throw new DidWebvhError('invalidInput', 'While pre-rotation is active, updateKeys must include the signing key');
  }
  for (const key of updateKeys) {
    if (!metadata.nextKeyHashes.includes(await deriveNextKeyHash(key))) {
      throw new DidWebvhError(
        'unauthorized',
        'Pre-rotation is active: updateKeys may only contain keys committed in nextKeyHashes, and the active keys can no longer sign'
      );
    }
  }
  return { signerKey, updateKeys };
}

/** Hashes pre-rotation keys. `undefined` means "no change"; the keys must be new, never an active one. */
async function nextKeyHashesFor(
  nextUpdateKeys: string[] | undefined,
  activeKeys: string[]
): Promise<string[] | undefined> {
  if (nextUpdateKeys === undefined) {
    return undefined;
  }
  nextUpdateKeys.forEach(validateUpdateKey);
  if (new Set(nextUpdateKeys).size !== nextUpdateKeys.length) {
    throw new DidWebvhError('invalidInput', 'nextUpdateKeys must not repeat a key');
  }
  if (nextUpdateKeys.some((key) => activeKeys.includes(key))) {
    throw new DidWebvhError(
      'invalidInput',
      'nextUpdateKeys must not include a key that is active in the same entry: pre-rotation commits to NEW keys'
    );
  }
  return Promise.all(nextUpdateKeys.map((key) => deriveNextKeyHash(key)));
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

const SCID = /^[1-9A-HJ-NP-Za-km-z]+$/u;
const HOST_SEGMENT = /^([^%]+)(?:%3A([0-9]+))?$/u;

/**
 * Derives the HTTPS URL of a did:webvh DID's `did.jsonl` (did:webvh v1.0,
 * "The DID to HTTPS Transformation"). Applies the same host and path rules as
 * `createDidWebvhLog`: lowercase ASCII FQDN (no IP literals), optional port
 * encoded as `%3A`, unencoded path segments without `.`/`..`, and no path,
 * query or fragment in the DID. Throws `DidWebvhError('invalidDid')` otherwise.
 */
export function deriveDidWebvhLogUrl(did: string): string {
  const fail = (reason: string): never => {
    throw new DidWebvhError('invalidDid', `Invalid did:webvh DID (${reason}): ${String(did)}`);
  };
  if (typeof did !== 'string' || !did.startsWith('did:webvh:')) fail('not a did:webvh DID');
  if (/[/?#\s]/u.test(did)) fail('DID URLs with a path, query or fragment are not resolvable');

  const [scid, hostSegment, ...pathSegments] = did.slice('did:webvh:'.length).split(':');
  if (!scid || !SCID.test(scid)) fail('SCID must be base58btc');
  const hostMatch = HOST_SEGMENT.exec(hostSegment ?? '') ?? fail('host');
  const [, host, port] = hostMatch;
  const domain = port === undefined ? host : `${host}:${port}`;
  try {
    validateDomain(domain);
    pathSegments.forEach(validatePathSegment);
  } catch (error) {
    fail(error instanceof Error ? error.message : String(error));
  }

  return pathSegments.length > 0
    ? `https://${domain}/${pathSegments.join('/')}/did.jsonl`
    : `https://${domain}/.well-known/did.jsonl`;
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
