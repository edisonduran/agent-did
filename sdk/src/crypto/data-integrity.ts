/**
 * Data Integrity proofs with the `eddsa-jcs-2022` cryptosuite (W3C VC Data Integrity EdDSA Cryptosuites v1.0, common
 * algorithms of VC Data Integrity 1.1): JCS (RFC 8785) canonicalization, SHA-256, Ed25519, base58btc `proofValue`.
 *
 * hashData = SHA-256(JCS(proofConfig)) || SHA-256(JCS(unsecuredDocument)); the signature covers hashData. The proof
 * configuration is the proof without `proofValue`, with the document's `@context` copied into it.
 *
 * Checked against the W3C `vc-di-eddsa` test vectors (fixtures/vc-di-eddsa-test-vectors.json). Python parity:
 * `sdk-python/src/agent_did_sdk/crypto/data_integrity.py`.
 */
import bs58 from 'bs58';
import { sha256 } from '@noble/hashes/sha256';
import { canonicalizeJson } from './hash';
import { verifyEd25519 } from './ed25519-verify';

export const DATA_INTEGRITY_PROOF_TYPE = 'DataIntegrityProof';
export const EDDSA_JCS_2022_CRYPTOSUITE = 'eddsa-jcs-2022';

type JsonObject = Record<string, unknown>;

/** A Data Integrity proof (`DataIntegrityProof`). */
export interface DataIntegrityProof {
  type: string;
  cryptosuite: string;
  verificationMethod: string;
  proofPurpose: string;
  proofValue: string;
  created?: string;
  expires?: string;
  '@context'?: unknown;
  [member: string]: unknown;
}

/** Proof options of `createEddsaJcs2022Proof`. */
export interface EddsaJcs2022ProofOptions {
  verificationMethod: string;
  proofPurpose: string;
  created?: string;
  expires?: string;
}

function isJsonObject(value: unknown): value is JsonObject {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function concat(first: Uint8Array, second: Uint8Array): Uint8Array {
  const out = new Uint8Array(first.length + second.length);
  out.set(first);
  out.set(second, first.length);
  return out;
}

/** The bytes an `eddsa-jcs-2022` signature covers. */
export function eddsaJcs2022HashData(unsecuredDocument: JsonObject, proofConfig: JsonObject): Uint8Array {
  const encoder = new TextEncoder();
  return concat(
    sha256(encoder.encode(canonicalizeJson(proofConfig))),
    sha256(encoder.encode(canonicalizeJson(unsecuredDocument)))
  );
}

/** The proof configuration: `proofOptions` with the document's `@context`, when it has one. */
function proofConfiguration(unsecuredDocument: JsonObject, proofOptions: JsonObject): JsonObject {
  const config: JsonObject = { ...proofOptions };
  if (unsecuredDocument['@context'] !== undefined) {
    config['@context'] = unsecuredDocument['@context'];
  }
  return config;
}

/**
 * Creates an `eddsa-jcs-2022` proof over `unsecuredDocument` (which must not carry a `proof`). `sign` returns the
 * 64-byte Ed25519 signature of the bytes it is given.
 */
export async function createEddsaJcs2022Proof(
  unsecuredDocument: JsonObject,
  options: EddsaJcs2022ProofOptions,
  sign: (hashData: Uint8Array) => Promise<Uint8Array>
): Promise<DataIntegrityProof> {
  if ('proof' in unsecuredDocument) {
    throw new TypeError('The document already carries a proof');
  }
  const proofOptions: JsonObject = {
    type: DATA_INTEGRITY_PROOF_TYPE,
    cryptosuite: EDDSA_JCS_2022_CRYPTOSUITE,
    ...(options.created !== undefined ? { created: options.created } : {}),
    ...(options.expires !== undefined ? { expires: options.expires } : {}),
    verificationMethod: options.verificationMethod,
    proofPurpose: options.proofPurpose
  };
  const config = proofConfiguration(unsecuredDocument, proofOptions);
  const signature = await sign(eddsaJcs2022HashData(unsecuredDocument, config));
  if (signature.length !== 64) {
    throw new Error('An Ed25519 signature is 64 bytes');
  }
  return { ...config, proofValue: `z${bs58.encode(signature)}` } as DataIntegrityProof;
}

/** Decodes a `proofValue` (`z` + base58btc of 64 bytes). Returns `undefined` for anything else. */
export function decodeEddsaProofValue(proofValue: unknown): Uint8Array | undefined {
  if (typeof proofValue !== 'string' || !proofValue.startsWith('z')) {
    return undefined;
  }
  try {
    const bytes = bs58.decode(proofValue.slice(1));
    return bytes.length === 64 ? bytes : undefined;
  } catch {
    return undefined;
  }
}

function startsWithContext(documentContext: unknown, proofContext: unknown): boolean {
  const documentValues = Array.isArray(documentContext) ? documentContext : [documentContext];
  const proofValues = Array.isArray(proofContext) ? proofContext : [proofContext];
  if (proofValues.length > documentValues.length) {
    return false;
  }
  return proofValues.every((value, index) => canonicalizeJson(value) === canonicalizeJson(documentValues[index]));
}

/**
 * Verifies the single `eddsa-jcs-2022` proof of `securedDocument` with `publicKey` (32-byte Ed25519 key). The caller
 * decides which key `proof.verificationMethod` names and whether it may sign for `proof.proofPurpose`. Never throws.
 */
export function verifyEddsaJcs2022Proof(securedDocument: unknown, publicKey: Uint8Array): boolean {
  if (!isJsonObject(securedDocument) || !isJsonObject(securedDocument.proof)) {
    return false;
  }
  const { proof: rawProof, ...unsecuredDocument } = securedDocument;
  const { proofValue, ...proofOptions } = rawProof as JsonObject;
  if (proofOptions.type !== DATA_INTEGRITY_PROOF_TYPE || proofOptions.cryptosuite !== EDDSA_JCS_2022_CRYPTOSUITE) {
    return false;
  }
  const signature = decodeEddsaProofValue(proofValue);
  if (signature === undefined) {
    return false;
  }
  try {
    if (proofOptions['@context'] !== undefined) {
      if (!startsWithContext(unsecuredDocument['@context'] ?? null, proofOptions['@context'])) {
        return false;
      }
      unsecuredDocument['@context'] = proofOptions['@context'];
    }
    const hashData = eddsaJcs2022HashData(unsecuredDocument, proofConfiguration(unsecuredDocument, proofOptions));
    return verifyEd25519(signature, hashData, publicKey);
  } catch {
    return false;
  }
}
