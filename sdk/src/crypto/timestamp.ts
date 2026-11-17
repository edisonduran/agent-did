/**
 * RFC 3161 timestamp tokens as trusted time evidence (ADR-007, D-11b).
 *
 * A token proves that the bytes it covers (here: the raw bytes of a signature) existed at the TSA's `genTime`.
 * Parsing, the CMS signature and the certificate path are checked by `pkijs` (ADR-007, D-11c); this module adds the
 * checks pkijs leaves to the caller (status, hash algorithm, the TSA certificate's extended key usage) and maps the
 * outcome to one reason per failure. The checks run in the same order as in the Python SDK
 * (`agent_did_sdk.crypto.timestamp`), so both report the same reason for the same token.
 *
 * Out of scope: revocation of TSA certificates (OCSP/CRL), long-term archive timestamps and sending requests to a
 * TSA. `createTimestampRequest` only builds the request bytes; the caller owns the transport.
 */
import * as asn1js from 'asn1js';
import * as pkijs from 'pkijs';
import { sha256 } from '@noble/hashes/sha256';
import { sha384, sha512 } from '@noble/hashes/sha512';
import { randomBytes } from '@noble/hashes/utils';

/** Why a timestamp token was rejected. */
export type TimestampRejection =
  /** Not a DER `TimeStampResp` or `TimeStampToken`, not exactly one signer, or no embedded signer certificate. */
  | 'token_malformed'
  /** The response status is not `granted` (0). */
  | 'not_granted'
  /** The message imprint uses a hash other than SHA-256, SHA-384 or SHA-512. */
  | 'hash_algorithm_unsupported'
  /** The message imprint is not the hash of the bytes the token should cover. */
  | 'imprint_mismatch'
  /** The signer certificate lacks a critical extended key usage with `id-kp-timeStamping`. */
  | 'not_a_timestamping_certificate'
  /** The CMS signature does not verify, or the signer certificate does not chain to a trust anchor at `genTime`. */
  | 'verification_failed';

export type VerifyTimestampTokenResult =
  | {
      status: 'valid';
      /** The TSA's `genTime` (RFC 3339, millisecond precision). */
      genTime: string;
      /** `genTime` plus the token's `accuracy`: the latest time the covered bytes can have come into existence. */
      trustedTimeNotAfter: string;
      /** The token's serial number, lowercase hex. */
      serialNumber: string;
    }
  | { status: 'invalid'; reason: TimestampRejection };

export interface VerifyTimestampTokenOptions {
  /** The TSA trust anchors, as DER bytes or PEM text. The caller chooses which TSAs it trusts. */
  trustAnchors: (Uint8Array | string)[];
}

const OID_SIGNED_DATA = '1.2.840.113549.1.7.2';
const OID_TST_INFO = '1.2.840.113549.1.9.16.1.4';
const OID_EXTENDED_KEY_USAGE = '2.5.29.37';
const OID_KP_TIME_STAMPING = '1.3.6.1.5.5.7.3.8';
const HASHES: Record<string, (bytes: Uint8Array) => Uint8Array> = {
  '2.16.840.1.101.3.4.2.1': sha256,
  '2.16.840.1.101.3.4.2.2': sha384,
  '2.16.840.1.101.3.4.2.3': sha512,
};
const SHA256_OID = '2.16.840.1.101.3.4.2.1';

class Rejected extends Error {
  constructor(public readonly reason: TimestampRejection) {
    super(reason);
  }
}

/**
 * Verifies an RFC 3161 timestamp token over `message` (the exact bytes the token's message imprint must hash). Accepts
 * a DER `TimeStampResp` or a bare DER `TimeStampToken`. Returns the verified `genTime` and `genTime + accuracy`, or
 * the reason for rejecting it. Throws `TypeError` for invalid arguments (not for an invalid token).
 */
export async function verifyTimestampToken(
  token: Uint8Array,
  message: Uint8Array,
  options: VerifyTimestampTokenOptions
): Promise<VerifyTimestampTokenResult> {
  if (!(token instanceof Uint8Array)) throw new TypeError('token must be a Uint8Array');
  if (!(message instanceof Uint8Array)) throw new TypeError('message must be a Uint8Array');
  const anchors = parseTrustAnchors(options?.trustAnchors);
  try {
    return await verifyParsed(token, message, anchors);
  } catch (error) {
    if (error instanceof Rejected) {
      return { status: 'invalid', reason: error.reason };
    }
    /* istanbul ignore next -- every parse step maps its failure to Rejected; anything else is a bug to surface */
    throw error;
  }
}

/**
 * Builds a DER `TimeStampReq` (RFC 3161 §2.4.1) for `message`: SHA-256 imprint, `certReq: true` (the TSA embeds its
 * certificate, which verification needs) and a random 64-bit nonce. Send it to a TSA with content type
 * `application/timestamp-query`; the SDK does not.
 */
export function createTimestampRequest(message: Uint8Array): Uint8Array {
  if (!(message instanceof Uint8Array)) throw new TypeError('message must be a Uint8Array');
  const nonce = randomBytes(8);
  nonce[0] &= 0x7f; // a positive INTEGER
  if (nonce[0] === 0) nonce[0] = 1; // and minimally encoded
  const request = new pkijs.TimeStampReq({
    version: 1,
    messageImprint: new pkijs.MessageImprint({
      hashAlgorithm: new pkijs.AlgorithmIdentifier({ algorithmId: SHA256_OID }),
      hashedMessage: new asn1js.OctetString({ valueHex: sha256(message) }),
    }),
    nonce: new asn1js.Integer({ valueHex: nonce }),
    certReq: true,
  });
  return new Uint8Array(request.toSchema().toBER(false));
}

async function verifyParsed(
  token: Uint8Array,
  message: Uint8Array,
  anchors: pkijs.Certificate[]
): Promise<VerifyTimestampTokenResult> {
  const contentInfo = parseResponse(token);
  const signedData = parseSignedData(contentInfo);
  const tstInfo = parseTstInfo(signedData);

  const hash = HASHES[tstInfo.messageImprint.hashAlgorithm.algorithmId];
  if (!hash) throw new Rejected('hash_algorithm_unsupported');
  if (!equalBytes(hash(message), new Uint8Array(tstInfo.messageImprint.hashedMessage.valueBlock.valueHexView))) {
    throw new Rejected('imprint_mismatch');
  }

  const signer = signerCertificate(signedData);
  if (!isTimestampingCertificate(signer)) throw new Rejected('not_a_timestamping_certificate');

  // A trust anchor replaces any embedded certificate with its subject and key (for example a cross-signed copy of a
  // root), so the path ends at the anchor instead of following the cross-signature.
  signedData.certificates = (signedData.certificates ?? []).filter(
    (certificate) => !(certificate instanceof pkijs.Certificate) || !anchors.some((anchor) => sameSubjectAndKey(anchor, certificate))
  );

  let verified: boolean;
  try {
    verified = await signedData.verify(
      { signer: 0, data: toArrayBuffer(message), trustedCerts: anchors, checkChain: true },
      cryptoEngine()
    );
  } catch {
    verified = false;
  }
  if (!verified) throw new Rejected('verification_failed');

  const genTime = tstInfo.genTime;
  const accuracy = tstInfo.accuracy;
  const accuracyMs =
    (accuracy?.seconds ?? 0) * 1000 + (accuracy?.millis ?? 0) + Math.ceil((accuracy?.micros ?? 0) / 1000);
  return {
    status: 'valid',
    genTime: genTime.toISOString(),
    trustedTimeNotAfter: new Date(genTime.getTime() + accuracyMs).toISOString(),
    serialNumber: toHex(new Uint8Array(tstInfo.serialNumber.valueBlock.valueHexView)),
  };
}

/** A `TimeStampResp` whose status is granted, or a bare `TimeStampToken`; returns the token's `ContentInfo`. */
function parseResponse(token: Uint8Array): pkijs.ContentInfo {
  const outer = fromDer(token);
  if (!(outer instanceof asn1js.Sequence) || outer.valueBlock.value.length === 0) throw new Rejected('token_malformed');
  if (outer.valueBlock.value[0] instanceof asn1js.ObjectIdentifier) {
    return parseOr(() => new pkijs.ContentInfo({ schema: outer }));
  }
  const response = parseOr(() => new pkijs.TimeStampResp({ schema: outer }));
  if (response.status.status !== 0) throw new Rejected('not_granted');
  if (!response.timeStampToken) throw new Rejected('token_malformed');
  return response.timeStampToken;
}

function parseSignedData(contentInfo: pkijs.ContentInfo): pkijs.SignedData {
  if (contentInfo.contentType !== OID_SIGNED_DATA) throw new Rejected('token_malformed');
  const signedData = parseOr(() => new pkijs.SignedData({ schema: contentInfo.content }));
  if (signedData.encapContentInfo.eContentType !== OID_TST_INFO || !signedData.encapContentInfo.eContent) {
    throw new Rejected('token_malformed');
  }
  if (signedData.signerInfos.length !== 1) throw new Rejected('token_malformed');
  return signedData;
}

function parseTstInfo(signedData: pkijs.SignedData): pkijs.TSTInfo {
  const content = signedData.encapContentInfo.eContent as asn1js.OctetString;
  return parseOr(() => pkijs.TSTInfo.fromBER(content.getValue()));
}

/** The embedded certificate named by the signer's `issuerAndSerialNumber`. */
function signerCertificate(signedData: pkijs.SignedData): pkijs.Certificate {
  const sid = signedData.signerInfos[0].sid;
  if (!(sid instanceof pkijs.IssuerAndSerialNumber)) throw new Rejected('token_malformed');
  const match = (signedData.certificates ?? []).find(
    (certificate): certificate is pkijs.Certificate =>
      certificate instanceof pkijs.Certificate &&
      certificate.issuer.isEqual(sid.issuer) &&
      certificate.serialNumber.isEqual(sid.serialNumber)
  );
  if (!match) throw new Rejected('token_malformed');
  return match;
}

/** RFC 3161 §2.3: the TSA certificate has a critical extended key usage that includes `id-kp-timeStamping`. */
function isTimestampingCertificate(certificate: pkijs.Certificate): boolean {
  const extension = (certificate.extensions ?? []).find((item) => item.extnID === OID_EXTENDED_KEY_USAGE);
  if (!extension || extension.critical !== true) return false;
  const usage = extension.parsedValue as pkijs.ExtKeyUsage | undefined;
  return Array.isArray(usage?.keyPurposes) && usage.keyPurposes.includes(OID_KP_TIME_STAMPING);
}

function sameSubjectAndKey(a: pkijs.Certificate, b: pkijs.Certificate): boolean {
  return (
    a.subject.isEqual(b.subject) &&
    equalBytes(
      new Uint8Array(a.subjectPublicKeyInfo.toSchema().toBER(false)),
      new Uint8Array(b.subjectPublicKeyInfo.toSchema().toBER(false))
    )
  );
}

function parseTrustAnchors(anchors: unknown): pkijs.Certificate[] {
  if (!Array.isArray(anchors) || anchors.length === 0) {
    throw new TypeError('trustAnchors must be a non-empty array of DER certificates or PEM text');
  }
  return anchors.flatMap((anchor) => {
    const ders =
      typeof anchor === 'string' ? pemBlocks(anchor) : anchor instanceof Uint8Array ? [anchor] : undefined;
    if (!ders || ders.length === 0) {
      throw new TypeError('trustAnchors must be a non-empty array of DER certificates or PEM text');
    }
    return ders.map((der) => {
      try {
        return pkijs.Certificate.fromBER(toArrayBuffer(der));
      } catch {
        throw new TypeError('trustAnchors contains a value that is not an X.509 certificate');
      }
    });
  });
}

function pemBlocks(pem: string): Uint8Array[] {
  const blocks = pem.match(/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/gu) ?? [];
  return blocks.map((block) => {
    const body = block.replace(/-----(BEGIN|END) CERTIFICATE-----|\s/gu, '');
    return new Uint8Array(Buffer.from(body, 'base64'));
  });
}

function fromDer(bytes: Uint8Array): asn1js.AsnType {
  const parsed = asn1js.fromBER(bytes);
  if (parsed.offset === -1 || parsed.offset !== bytes.byteLength) throw new Rejected('token_malformed');
  return parsed.result;
}

function parseOr<T>(parse: () => T): T {
  try {
    return parse();
  } catch {
    throw new Rejected('token_malformed');
  }
}

function cryptoEngine(): pkijs.ICryptoEngine {
  return new pkijs.CryptoEngine({ name: 'agent-did', crypto: globalThis.crypto });
}

function toArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  return bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength) as ArrayBuffer;
}

function equalBytes(a: Uint8Array, b: Uint8Array): boolean {
  return a.length === b.length && a.every((value, index) => value === b[index]);
}

function toHex(bytes: Uint8Array): string {
  return Array.from(bytes, (value) => value.toString(16).padStart(2, '0')).join('');
}
