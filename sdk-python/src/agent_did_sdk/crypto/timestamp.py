"""RFC 3161 timestamp tokens as trusted time evidence (ADR-007, D-11b).

A token proves that the bytes it covers (here: the raw bytes of a signature) existed at the TSA's ``genTime``. The CMS
signature and the certificate path are checked by ``rfc3161-client`` (ADR-007, D-11c, the optional extra
``agent-did-sdk[timestamps]``); this module adds the checks in the same order as the TypeScript SDK
(``sdk/src/crypto/timestamp.ts``), so both report the same reason for the same token.

Out of scope: revocation of TSA certificates (OCSP/CRL), long-term archive timestamps and sending requests to a TSA.
:func:`create_timestamp_request` only builds the request bytes; the caller owns the transport.
"""

from __future__ import annotations

import hashlib
import re
from base64 import b64decode
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING, Any, Literal

if TYPE_CHECKING:
    import cryptography.x509

TimestampRejection = Literal[
    "token_malformed",
    "not_granted",
    "hash_algorithm_unsupported",
    "imprint_mismatch",
    "not_a_timestamping_certificate",
    "verification_failed",
]
"""Why a timestamp token was rejected.

- ``token_malformed``: not a DER ``TimeStampResp`` or ``TimeStampToken``, not exactly one signer, or no embedded
  signer certificate.
- ``not_granted``: the response status is not ``granted`` (0).
- ``hash_algorithm_unsupported``: the message imprint uses a hash other than SHA-256, SHA-384 or SHA-512.
- ``imprint_mismatch``: the message imprint is not the hash of the bytes the token should cover.
- ``not_a_timestamping_certificate``: the signer certificate lacks a critical extended key usage with
  ``id-kp-timeStamping``.
- ``verification_failed``: the CMS signature does not verify, or the signer certificate does not chain to a trust
  anchor at ``genTime``.
"""

_EXTRA_HINT = "RFC 3161 timestamps need the optional extra: pip install 'agent-did-sdk[timestamps]'"
_HASHES: dict[str, Callable[[bytes], Any]] = {
    "2.16.840.1.101.3.4.2.1": hashlib.sha256,
    "2.16.840.1.101.3.4.2.2": hashlib.sha384,
    "2.16.840.1.101.3.4.2.3": hashlib.sha512,
}
_PEM_BLOCK = re.compile(r"-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----")


@dataclass(frozen=True)
class VerifyTimestampTokenResult:
    """Outcome of :func:`verify_timestamp_token`. ``status`` is ``"valid"`` or ``"invalid"`` (then ``reason``)."""

    status: Literal["valid", "invalid"]
    reason: TimestampRejection | None = None
    gen_time: str | None = None
    """The TSA's ``genTime`` (RFC 3339, millisecond precision)."""
    trusted_time_not_after: str | None = None
    """``genTime`` plus the token's ``accuracy``: the latest time the covered bytes can have come into existence."""
    serial_number: str | None = None
    """The token's serial number, lowercase hex."""


class _Rejected(Exception):
    def __init__(self, reason: TimestampRejection) -> None:
        super().__init__(reason)
        self.reason: TimestampRejection = reason


def verify_timestamp_token(
    token: bytes, message: bytes, *, trust_anchors: Sequence[bytes | str]
) -> VerifyTimestampTokenResult:
    """Verify an RFC 3161 timestamp token over *message* (the exact bytes the message imprint must hash).

    Accepts a DER ``TimeStampResp`` or a bare DER ``TimeStampToken``. *trust_anchors* are the TSA trust anchors the
    caller chooses, as DER bytes or PEM text. Returns the verified ``genTime`` and ``genTime + accuracy``, or the
    reason for rejecting the token. Raises ``TypeError`` for invalid arguments (not for an invalid token) and
    ``ImportError`` when the ``timestamps`` extra is not installed.
    """
    if not isinstance(token, bytes):
        raise TypeError("token must be bytes")
    if not isinstance(message, bytes):
        raise TypeError("message must be bytes")
    _require_extra()
    anchors = _parse_trust_anchors(trust_anchors)
    try:
        return _verify(token, message, anchors)
    except _Rejected as rejected:
        return VerifyTimestampTokenResult(status="invalid", reason=rejected.reason)


def create_timestamp_request(message: bytes) -> bytes:
    """Build a DER ``TimeStampReq`` (RFC 3161 §2.4.1) for *message*.

    SHA-256 imprint, ``certReq`` true (the TSA embeds its certificate, which verification needs) and a random nonce.
    Send it to a TSA with content type ``application/timestamp-query``; the SDK does not.
    """
    if not isinstance(message, bytes):
        raise TypeError("message must be bytes")
    rfc3161 = _require_extra()
    builder = rfc3161.TimestampRequestBuilder(hash_algorithm=None, nonce=True, cert_req=True)
    request = builder.data(message).hash_algorithm(rfc3161.base.HashAlgorithm.SHA256).build()
    return bytes(request.as_bytes())


def _require_extra() -> Any:
    try:
        import rfc3161_client
        import rfc3161_client.base
    except ImportError as exc:  # pragma: no cover - exercised only without the extra
        raise ImportError(_EXTRA_HINT) from exc
    return rfc3161_client


def _verify(token: bytes, message: bytes, anchors: list[cryptography.x509.Certificate]) -> VerifyTimestampTokenResult:
    rfc3161 = _require_extra()
    import cryptography.x509

    response_der = _sort_certificate_set(_granted_response(token))
    try:
        response = rfc3161.decode_timestamp_response(response_der)
        tst_info = response.tst_info
        signer_infos = list(response.signed_data.signer_infos)
        certificates = [cryptography.x509.load_der_x509_certificate(der) for der in response.signed_data.certificates]
    except Exception:  # noqa: BLE001 - any parse failure of untrusted bytes
        raise _Rejected("token_malformed") from None
    if len(signer_infos) != 1:
        raise _Rejected("token_malformed")

    hash_fn = _HASHES.get(tst_info.message_imprint.hash_algorithm.dotted_string)
    if hash_fn is None:
        raise _Rejected("hash_algorithm_unsupported")
    if hash_fn(message).digest() != tst_info.message_imprint.message:
        raise _Rejected("imprint_mismatch")

    signer = signer_infos[0]
    leaf = next(
        (cert for cert in certificates if cert.issuer == signer.issuer and cert.serial_number == signer.serial_number),
        None,
    )
    if leaf is None:
        raise _Rejected("token_malformed")
    if not _is_timestamping_certificate(leaf):
        raise _Rejected("not_a_timestamping_certificate")

    builder = rfc3161.VerifierBuilder()
    for anchor in anchors:
        builder = builder.add_root_certificate(anchor)
    try:
        builder.build().verify(response, tst_info.message_imprint.message)
    except Exception:  # noqa: BLE001 - VerificationError, or a defect of the library: fail closed
        raise _Rejected("verification_failed") from None

    gen_time = tst_info.gen_time
    if gen_time.tzinfo is None:  # pragma: no cover - rfc3161-client returns aware datetimes; kept for other versions
        gen_time = gen_time.replace(tzinfo=timezone.utc)
    not_after = gen_time + timedelta(milliseconds=_accuracy_millis(tst_info))
    return VerifyTimestampTokenResult(
        status="valid",
        gen_time=_iso_millis(gen_time),
        trusted_time_not_after=_iso_millis(not_after),
        serial_number=_serial_hex(tst_info.serial_number),
    )


def _granted_response(token: bytes) -> bytes:
    """The DER ``TimeStampResp`` of *token*: a bare ``TimeStampToken`` is wrapped as granted; any other status is
    ``not_granted``. Rejects anything that is not one complete DER SEQUENCE."""
    outer_tag, outer_value, end = _read_der(token, 0)
    if outer_tag != 0x30 or end != len(token) or not outer_value:
        raise _Rejected("token_malformed")
    first_tag, first_value, _ = _read_der(outer_value, 0)
    if first_tag == 0x06:  # ContentInfo: OID first
        status_info = b"\x30\x03\x02\x01\x00"
        body = status_info + token
        return b"\x30" + _der_length(len(body)) + body
    if first_tag != 0x30:
        raise _Rejected("token_malformed")
    status_tag, status_value, _ = _read_der(first_value, 0)
    if status_tag != 0x02 or int.from_bytes(status_value, "big", signed=True) != 0:
        if status_tag != 0x02:
            raise _Rejected("token_malformed")
        raise _Rejected("not_granted")
    return token


def _sort_certificate_set(response: bytes) -> bytes:
    """Put the token's ``certificates`` SET OF in DER order (sorted encodings).

    Some TSAs (DigiCert among them) send the set unsorted, which X.690 allows in BER but ``rfc3161-client`` rejects
    as invalid DER. The set is not covered by the CMS signature and keeps its length, so reordering its elements
    changes nothing that is verified. Any other structure is returned unchanged for the parser to judge.
    """
    try:
        _tag, _value, resp_end = _read_der(response, 0)
        children = _children(response, _value_start(response, 0), resp_end)
        if len(children) < 2:
            return response
        content_info = children[1]
        ci_children = _children(response, _value_start(response, content_info[0]), content_info[1])
        if len(ci_children) < 2 or ci_children[1][2] != 0xA0:
            return response
        explicit_start = _value_start(response, ci_children[1][0])
        signed_data_tag, _sd, signed_data_end = _read_der(response, explicit_start)
        if signed_data_tag != 0x30:
            return response
        for start, end, tag in _children(response, _value_start(response, explicit_start), signed_data_end):
            if tag == 0xA0:
                value_start = _value_start(response, start)
                elements = [response[a:b] for a, b, _ in _children(response, value_start, end)]
                return response[:value_start] + b"".join(sorted(elements)) + response[end:]
    except _Rejected:
        return response
    return response


def _value_start(data: bytes, offset: int) -> int:
    _tag, value, end = _read_der(data, offset)
    return end - len(value)


def _children(data: bytes, start: int, end: int) -> list[tuple[int, int, int]]:
    """``(start, end, tag)`` of each TLV between *start* and *end*."""
    result: list[tuple[int, int, int]] = []
    offset = start
    while offset < end:
        tag, _value, child_end = _read_der(data, offset)
        result.append((offset, child_end, tag))
        offset = child_end
    return result


def _read_der(data: bytes, offset: int) -> tuple[int, bytes, int]:
    """One DER TLV at *offset* (single-byte tags only): ``(tag, value, end offset)``."""
    if offset + 2 > len(data):
        raise _Rejected("token_malformed")
    tag = data[offset]
    if tag & 0x1F == 0x1F:
        raise _Rejected("token_malformed")
    length = data[offset + 1]
    position = offset + 2
    if length & 0x80:
        count = length & 0x7F
        if count == 0 or count > 4 or position + count > len(data):
            raise _Rejected("token_malformed")
        length = int.from_bytes(data[position : position + count], "big")
        position += count
    if position + length > len(data):
        raise _Rejected("token_malformed")
    return tag, data[position : position + length], position + length


def _der_length(length: int) -> bytes:
    if length < 0x80:
        return bytes([length])
    encoded = length.to_bytes((length.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(encoded)]) + encoded


def _is_timestamping_certificate(certificate: cryptography.x509.Certificate) -> bool:
    """RFC 3161 §2.3: a critical extended key usage that includes ``id-kp-timeStamping``."""
    import cryptography.x509
    from cryptography.x509.oid import ExtendedKeyUsageOID

    try:
        extension = certificate.extensions.get_extension_for_class(cryptography.x509.ExtendedKeyUsage)
    except cryptography.x509.ExtensionNotFound:
        return False
    return bool(extension.critical) and ExtendedKeyUsageOID.TIME_STAMPING in extension.value


def _accuracy_millis(tst_info: Any) -> int:
    try:
        accuracy = tst_info.accuracy
    except Exception:  # noqa: BLE001 - absent accuracy
        return 0
    if accuracy is None:
        return 0
    seconds = accuracy.seconds or 0
    millis = accuracy.millis or 0
    micros = accuracy.micros or 0
    return int(seconds) * 1000 + int(millis) + -(-int(micros) // 1000)


def _iso_millis(value: datetime) -> str:
    utc = value.astimezone(timezone.utc)
    return utc.strftime("%Y-%m-%dT%H:%M:%S") + f".{utc.microsecond // 1000:03d}Z"


def _serial_hex(serial: int) -> str:
    """The serial as its DER INTEGER content bytes, like the TypeScript SDK reports it."""
    return serial.to_bytes((serial.bit_length() + 8) // 8, "big", signed=True).hex()


def _parse_trust_anchors(anchors: Sequence[bytes | str]) -> list[cryptography.x509.Certificate]:
    import cryptography.x509

    message = "trust_anchors must be a non-empty list of DER certificates or PEM text"
    if isinstance(anchors, (str, bytes)) or not isinstance(anchors, Sequence) or not anchors:
        raise TypeError(message)
    ders: list[bytes] = []
    for anchor in anchors:
        if isinstance(anchor, str):
            blocks = _PEM_BLOCK.findall(anchor)
            if not blocks:
                raise TypeError(message)
            ders.extend(b64decode(re.sub(r"-----(BEGIN|END) CERTIFICATE-----|\s", "", block)) for block in blocks)
        elif isinstance(anchor, bytes):
            ders.append(anchor)
        else:
            raise TypeError(message)
    certificates: list[cryptography.x509.Certificate] = []
    for der in ders:
        try:
            certificate = cryptography.x509.load_der_x509_certificate(der)
        except ValueError:
            raise TypeError("trust_anchors contains a value that is not an X.509 certificate") from None
        if certificate not in certificates:
            certificates.append(certificate)
    return certificates
