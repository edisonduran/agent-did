"""RFC 3161 timestamp tokens (ADR-007, D-11b): fixtures/timestamp-vectors.json, recorded from FreeTSA, DigiCert and an
OpenSSL test TSA (scripts/record-timestamp-vectors.js).

Parity: sdk/tests/Timestamp.test.ts.
"""

from __future__ import annotations

import base64
import hashlib
import json
import pathlib
import re
from typing import Any

import pytest

from agent_did_sdk import create_timestamp_request, verify_timestamp_token
from agent_did_sdk.crypto.timestamp import VerifyTimestampTokenResult

_FIXTURE = json.loads(
    (pathlib.Path(__file__).resolve().parents[2] / "fixtures" / "timestamp-vectors.json").read_text(encoding="utf-8")
)
_MESSAGE = bytes.fromhex(_FIXTURE["message"])


def _anchors(names: list[str]) -> list[bytes | str]:
    return [_FIXTURE["anchors"][name] for name in names]


def _token(vector: dict[str, Any]) -> bytes:
    return base64.b64decode(vector["token"])


def _by_name(name: str) -> dict[str, Any]:
    return next(vector for vector in _FIXTURE["vectors"] if vector["name"] == name)


def _as_fixture(result: VerifyTimestampTokenResult) -> dict[str, Any]:
    if result.status == "invalid":
        return {"status": "invalid", "reason": result.reason}
    return {
        "status": "valid",
        "genTime": result.gen_time,
        "trustedTimeNotAfter": result.trusted_time_not_after,
        "serialNumber": result.serial_number,
    }


def test_covers_real_tsas_and_every_rejection_reason() -> None:
    reasons = {
        vector["expected"]["reason"] for vector in _FIXTURE["vectors"] if vector["expected"]["status"] == "invalid"
    }
    assert sorted(reasons) == [
        "hash_algorithm_unsupported",
        "imprint_mismatch",
        "not_a_timestamping_certificate",
        "not_granted",
        "token_malformed",
        "verification_failed",
    ]
    assert _by_name("freetsa-granted")["expected"]["status"] == "valid"
    assert _by_name("digicert-granted")["expected"]["status"] == "valid"


@pytest.mark.parametrize("vector", _FIXTURE["vectors"], ids=lambda vector: vector["name"])
def test_vector(vector: dict[str, Any]) -> None:
    result = verify_timestamp_token(_token(vector), _MESSAGE, trust_anchors=_anchors(vector["anchors"]))
    assert _as_fixture(result) == vector["expected"]


def test_accepts_anchors_as_der_bytes() -> None:
    der = base64.b64decode(re.sub(r"-----[^-]+-----|\s", "", _FIXTURE["anchors"]["test-root"]))
    vector = _by_name("test-tsa-granted")
    assert _as_fixture(verify_timestamp_token(_token(vector), _MESSAGE, trust_anchors=[der])) == vector["expected"]


def test_rejects_a_token_over_the_right_hash_of_other_bytes() -> None:
    vector = _by_name("test-tsa-granted")
    other = bytes([_MESSAGE[0] ^ 1]) + _MESSAGE[1:]
    result = verify_timestamp_token(_token(vector), other, trust_anchors=_anchors(vector["anchors"]))
    assert _as_fixture(result) == {"status": "invalid", "reason": "imprint_mismatch"}


def test_raises_type_error_for_invalid_arguments_not_for_an_invalid_token() -> None:
    token = _token(_by_name("test-tsa-granted"))
    anchors = _anchors(["test-root"])
    with pytest.raises(TypeError):
        verify_timestamp_token("x", _MESSAGE, trust_anchors=anchors)  # type: ignore[arg-type]
    with pytest.raises(TypeError):
        verify_timestamp_token(token, "x", trust_anchors=anchors)  # type: ignore[arg-type]
    with pytest.raises(TypeError):
        verify_timestamp_token(token, _MESSAGE, trust_anchors=[])
    with pytest.raises(TypeError):
        verify_timestamp_token(token, _MESSAGE, trust_anchors=["no certificate here"])
    with pytest.raises(TypeError):
        verify_timestamp_token(token, _MESSAGE, trust_anchors=[b"\x01\x02\x03"])


def test_create_timestamp_request() -> None:
    import rfc3161_client._rust as rust  # noqa: PLC0415 - parse with the same library

    first = create_timestamp_request(_MESSAGE)
    second = create_timestamp_request(_MESSAGE)
    parsed = rust.parse_timestamp_request(first)
    assert parsed.version == 1
    assert parsed.message_imprint.hash_algorithm.dotted_string == "2.16.840.1.101.3.4.2.1"
    assert parsed.message_imprint.message == hashlib.sha256(_MESSAGE).digest()
    assert parsed.cert_req is True
    assert parsed.nonce is not None and parsed.nonce > 0
    assert rust.parse_timestamp_request(second).nonce != parsed.nonce
    with pytest.raises(TypeError):
        create_timestamp_request("x")  # type: ignore[arg-type]


async def _stamped_agent() -> tuple[Any, str, str, str, str, str]:
    """An agent whose key signed the fixture message, and whose key is retired after the token's genTime."""
    from agent_did_sdk.core.client import AgentDidClient
    from agent_did_sdk.core.identity import AgentIdentity, AgentIdentityConfig
    from agent_did_sdk.core.signer import LocalKeySigner
    from agent_did_sdk.core.types import CreateAgentParams

    client = AgentDidClient()
    identity = AgentIdentity(AgentIdentityConfig(controller_signer=LocalKeySigner.generate()[0], client=client))
    seed, payload = _FIXTURE["signingSeed"], _FIXTURE["signedPayload"]
    result = await identity.create(CreateAgentParams(name="StampedBot", signer=LocalKeySigner(seed)))
    did = result.document.id
    signature = await identity.sign_message(payload, seed)
    assert signature == _FIXTURE["message"]
    first = next(line for line in client.export_did_webvh_history(did).splitlines() if line.strip())
    stated_time = json.loads(first)["versionTime"]
    await client.rotate_verification_method(did)
    return client, did, f"{did}#key-1", payload, signature, stated_time


async def test_a_token_that_predates_the_key_retirement_turns_indeterminate_into_valid() -> None:
    client, did, key_id, payload, signature, stated_time = await _stamped_agent()
    vector = _by_name("test-tsa-granted")

    plain = await client.verify_signature_at_time(did, payload, signature, key_id, stated_time=stated_time)
    assert plain.status == "indeterminate"
    stamped = await client.verify_signature_at_time(
        did,
        payload,
        signature,
        key_id,
        stated_time=stated_time,
        timestamp_token=_token(vector),
        tsa_trust_anchors=_anchors(vector["anchors"]),
    )
    assert stamped.status == "valid"


async def test_timestamp_invalid_for_a_token_that_does_not_verify_or_covers_another_signature() -> None:
    client, did, key_id, payload, signature, stated_time = await _stamped_agent()
    granted = _token(_by_name("test-tsa-granted"))

    untrusted = await client.verify_signature_at_time(
        did, payload, signature, key_id, stated_time=stated_time,
        timestamp_token=granted, tsa_trust_anchors=_anchors(["test-other-root"]),
    )
    assert (untrusted.status, untrusted.reason, untrusted.timestamp_rejection) == (
        "invalid", "timestamp_invalid", "verification_failed"
    )
    other = ("1" if signature.startswith("0") else "0") + signature[1:]
    mismatch = await client.verify_signature_at_time(
        did, payload, other, key_id, stated_time=stated_time,
        timestamp_token=granted, tsa_trust_anchors=_anchors(["test-root"]),
    )
    assert (mismatch.reason, mismatch.timestamp_rejection) == ("timestamp_invalid", "imprint_mismatch")
    not_hex = await client.verify_signature_at_time(
        did, payload, "not-hex", key_id, stated_time=stated_time,
        timestamp_token=granted, tsa_trust_anchors=_anchors(["test-root"]),
    )
    assert (not_hex.status, not_hex.reason) == ("invalid", "signature_invalid")


async def test_refuses_a_token_with_trusted_time_not_after_or_without_anchors() -> None:
    client, did, key_id, payload, signature, stated_time = await _stamped_agent()
    token = _token(_by_name("test-tsa-granted"))

    with pytest.raises(TypeError):
        await client.verify_signature_at_time(
            did, payload, signature, key_id, stated_time=stated_time, timestamp_token=token,
            tsa_trust_anchors=_anchors(["test-root"]), trusted_time_not_after=stated_time,
        )
    with pytest.raises(TypeError):
        await client.verify_signature_at_time(
            did, payload, signature, key_id, stated_time=stated_time, timestamp_token=token
        )


# --- Malformed token structures (C-QA-2; TypeScript parity: Timestamp.test.ts "malformed token structures") ---

from agent_did_sdk.crypto import timestamp as _ts  # noqa: E402


def _tlv(tag: int, value: bytes) -> bytes:
    return bytes([tag]) + _ts._der_length(len(value)) + value


def _mutated_bare_token(mutate: Any) -> bytes:
    """Re-encodes the bare test token after *mutate* changes the list of SignedData child TLVs."""
    token = _token(_by_name("test-tsa-bare-token"))
    _tag, content_info, _ = _ts._read_der(token, 0)
    oid_end = _ts._children(content_info, 0, len(content_info))[0][1]
    _tag, explicit, _ = _ts._read_der(content_info, oid_end)
    _tag, signed_data, _ = _ts._read_der(explicit, 0)
    children = [signed_data[a:b] for a, b, _ in _ts._children(signed_data, 0, len(signed_data))]
    children = mutate(children)
    return _tlv(0x30, content_info[:oid_end] + _tlv(0xA0, _tlv(0x30, b"".join(children))))


_MALFORMED = {"status": "invalid", "reason": "token_malformed"}


@pytest.mark.parametrize(
    "der",
    [
        "30",  # one byte
        "1f0100",  # high tag number
        "3080",  # long form with no length bytes
        "3005",  # length beyond the data
        "020100",  # not a SEQUENCE
        "3000",  # empty SEQUENCE
        "300302010000",  # trailing bytes
        "3003020100",  # neither ContentInfo nor TimeStampResp
        "30053003040100",  # status that is not an INTEGER
        "30053003020100",  # granted response without a token
        "3003060100",  # ContentInfo without content
        "300730030201000505",  # granted, then bytes that are not a TLV
        "300f06092a864886f70d010702a0020400",  # ContentInfo whose content is not SignedData
    ],
)
def test_rejects_malformed_der(der: str) -> None:
    result = verify_timestamp_token(bytes.fromhex(der), _MESSAGE, trust_anchors=_anchors(["test-root"]))
    assert _as_fixture(result) == _MALFORMED


def test_rejects_a_token_with_two_signers_or_without_the_signer_certificate() -> None:
    def two_signers(children: list[bytes]) -> list[bytes]:
        _tag, signer_infos, _ = _ts._read_der(children[-1], 0)
        return [*children[:-1], _tlv(0x31, signer_infos + signer_infos)]

    def without_certificates(children: list[bytes]) -> list[bytes]:
        return [child for child in children if child[0] != 0xA0]

    for mutate in (two_signers, without_certificates):
        result = verify_timestamp_token(_mutated_bare_token(mutate), _MESSAGE, trust_anchors=_anchors(["test-root"]))
        assert _as_fixture(result) == _MALFORMED


def test_rejects_an_anchor_of_another_type() -> None:
    with pytest.raises(TypeError):
        verify_timestamp_token(_token(_by_name("test-tsa-granted")), _MESSAGE, trust_anchors=[123])  # type: ignore[list-item]


def test_a_certificate_without_extended_key_usage_is_not_a_timestamping_certificate() -> None:
    import cryptography.x509

    root = cryptography.x509.load_pem_x509_certificate(_FIXTURE["anchors"]["test-root"].encode())
    assert _ts._is_timestamping_certificate(root) is False


def test_accuracy_that_the_library_cannot_read_counts_as_zero() -> None:
    class _NoAccuracy:
        @property
        def accuracy(self) -> Any:
            raise ValueError("absent")

    assert _ts._accuracy_millis(_NoAccuracy()) == 0
