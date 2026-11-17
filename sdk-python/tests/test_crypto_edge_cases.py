"""Edge cases of the crypto modules that the protocol-level tests do not reach (C-QA-2).

TypeScript parity: sdk/tests/CryptoEdgeCases.test.ts.
"""

from __future__ import annotations

from typing import Any

import pytest
from nacl.signing import SigningKey

from agent_did_sdk.crypto.data_integrity import (
    create_eddsa_jcs_2022_proof,
    encode_eddsa_proof_value,
    verify_eddsa_jcs_2022_proof,
)

_KEY = SigningKey(bytes([7]) * 32)
_PUBLIC_KEY = bytes(_KEY.verify_key)
_OPTIONS: dict[str, Any] = {"verification_method": "did:example:a#key-1", "proof_purpose": "assertionMethod"}
_UNSECURED: dict[str, Any] = {"@context": ["https://www.w3.org/ns/credentials/v2"], "id": "urn:uuid:1", "value": 1}


async def _sign(data: bytes) -> bytes:
    return _KEY.sign(data).signature


async def _secured(document: dict[str, Any] = _UNSECURED, **extra: Any) -> dict[str, Any]:
    proof = await create_eddsa_jcs_2022_proof(document, sign=_sign, **_OPTIONS, **extra)
    return {**document, "proof": proof}


async def test_refuses_a_second_proof_and_a_signature_of_the_wrong_length() -> None:
    with pytest.raises(TypeError, match="already carries a proof"):
        await create_eddsa_jcs_2022_proof(await _secured(), sign=_sign, **_OPTIONS)

    async def short(_data: bytes) -> bytes:
        return bytes(63)

    with pytest.raises(ValueError, match="64 bytes"):
        await create_eddsa_jcs_2022_proof(_UNSECURED, sign=short, **_OPTIONS)
    with pytest.raises(ValueError, match="64 bytes"):
        encode_eddsa_proof_value(bytes(65))


async def test_signs_created_and_expires_into_the_proof() -> None:
    document = await _secured(created="2026-01-01T00:00:00Z", expires="2027-01-01T00:00:00Z")
    assert document["proof"]["created"] == "2026-01-01T00:00:00Z"
    assert document["proof"]["expires"] == "2027-01-01T00:00:00Z"
    assert verify_eddsa_jcs_2022_proof(document, _PUBLIC_KEY) is True


async def test_rejects_every_malformed_variant() -> None:
    document = await _secured()
    proof = document["proof"]

    assert verify_eddsa_jcs_2022_proof("not an object", _PUBLIC_KEY) is False
    assert verify_eddsa_jcs_2022_proof(dict(_UNSECURED), _PUBLIC_KEY) is False
    other_suite = {**proof, "cryptosuite": "eddsa-rdfc-2022"}
    assert verify_eddsa_jcs_2022_proof({**document, "proof": other_suite}, _PUBLIC_KEY) is False
    assert verify_eddsa_jcs_2022_proof({**document, "proof": {**proof, "proofValue": "z0"}}, _PUBLIC_KEY) is False
    # A value JCS cannot serialize makes the check fail instead of raising
    assert verify_eddsa_jcs_2022_proof({**document, "value": float("nan")}, _PUBLIC_KEY) is False


async def test_proof_context_must_be_a_prefix_of_the_document_context() -> None:
    with_context = {**_UNSECURED, "@context": ["https://www.w3.org/ns/credentials/v2", "https://example.org/v1"]}
    document = await _secured(with_context)
    proof = document["proof"]
    longer = [*with_context["@context"], "https://example.org/v2"]

    assert verify_eddsa_jcs_2022_proof({**document, "proof": {**proof, "@context": longer}}, _PUBLIC_KEY) is False
    other = {**proof, "@context": ["https://example.org/other"]}
    assert verify_eddsa_jcs_2022_proof({**document, "proof": other}, _PUBLIC_KEY) is False


def test_decodes_only_z_prefixed_base58btc_of_64_bytes() -> None:
    from agent_did_sdk.crypto.data_integrity import decode_eddsa_proof_value

    assert decode_eddsa_proof_value(42) is None
    assert decode_eddsa_proof_value("u" + "A" * 86) is None
    assert decode_eddsa_proof_value("z0OIl") is None
    assert decode_eddsa_proof_value("z" + "A" * 10) is None
