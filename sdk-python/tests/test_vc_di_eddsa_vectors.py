"""W3C vc-di-eddsa ``eddsa-jcs-2022`` test vectors against the SDK's Data Integrity implementation (ADR-006 D-8d).

Runs only when VC_DI_EDDSA_DIR points at a checkout of w3c/vc-di-eddsa at the commit pinned in
fixtures/vc-di-eddsa-test-vectors.json (the CI workflow ``ci-vc-di-eddsa-vectors.yml`` does this). TypeScript parity:
sdk/tests/VcDiEddsaTestVectors.test.ts.
"""

from __future__ import annotations

import copy
import hashlib
import json
import os
import pathlib
from typing import Any

import pytest
from nacl.signing import SigningKey

from agent_did_sdk.crypto.data_integrity import (
    create_eddsa_jcs_2022_proof,
    eddsa_jcs_2022_hash_data,
    verify_eddsa_jcs_2022_proof,
)
from agent_did_sdk.crypto.hash import canonicalize_json
from agent_did_sdk.crypto.multibase import _base58_decode, decode_public_key_multibase

_PIN: dict[str, Any] = json.loads(
    (pathlib.Path(__file__).resolve().parents[2] / "fixtures" / "vc-di-eddsa-test-vectors.json").read_text(
        encoding="utf-8"
    )
)
_DIR = os.environ.get("VC_DI_EDDSA_DIR")
_VECTORS: dict[str, str] = _PIN["eddsaJcs2022"]

pytestmark = pytest.mark.skipif(_DIR is None, reason="VC_DI_EDDSA_DIR is not set")


def _text(file: str) -> str:
    assert _DIR is not None
    return (pathlib.Path(_DIR) / file).read_text(encoding="utf-8").strip()


def _json(file: str) -> dict[str, Any]:
    value: dict[str, Any] = json.loads(_text(file))
    return value


def _decode_private_key_multibase(value: str) -> bytes:
    """``z`` + base58btc(0x80 0x26 + 32-byte seed): the multicodec Ed25519 private key of the vectors."""
    decoded = _base58_decode(value[1:])
    if not value.startswith("z") or len(decoded) != 34 or decoded[:2] != b"\x80\x26":
        raise ValueError("not an Ed25519 private key multikey")
    return decoded[2:]


def test_canonicalizes_and_hashes_the_document_and_the_proof_configuration() -> None:
    unsigned = _json(_PIN["unsigned"])
    proof_config = _json(_VECTORS["proofConfig"])
    assert canonicalize_json(unsigned) == _text(_VECTORS["canonicalDocument"])
    assert canonicalize_json(proof_config) == _text(_VECTORS["canonicalProofConfig"])
    assert hashlib.sha256(canonicalize_json(unsigned).encode()).hexdigest() == _text(_VECTORS["documentHash"])
    assert hashlib.sha256(canonicalize_json(proof_config).encode()).hexdigest() == _text(_VECTORS["proofConfigHash"])
    assert eddsa_jcs_2022_hash_data(unsigned, proof_config).hex() == _text(_VECTORS["combinedHash"])


async def test_creates_the_signed_credential_of_the_vectors() -> None:
    key_pair = _json(_PIN["keyPair"])
    unsigned = _json(_PIN["unsigned"])
    proof_config = _json(_VECTORS["proofConfig"])
    signing_key = SigningKey(_decode_private_key_multibase(key_pair["privateKeyMultibase"]))
    assert bytes(signing_key.verify_key) == decode_public_key_multibase(key_pair["publicKeyMultibase"])

    async def sign(hash_data: bytes) -> bytes:
        return signing_key.sign(hash_data).signature

    proof = await create_eddsa_jcs_2022_proof(
        unsigned,
        created=proof_config["created"],
        verification_method=proof_config["verificationMethod"],
        proof_purpose=proof_config["proofPurpose"],
        sign=sign,
    )
    assert _base58_decode(proof["proofValue"][1:]).hex() == _text(_VECTORS["signatureHex"])
    assert proof["proofValue"] == _text(_VECTORS["proofValue"])
    assert {**unsigned, "proof": proof} == _json(_VECTORS["signed"])


def test_verifies_the_signed_credential_and_rejects_a_changed_one() -> None:
    public_key = decode_public_key_multibase(_json(_PIN["keyPair"])["publicKeyMultibase"])
    signed = _json(_VECTORS["signed"])
    assert verify_eddsa_jcs_2022_proof(signed, public_key)

    changed = copy.deepcopy(signed)
    changed["credentialSubject"]["alumniOf"] = "Another School"
    assert not verify_eddsa_jcs_2022_proof(changed, public_key)

    other_context = copy.deepcopy(signed)
    other_context["@context"] = ["https://www.w3.org/ns/credentials/v2"]
    assert not verify_eddsa_jcs_2022_proof(other_context, public_key)
