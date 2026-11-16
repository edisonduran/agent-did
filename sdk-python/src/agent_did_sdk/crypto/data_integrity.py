"""Data Integrity proofs with the ``eddsa-jcs-2022`` cryptosuite.

W3C VC Data Integrity EdDSA Cryptosuites v1.0, common algorithms of VC Data Integrity 1.1: JCS (RFC 8785)
canonicalization, SHA-256, Ed25519, base58btc ``proofValue``.

``hashData = SHA-256(JCS(proofConfig)) || SHA-256(JCS(unsecuredDocument))``; the signature covers ``hashData``. The
proof configuration is the proof without ``proofValue``, with the document's ``@context`` copied into it.

Checked against the W3C ``vc-di-eddsa`` test vectors (fixtures/vc-di-eddsa-test-vectors.json). TypeScript parity:
``sdk/src/crypto/data-integrity.ts``.
"""

from __future__ import annotations

import hashlib
from collections.abc import Awaitable, Callable
from typing import Any

from .ed25519 import verify_ed25519
from .hash import canonicalize_json
from .multibase import _base58_decode, _base58_encode

DATA_INTEGRITY_PROOF_TYPE = "DataIntegrityProof"
EDDSA_JCS_2022_CRYPTOSUITE = "eddsa-jcs-2022"


def eddsa_jcs_2022_hash_data(unsecured_document: dict[str, Any], proof_config: dict[str, Any]) -> bytes:
    """The bytes an ``eddsa-jcs-2022`` signature covers."""
    return (
        hashlib.sha256(canonicalize_json(proof_config).encode("utf-8")).digest()
        + hashlib.sha256(canonicalize_json(unsecured_document).encode("utf-8")).digest()
    )


def _proof_configuration(unsecured_document: dict[str, Any], proof_options: dict[str, Any]) -> dict[str, Any]:
    config = dict(proof_options)
    if "@context" in unsecured_document:
        config["@context"] = unsecured_document["@context"]
    return config


async def create_eddsa_jcs_2022_proof(
    unsecured_document: dict[str, Any],
    *,
    verification_method: str,
    proof_purpose: str,
    sign: Callable[[bytes], Awaitable[bytes]],
    created: str | None = None,
    expires: str | None = None,
) -> dict[str, Any]:
    """Create an ``eddsa-jcs-2022`` proof over *unsecured_document* (which must not carry a ``proof``).

    *sign* returns the 64-byte Ed25519 signature of the bytes it is given.
    """
    if "proof" in unsecured_document:
        raise TypeError("The document already carries a proof")
    options: dict[str, Any] = {"type": DATA_INTEGRITY_PROOF_TYPE, "cryptosuite": EDDSA_JCS_2022_CRYPTOSUITE}
    if created is not None:
        options["created"] = created
    if expires is not None:
        options["expires"] = expires
    options["verificationMethod"] = verification_method
    options["proofPurpose"] = proof_purpose
    config = _proof_configuration(unsecured_document, options)
    signature = await sign(eddsa_jcs_2022_hash_data(unsecured_document, config))
    if len(signature) != 64:
        raise ValueError("An Ed25519 signature is 64 bytes")
    return {**config, "proofValue": encode_eddsa_proof_value(signature)}


def encode_eddsa_proof_value(signature: bytes) -> str:
    """The ``proofValue`` of a 64-byte Ed25519 signature: ``z`` + base58btc."""
    if len(signature) != 64:
        raise ValueError("An Ed25519 signature is 64 bytes")
    return "z" + _base58_encode(signature)


def decode_eddsa_proof_value(proof_value: object) -> bytes | None:
    """Decode a ``proofValue`` (``z`` + base58btc of 64 bytes). Returns ``None`` for anything else."""
    if not isinstance(proof_value, str) or not proof_value.startswith("z"):
        return None
    try:
        decoded = _base58_decode(proof_value[1:])
    except ValueError:
        return None
    return decoded if len(decoded) == 64 else None


def _starts_with_context(document_context: object, proof_context: object) -> bool:
    document_values = document_context if isinstance(document_context, list) else [document_context]
    proof_values = proof_context if isinstance(proof_context, list) else [proof_context]
    if len(proof_values) > len(document_values):
        return False
    return all(
        canonicalize_json(value) == canonicalize_json(document_values[index])
        for index, value in enumerate(proof_values)
    )


def verify_eddsa_jcs_2022_proof(secured_document: object, public_key: bytes) -> bool:
    """Verify the single ``eddsa-jcs-2022`` proof of *secured_document* with *public_key* (32-byte Ed25519 key).

    The caller decides which key ``proof.verificationMethod`` names and whether it may sign for
    ``proof.proofPurpose``. Never raises.
    """
    if not isinstance(secured_document, dict) or not isinstance(secured_document.get("proof"), dict):
        return False
    unsecured_document = {key: value for key, value in secured_document.items() if key != "proof"}
    proof_options = {key: value for key, value in secured_document["proof"].items() if key != "proofValue"}
    if (
        proof_options.get("type") != DATA_INTEGRITY_PROOF_TYPE
        or proof_options.get("cryptosuite") != EDDSA_JCS_2022_CRYPTOSUITE
    ):
        return False
    signature = decode_eddsa_proof_value(secured_document["proof"].get("proofValue"))
    if signature is None:
        return False
    try:
        if "@context" in proof_options:
            if not _starts_with_context(unsecured_document.get("@context"), proof_options["@context"]):
                return False
            unsecured_document["@context"] = proof_options["@context"]
        hash_data = eddsa_jcs_2022_hash_data(
            unsecured_document, _proof_configuration(unsecured_document, proof_options)
        )
    except Exception:  # noqa: BLE001 - a value JCS cannot represent is a failed verification
        return False
    return verify_ed25519(signature, hash_data, public_key)
