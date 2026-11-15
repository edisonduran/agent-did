"""Runs ``fixtures/verification-relationship-vectors.json`` (RFC-001 §6.2.1.3).

The TypeScript SDK runs the same file in ``sdk/tests/VerificationRelationshipVectors.test.ts``.
"""

from __future__ import annotations

import json
import pathlib
from typing import Any, cast

import pytest
from nacl.signing import VerifyKey

from agent_did_sdk import (
    REQUIRED_RELATIONSHIP_BY_ARTIFACT,
    SIGNED_ARTIFACT_KINDS,
    AgentDIDDocument,
    IdentityCompositionError,
    SignedArtifactKind,
    assert_key_purpose,
    assert_signing_purpose,
    decode_public_key_multibase,
    required_relationship_for,
)
from agent_did_sdk.verification.signature import verify_with_active_keys

FIXTURE: dict[str, Any] = json.loads(
    (pathlib.Path(__file__).resolve().parents[2] / "fixtures" / "verification-relationship-vectors.json").read_text(
        encoding="utf-8"
    )
)
DOCUMENT = AgentDIDDocument.model_validate(FIXTURE["didDocument"])


def _check_key_for_artifact(key_id: str, artifact: SignedArtifactKind) -> None:
    """The SDK path for a signed artifact: pick the relationship from the table, then apply §6.2.1."""
    required = required_relationship_for(artifact)
    assert_signing_purpose(required, DOCUMENT, key_id)
    assert_key_purpose(key_id, DOCUMENT, required)


def test_exports_the_same_artifact_table_as_the_fixture() -> None:
    assert dict(REQUIRED_RELATIONSHIP_BY_ARTIFACT) == FIXTURE["requiredRelationshipByArtifact"]
    assert list(SIGNED_ARTIFACT_KINDS) == list(FIXTURE["requiredRelationshipByArtifact"])
    with pytest.raises(TypeError):
        cast(Any, REQUIRED_RELATIONSHIP_BY_ARTIFACT)["assertion"] = "authentication"


@pytest.mark.parametrize("artifact", ["receipt", "", None])
def test_rejects_an_unknown_artifact_kind(artifact: Any) -> None:
    with pytest.raises(ValueError):
        required_relationship_for(artifact)


@pytest.mark.parametrize("vector", FIXTURE["vectors"], ids=[vector["id"] for vector in FIXTURE["vectors"]])
def test_vector(vector: dict[str, Any]) -> None:
    # The signature is valid for the key, so a rejection can only come from the relationship check.
    method = next(m for m in DOCUMENT.verification_method if m.id == vector["keyId"])
    assert method.public_key_multibase is not None
    VerifyKey(decode_public_key_multibase(method.public_key_multibase)).verify(
        FIXTURE["payload"].encode("utf-8"), bytes.fromhex(vector["signatureHex"])
    )

    expected = vector["expected"]
    if expected["ok"]:
        _check_key_for_artifact(vector["keyId"], vector["artifact"])
        return

    with pytest.raises(IdentityCompositionError) as caught:
        _check_key_for_artifact(vector["keyId"], vector["artifact"])
    assert caught.value.reason == expected["reason"]
    assert caught.value.key_id == vector["keyId"]
    assert caught.value.required_purpose == expected["requiredPurpose"]
    assert caught.value.found_in == expected["foundIn"]


def _with_method_type(vector: dict[str, Any]) -> dict[str, Any]:
    """``didDocument`` with the vector's key method set to the vector's ``type``."""
    doc: dict[str, Any] = json.loads(json.dumps(FIXTURE["didDocument"]))
    for method in doc["verificationMethod"]:
        if method["id"] == vector["keyId"]:
            method["type"] = vector["type"]
    return doc


@pytest.mark.parametrize(
    "vector", FIXTURE["methodTypeVectors"], ids=[vector["id"] for vector in FIXTURE["methodTypeVectors"]]
)
def test_method_type_vector(vector: dict[str, Any]) -> None:
    """ADR-006 D-8b: Ed25519 keys are read from ``Multikey`` or ``Ed25519VerificationKey2020`` methods only."""
    raw = _with_method_type(vector)
    if not vector["expected"]["documentValid"]:
        with pytest.raises(ValueError, match="type must be Multikey or Ed25519VerificationKey2020"):
            AgentDIDDocument.model_validate(raw)
        return
    doc = AgentDIDDocument.model_validate(raw)
    assert (
        verify_with_active_keys(doc, FIXTURE["payload"], vector["signatureHex"], vector["keyId"], "assertionMethod")
        is vector["expected"]["signatureValid"]
    )
