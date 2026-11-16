"""Shared composition contract vectors (fixtures/composition-contract-vectors.json, contract §7).

TypeScript parity: sdk/tests/CompositionContractVectors.test.ts.
"""

from __future__ import annotations

import json
import pathlib
from typing import Any

import pytest
from pydantic import ValidationError

from agent_did_sdk.core.agent_card import agent_card_signing_payload, parse_signed_agent_card, sign_agent_card
from agent_did_sdk.core.identity_composition import composition_reason_for_key
from agent_did_sdk.core.signer import LocalKeySigner
from agent_did_sdk.core.types import AgentDIDDocument
from agent_did_sdk.crypto.ed25519 import verify_ed25519
from agent_did_sdk.crypto.multibase import decode_public_key_multibase

_VECTORS: dict[str, Any] = json.loads(
    (pathlib.Path(__file__).resolve().parents[2] / "fixtures" / "composition-contract-vectors.json").read_text(
        encoding="utf-8"
    )
)


def _card_outcome(card: object) -> dict[str, Any]:
    """Format check, then every signature against the key of its kid: what a resolver-backed verifier does."""
    parsed = parse_signed_agent_card(card)
    if parsed is None:
        return {"expected": "format_drift"}
    for entry in parsed.signatures:
        key = _VECTORS["keys"].get(entry.key_id)
        if key is None or not verify_ed25519(
            entry.signature, entry.signing_input.encode("utf-8"), decode_public_key_multibase(key["publicKeyMultibase"])
        ):
            return {"expected": "tampered"}
    return {"expected": "ok", "did": parsed.did, "publishedKeyIds": list(parsed.published_key_ids)}


def _document_valid(document: object) -> bool:
    try:
        AgentDIDDocument.model_validate(document)
    except ValidationError:
        return False
    return True


async def test_signs_the_card_byte_for_byte() -> None:
    sign = _VECTORS["sign"]
    signer = LocalKeySigner(_VECTORS["keys"][sign["keyId"]]["seedHex"])
    signed = await sign_agent_card(sign["card"], signer, sign["keyId"])
    # JSON.stringify form: insertion order, no spaces
    assert json.dumps(signed, separators=(",", ":"), ensure_ascii=False) == json.dumps(
        sign["signedCard"], separators=(",", ":"), ensure_ascii=False
    )


@pytest.mark.parametrize("vector", _VECTORS["cards"], ids=lambda v: v["name"])
def test_card(vector: dict[str, Any]) -> None:
    expected = {name: value for name, value in vector.items() if name not in ("name", "card")}
    assert _card_outcome(vector["card"]) == expected


@pytest.mark.parametrize("vector", _VECTORS["payloads"], ids=lambda v: v["name"])
def test_payload(vector: dict[str, Any]) -> None:
    assert agent_card_signing_payload(vector["card"]) == vector["payload"]


@pytest.mark.parametrize("vector", _VECTORS["documents"], ids=lambda v: v["name"])
def test_document(vector: dict[str, Any]) -> None:
    assert _document_valid(vector["document"]) is vector["valid"]


@pytest.mark.parametrize("vector", _VECTORS["reasons"], ids=lambda v: v["name"])
def test_reason(vector: dict[str, Any]) -> None:
    document = AgentDIDDocument.model_validate(vector["document"])
    assert composition_reason_for_key(document, vector["keyId"]) == vector["expected"]
