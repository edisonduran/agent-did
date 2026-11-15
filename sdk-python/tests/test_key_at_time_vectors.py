"""Runs ``fixtures/key-at-time-vectors.json`` (RFC-001 §6.2.2).

The TypeScript SDK generates the file and runs it in ``sdk/tests/KeyAtTimeVectors.test.ts``.
"""

from __future__ import annotations

import json
import pathlib
from typing import Any

import pytest
from nacl.signing import SigningKey

from agent_did_sdk import (
    AgentDidClient,
    DidWebvhError,
    KeyAtTimeResult,
    VerifySignatureAtTimeResult,
    check_did_webvh_key_at_time,
)
from agent_did_sdk.core.signer import LocalKeySigner
from agent_did_sdk.crypto.multibase import encode_public_key_multibase
from agent_did_sdk.verification.key_at_time import parse_rfc3339_millis
from agent_did_sdk.webvh.adapter import create_did_webvh_log

FIXTURE: dict[str, Any] = json.loads(
    (pathlib.Path(__file__).resolve().parents[2] / "fixtures" / "key-at-time-vectors.json").read_text(
        encoding="utf-8"
    )
)
DID: str = FIXTURE["did"]
PRIVATE_KEYS = {"key-1": FIXTURE["inputs"]["key1PrivateKeyHex"], "key-2": FIXTURE["inputs"]["key2PrivateKeyHex"]}


def _key_id(key: str) -> str:
    return f"{DID}#{key}"


def _public_key_multibase(key: str) -> str:
    return encode_public_key_multibase(bytes(SigningKey(bytes.fromhex(PRIVATE_KEYS[key])).verify_key))


@pytest.mark.parametrize("vector", FIXTURE["vectors"], ids=[vector["id"] for vector in FIXTURE["vectors"]])
async def test_vector(vector: dict[str, Any]) -> None:
    log = FIXTURE["logs"][vector["log"]]
    expected = vector["expected"]
    options: dict[str, Any] = {
        "key_id": _key_id(vector["key"]),
        "required_purpose": vector["requiredPurpose"],
        "stated_time": vector["statedTime"],
        "trusted_time_not_after": vector.get("trustedTimeNotAfter"),
    }

    result: KeyAtTimeResult = await check_did_webvh_key_at_time(log, did=DID, **options)
    assert result.status == expected["status"]
    assert result.key_id == _key_id(vector["key"])
    if result.status == "authorized":
        assert result.basis == expected["basis"]
        assert result.public_key_multibase == _public_key_multibase(vector["key"])
    elif result.status == "not_authorized":
        assert result.reason == expected["reason"]
        assert list(result.found_in) == expected["foundIn"]
    else:
        assert result.reason == expected["reason"]
        assert result.boundary_time == expected["boundaryTime"]
        assert result.boundary_version_id is not None
        assert result.boundary_version_id.split("-")[0] == str(expected["boundaryVersionNumber"])

    client = AgentDidClient()
    await client.import_did_webvh_history(log)
    signer = ("key-2" if vector["key"] == "key-1" else "key-1") if vector.get("wrongSignature") else vector["key"]
    key_id = options.pop("key_id")
    verified: VerifySignatureAtTimeResult = await client.verify_signature_at_time(
        DID, FIXTURE["inputs"]["payload"], FIXTURE["signatures"][signer], key_id, **options
    )
    assert verified.status == expected["signature"]
    if verified.status == "invalid":
        assert verified.reason == expected["signatureReason"]


async def test_rejects_a_log_of_another_did() -> None:
    with pytest.raises(DidWebvhError):
        await check_did_webvh_key_at_time(
            FIXTURE["logs"]["rotated"],
            key_id=_key_id("key-2"),
            stated_time="2026-01-03T12:00:00Z",
            did="did:webvh:QmOther:example.com",
        )


async def test_rejects_a_tampered_log() -> None:
    tampered = FIXTURE["logs"]["rotated"].replace('"time-bot"', '"evil-bot"')
    with pytest.raises(DidWebvhError):
        await check_did_webvh_key_at_time(tampered, key_id=_key_id("key-2"), stated_time="2026-01-03T12:00:00Z")


async def test_raises_on_unreadable_time_evidence() -> None:
    with pytest.raises(ValueError):
        await check_did_webvh_key_at_time(
            FIXTURE["logs"]["rotated"],
            key_id=_key_id("key-2"),
            stated_time="2026-01-03T12:00:00Z",
            trusted_time_not_after="soon",
        )


async def test_is_indeterminate_without_a_did_webvh_log_in_the_client() -> None:
    result = await AgentDidClient().verify_signature_at_time(
        DID,
        FIXTURE["inputs"]["payload"],
        FIXTURE["signatures"]["key-2"],
        _key_id("key-2"),
        stated_time="2026-01-03T12:00:00Z",
    )
    assert result == VerifySignatureAtTimeResult(
        status="indeterminate",
        key=KeyAtTimeResult(status="indeterminate", key_id=_key_id("key-2"), reason="history_unavailable"),
    )


async def test_defaults_to_assertion_method() -> None:
    result = await check_did_webvh_key_at_time(
        FIXTURE["logs"]["rotated"], key_id=_key_id("key-2"), stated_time="2026-01-03T12:00:00Z"
    )
    assert result.status == "authorized"


async def _log_with_key_type(key_type: str) -> tuple[str, str]:
    """A one-entry log whose key-1 method has ``key_type`` (same document as the TypeScript test)."""
    created = await create_did_webvh_log(
        domain=FIXTURE["inputs"]["domain"],
        path_segments=["fleet", "type-bot"],
        signer=LocalKeySigner(FIXTURE["inputs"]["controllerPrivateKeyHex"]),
        created=FIXTURE["inputs"]["created"],
        document={
            "@context": ["https://www.w3.org/ns/did/v1", "https://agent-did.org/v1"],
            "id": "{DID}",
            "controller": "{DID}",
            "created": FIXTURE["inputs"]["created"],
            "updated": FIXTURE["inputs"]["created"],
            "agentMetadata": {"name": "type-bot", "version": "1.0.0"},
            "verificationMethod": [
                {
                    "id": "{DID}#key-1",
                    "type": key_type,
                    "controller": "{DID}",
                    "publicKeyMultibase": _public_key_multibase("key-1"),
                }
            ],
            "authentication": ["{DID}#key-1"],
            "assertionMethod": ["{DID}#key-1"],
        },
    )
    return created.log, created.did


async def test_reads_an_rc4_ed25519_verification_key_2020_key() -> None:
    """ADR-006 D-8b: rc.4 logs with Ed25519VerificationKey2020 methods stay valid."""
    log, did = await _log_with_key_type("Ed25519VerificationKey2020")
    result = await check_did_webvh_key_at_time(log, key_id=f"{did}#key-1", stated_time="2026-01-02T00:00:00Z")
    assert result.status == "authorized"


async def test_never_authorizes_a_public_key_multibase_key_of_another_type() -> None:
    log, did = await _log_with_key_type("JsonWebKey2020")
    result = await check_did_webvh_key_at_time(log, key_id=f"{did}#key-1", stated_time="2026-01-02T00:00:00Z")
    assert result.status == "not_authorized"
    assert result.reason == "key_not_found"


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("2026-01-03T00:00:00Z", 1767398400000),
        ("2026-01-03T01:00:00+01:00", 1767398400000),
        ("2026-01-03T00:00:00.123456789z", 1767398400123),
        ("2024-02-29T00:00:00Z", 1709164800000),
        ("2026-02-29T00:00:00Z", None),
        ("0000-01-01T00:00:00Z", None),
        ("2026-01-03 00:00:00Z", None),
        ("2026-01-03T24:00:00Z", None),
        ("2026-01-03T00:00:00+24:00", None),
        (1767398400, None),
    ],
)
def test_parses_rfc3339(value: object, expected: int | None) -> None:
    assert parse_rfc3339_millis(value) == expected
