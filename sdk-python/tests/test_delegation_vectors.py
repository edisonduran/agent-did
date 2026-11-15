"""Shared vectors of capabilities and OAuth client assertions (fixtures/delegation-vectors.json, RFC-001 §6.7, §6.8,
ADR-008 D-12f).

TypeScript parity: sdk/tests/DelegationVectors.test.ts.
"""

from __future__ import annotations

import base64
import json
import pathlib
from datetime import datetime
from typing import Any

import pytest

from agent_did_sdk import create_client_assertion, root_capability_id
from agent_did_sdk.core.agent_card import did_of_key_id
from agent_did_sdk.core.capability import (
    CAPABILITY_HEADER_MISSING,
    CapabilityChainRejection,
    action_allowed,
    check_capability_chain,
    parse_capability_header,
    target_within,
)
from agent_did_sdk.core.http_signatures import HttpRequestLike, build_signature_base, parse_signature_input_header
from agent_did_sdk.core.oauth_client import parse_client_assertion
from agent_did_sdk.core.signer import LocalKeySigner
from agent_did_sdk.crypto.data_integrity import (
    eddsa_jcs_2022_hash_data,
    encode_eddsa_proof_value,
    verify_eddsa_jcs_2022_proof,
)
from agent_did_sdk.crypto.ed25519 import verify_ed25519
from agent_did_sdk.crypto.multibase import decode_public_key_multibase

_VECTORS: dict[str, Any] = json.loads(
    (pathlib.Path(__file__).resolve().parents[2] / "fixtures" / "delegation-vectors.json").read_text(encoding="utf-8")
)
_CAPABILITIES: dict[str, Any] = _VECTORS["capabilities"]
_ASSERTIONS: dict[str, Any] = _VECTORS["clientAssertions"]


def _public_key(key_id: str) -> bytes | None:
    key = _VECTORS["keys"].get(key_id)
    return None if key is None else decode_public_key_multibase(key["publicKeyMultibase"])


def _millis(value: str) -> int:
    return int(datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp() * 1000)


def _chain_outcome(vector: dict[str, Any]) -> dict[str, Any]:
    """check_capability_chain, then per link the delegator check and the proof with the verificationMethod key."""
    checked = check_capability_chain(
        vector["capability"], vector["rootControllers"], _millis(vector["now"]), vector["maxChainLength"]
    )
    if isinstance(checked, CapabilityChainRejection):
        outcome: dict[str, Any] = {"expected": checked.reason}
        if checked.capability_id is not None:
            outcome["capabilityId"] = checked.capability_id
        return outcome
    delegators: list[str] = []
    for index, item in enumerate(checked.capabilities):
        delegator = did_of_key_id(item["proof"]["verificationMethod"])
        allowed = (
            delegator in checked.root_controllers
            if index == 0
            else checked.capabilities[index - 1]["controller"] == delegator
        )
        if not allowed:
            return {"expected": "delegator_mismatch", "capabilityId": item["id"]}
        key = _public_key(item["proof"]["verificationMethod"])
        if key is None or not verify_eddsa_jcs_2022_proof(item, key):
            return {"expected": "signature_invalid", "capabilityId": item["id"]}
        assert delegator is not None
        delegators.append(delegator)
    result: dict[str, Any] = {"expected": "ok", "delegators": delegators}
    if checked.allowed_action is not None:
        result["allowedAction"] = list(checked.allowed_action)
    result["controller"] = checked.capabilities[-1]["controller"]
    return result


def test_derives_the_root_id() -> None:
    assert root_capability_id("https://api.example.com/files") == _CAPABILITIES["rootId"]


@pytest.mark.parametrize("vector", _CAPABILITIES["sign"], ids=lambda v: v["name"])
async def test_signs_the_capability_byte_for_byte(vector: dict[str, Any]) -> None:
    signer = LocalKeySigner(_VECTORS["keys"][vector["keyId"]]["seedHex"])
    signature = bytes.fromhex(await signer.sign(eddsa_jcs_2022_hash_data(vector["unsigned"], vector["proofOptions"])))
    assert encode_eddsa_proof_value(signature) == vector["proofValue"]
    signed = {**vector["unsigned"], "proof": {**vector["proofOptions"], "proofValue": vector["proofValue"]}}
    key = _public_key(vector["keyId"])
    assert key is not None and verify_eddsa_jcs_2022_proof(signed, key)


@pytest.mark.parametrize("vector", _CAPABILITIES["chains"], ids=lambda v: v["name"])
def test_chain(vector: dict[str, Any]) -> None:
    excluded = ("name", "capability", "rootControllers", "now", "maxChainLength")
    expected = {name: value for name, value in vector.items() if name not in excluded}
    assert _chain_outcome(vector) == expected


@pytest.mark.parametrize("vector", _CAPABILITIES["targets"], ids=lambda v: f"{v['method']} {v['url']}")
def test_target(vector: dict[str, Any]) -> None:
    matches = target_within(vector["url"].split("?", 1)[0], vector["invocationTarget"]) and action_allowed(
        vector["method"], vector.get("allowedAction")
    )
    assert matches is vector["matches"]


@pytest.mark.parametrize("vector", _CAPABILITIES["headers"], ids=lambda v: v["name"])
def test_header(vector: dict[str, Any]) -> None:
    parsed = parse_capability_header(vector["value"], "sig1")
    if vector["expected"] == "capability":
        assert parsed == vector["capability"]
    else:
        kind = "missing" if parsed is CAPABILITY_HEADER_MISSING else "malformed" if parsed is None else "capability"
        assert kind == vector["expected"]


def test_rebuilds_the_signature_base_of_an_invocation_and_verifies_it() -> None:
    invocation = _CAPABILITIES["invocation"]
    request = invocation["request"]
    headers = {key.lower(): value for key, value in request["headers"].items()}
    signature_input = parse_signature_input_header(headers["signature-input"])["sig1"]
    base = build_signature_base(
        HttpRequestLike(method=request["method"], url=request["url"], headers=headers), signature_input
    )
    assert base == invocation["signatureBase"]
    signature = base64.b64decode(headers["signature"][len("sig1=:") : -1])
    key = _public_key(invocation["keyId"])
    assert key is not None and verify_ed25519(signature, base.encode("utf-8"), key)
    capability = parse_capability_header(headers["agent-did-capability"], "sig1")
    assert isinstance(capability, dict) and capability["id"] == invocation["capabilityId"]


@pytest.mark.parametrize("vector", _ASSERTIONS["sign"], ids=lambda v: v["name"])
async def test_signs_the_assertion_byte_for_byte(vector: dict[str, Any]) -> None:
    params = vector["params"]
    signer = LocalKeySigner(_VECTORS["keys"][params["verificationMethodId"]]["seedHex"])
    assertion = await create_client_assertion(
        client_id=params["clientId"],
        issuer=params["issuer"],
        verification_method_id=params["verificationMethodId"],
        signer=signer,
        issued_at=params["issuedAt"],
        jti=params["jti"],
        lifetime_seconds=params["lifetimeSeconds"],
        jws_alg=params["jwsAlg"],
    )
    assert assertion == vector["assertion"]


@pytest.mark.parametrize("vector", _ASSERTIONS["verify"], ids=lambda v: v["name"])
def test_verify_assertion(vector: dict[str, Any]) -> None:
    parsed = parse_client_assertion(
        vector["assertion"],
        client_id=vector["clientId"],
        issuer=vector["issuer"],
        did=vector["did"],
        now_seconds=vector["now"],
        max_clock_skew_seconds=vector["maxClockSkewSeconds"],
    )
    if isinstance(parsed, str):
        outcome = parsed
    else:
        key = _public_key(parsed.key_id)
        valid = key is not None and verify_ed25519(parsed.signature, parsed.signing_input.encode("ascii"), key)
        outcome = "ok" if valid else "signature_invalid"
    assert outcome == vector["expected"]
