"""Capabilities (RFC-001 §6.7, ADR-008 D-12a/b); parity: sdk/tests/Capabilities.test.ts."""

from __future__ import annotations

import base64
import copy
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

import pytest

from agent_did_sdk import (
    AgentDidClient,
    AgentDidClientOptions,
    VerifyHttpCapabilityInvocationParams,
    VerifyHttpRequestSignatureParams,
    root_capability_id,
)
from agent_did_sdk.core.capability import check_capability_chain, parse_capability_header, target_within
from agent_did_sdk.core.identity import AgentIdentity, AgentIdentityConfig
from agent_did_sdk.core.signer import LocalKeySigner
from agent_did_sdk.core.types import CreateAgentParams, SignHttpRequestParams
from agent_did_sdk.crypto.data_integrity import encode_eddsa_proof_value
from agent_did_sdk.crypto.hash import canonicalize_json

TARGET = "https://api.example.com/files"
FAR = "2099-01-01T00:00:00Z"


@dataclass
class Party:
    did: str
    key_id: str
    signer: LocalKeySigner
    private_key: str


@dataclass
class Setup:
    client: AgentDidClient
    identity: AgentIdentity
    owner: Party
    alice: Party
    bob: Party
    plain: Party


async def _setup(client: AgentDidClient | None = None) -> Setup:
    client = client or AgentDidClient()
    identity = AgentIdentity(AgentIdentityConfig(controller_signer=LocalKeySigner.generate()[0], client=client))

    async def make(name: str, relationships: list[str]) -> Party:
        created = await identity.create(
            CreateAgentParams(name=name, additional_verification_relationships=relationships)  # type: ignore[arg-type]
        )
        did = created.document.id
        return Party(did, f"{did}#key-1", LocalKeySigner(created.agent_private_key), created.agent_private_key)

    return Setup(
        client=client,
        identity=identity,
        owner=await make("Owner", ["capabilityDelegation"]),
        alice=await make("Alice", ["capabilityDelegation", "capabilityInvocation"]),
        bob=await make("Bob", ["capabilityInvocation"]),
        plain=await make("Plain", []),
    )


async def test_delegates_from_the_root_and_verifies_the_chain() -> None:
    s = await _setup()
    capability = await s.client.create_capability(
        invocation_target=TARGET,
        controller=s.alice.did,
        expires=FAR,
        allowed_action=["GET", "POST"],
        verification_method_id=s.owner.key_id,
        signer=s.owner.signer,
    )
    assert capability["parentCapability"] == root_capability_id(TARGET)
    assert capability["parentCapability"] == "urn:zcap:root:https%3A%2F%2Fapi.example.com%2Ffiles"
    assert capability["proof"]["capabilityChain"] == [capability["parentCapability"]]
    assert capability["proof"]["proofPurpose"] == "capabilityDelegation"

    result = await s.client.verify_capability_chain(capability, root_controllers={TARGET: [s.owner.did]})
    assert result.ok
    assert result.capability == capability
    assert result.controller == s.alice.did
    assert result.allowed_action == ("GET", "POST")
    assert result.delegators == (s.owner.did,)


async def test_verifies_a_chain_of_three_with_attenuation() -> None:
    s = await _setup()
    first = await s.client.create_capability(
        invocation_target=TARGET, controller=s.alice.did, expires=FAR,
        verification_method_id=s.owner.key_id, signer=s.owner.signer,
    )
    second = await s.client.create_capability(
        invocation_target=f"{TARGET}/reports", controller=s.alice.did, expires="2098-01-01T00:00:00Z",
        allowed_action=["GET"], parent_capability=first,
        verification_method_id=s.alice.key_id, signer=s.alice.signer,
    )
    third = await s.client.create_capability(
        invocation_target=f"{TARGET}/reports/2026", controller=s.bob.did, expires="2097-01-01T00:00:00Z",
        parent_capability=second, verification_method_id=s.alice.key_id, signer=s.alice.signer,
    )
    assert third["proof"]["capabilityChain"] == [first["parentCapability"], first["id"], second]
    roots = {TARGET: [s.owner.did]}
    result = await s.client.verify_capability_chain(third, root_controllers=roots)
    assert result.ok and result.controller == s.bob.did and result.allowed_action == ("GET",)
    assert result.delegators == (s.owner.did, s.alice.did, s.alice.did)
    too_long = await s.client.verify_capability_chain(third, root_controllers=roots, max_chain_length=2)
    assert (too_long.reason, too_long.capability_id) == ("chain_too_long", third["id"])


async def test_refuses_to_widen_the_parent_or_sign_for_someone_else() -> None:
    s = await _setup()
    parent = await s.client.create_capability(
        invocation_target=TARGET, controller=s.alice.did, expires="2098-01-01T00:00:00Z", allowed_action=["GET"],
        verification_method_id=s.owner.key_id, signer=s.owner.signer,
    )
    base: dict[str, Any] = {
        "controller": s.bob.did, "parent_capability": parent,
        "verification_method_id": s.alice.key_id, "signer": s.alice.signer,
    }
    with pytest.raises(ValueError, match="widen"):
        await s.client.create_capability(
            **base, invocation_target="https://api.example.com/other", expires="2097-01-01T00:00:00Z"
        )
    with pytest.raises(ValueError, match="widen"):
        await s.client.create_capability(**base, invocation_target=TARGET, expires=FAR)
    with pytest.raises(ValueError, match="widen"):
        await s.client.create_capability(
            **base, invocation_target=TARGET, expires="2097-01-01T00:00:00Z", allowed_action=["DELETE"]
        )
    with pytest.raises(ValueError, match="controller"):
        await s.client.create_capability(
            **{**base, "verification_method_id": s.owner.key_id, "signer": s.owner.signer},
            invocation_target=TARGET, expires="2097-01-01T00:00:00Z",
        )


async def test_refuses_a_delegation_key_not_under_capability_delegation() -> None:
    s = await _setup()
    with pytest.raises(ValueError, match="capabilityDelegation"):
        await s.client.create_capability(
            invocation_target=TARGET, controller=s.alice.did, expires=FAR,
            verification_method_id=s.bob.key_id, signer=s.bob.signer,
        )


async def test_rejects_an_unknown_or_wrong_root_controller() -> None:
    s = await _setup()
    capability = await s.client.create_capability(
        invocation_target=TARGET, controller=s.alice.did, expires=FAR,
        verification_method_id=s.owner.key_id, signer=s.owner.signer,
    )
    unknown = await s.client.verify_capability_chain(capability, root_controllers={})
    assert (unknown.reason, unknown.capability_id) == ("root_controller_unknown", capability["id"])
    wrong = await s.client.verify_capability_chain(capability, root_controllers={TARGET: [s.bob.did]})
    assert (wrong.reason, wrong.capability_id) == ("delegator_mismatch", capability["id"])


async def test_rejects_tampering_expiry_and_wrong_purpose() -> None:
    s = await _setup()
    roots = {TARGET: [s.owner.did, s.plain.did]}
    capability = await s.client.create_capability(
        invocation_target=TARGET, controller=s.alice.did, expires="2030-01-01T00:00:00Z",
        verification_method_id=s.owner.key_id, signer=s.owner.signer,
    )
    tampered = copy.deepcopy(capability)
    tampered["controller"] = s.plain.did
    assert (await s.client.verify_capability_chain(tampered, root_controllers=roots)).reason == "signature_invalid"

    later = AgentDidClient(AgentDidClientOptions(clock=lambda: datetime(2031, 1, 1, tzinfo=timezone.utc)))
    assert (await later.verify_capability_chain(capability, root_controllers=roots)).reason == "expired"

    forged = copy.deepcopy(capability)
    forged["proof"]["verificationMethod"] = s.plain.key_id
    assert (await s.client.verify_capability_chain(forged, root_controllers=roots)).reason == "key_purpose_violation"
    forged["proof"]["verificationMethod"] = f"{s.plain.did}#key-9"
    assert (await s.client.verify_capability_chain(forged, root_controllers=roots)).reason == "key_not_authorized"


def test_checks_attenuation_in_a_chain_it_did_not_create() -> None:
    owner, alice, bob = "did:webvh:owner:example.com", "did:webvh:alice:example.com", "did:webvh:bob:example.com"
    root_id = root_capability_id(TARGET)

    def proof(chain: list[Any], key_id: str) -> dict[str, Any]:
        return {
            "type": "DataIntegrityProof", "cryptosuite": "eddsa-jcs-2022", "created": "2026-11-15T00:00:00Z",
            "verificationMethod": key_id, "proofPurpose": "capabilityDelegation", "capabilityChain": chain,
            "proofValue": encode_eddsa_proof_value(bytes(64)),
        }

    first = {
        "@context": ["https://w3id.org/zcap/v1"], "id": "urn:uuid:00000000-0000-4000-8000-000000000001",
        "parentCapability": root_id, "invocationTarget": f"{TARGET}/a", "controller": alice, "allowedAction": ["GET"],
        "expires": "2098-01-01T00:00:00Z", "proof": proof([root_id], f"{owner}#key-1"),
    }
    second = {
        "@context": ["https://w3id.org/zcap/v1"], "id": "urn:uuid:00000000-0000-4000-8000-000000000002",
        "parentCapability": first["id"], "invocationTarget": f"{TARGET}/b", "controller": bob,
        "expires": "2097-01-01T00:00:00Z", "proof": proof([root_id, first], f"{alice}#key-1"),
    }
    now = 1_794_700_800_000
    roots = {TARGET: [owner]}

    def reason(capability: dict[str, Any]) -> str | None:
        return getattr(check_capability_chain(capability, roots, now), "reason", None)

    assert reason(second) == "attenuation_violation"
    ok = check_capability_chain({**second, "invocationTarget": f"{TARGET}/a/b"}, roots, now)
    assert getattr(ok, "allowed_action", None) == ("GET",)
    assert reason({**second, "invocationTarget": f"{TARGET}/a/b", "allowedAction": ["GET", "PUT"]}) == (
        "attenuation_violation"
    )
    assert reason({**second, "invocationTarget": f"{TARGET}/a/b", "expires": FAR}) == "attenuation_violation"
    assert reason({**second, "parentCapability": "urn:uuid:00000000-0000-4000-8000-000000000009"}) == (
        "malformed_capability"
    )
    assert reason({**first, "proof": proof(["urn:uuid:x"], f"{owner}#key-1"), "parentCapability": "urn:uuid:x"}) == (
        "malformed_capability"
    )
    assert reason({**first, "extra": 1}) == "malformed_capability"
    assert reason({**first, "proof": {**first["proof"], "proofPurpose": "assertionMethod"}}) == "unsupported_proof"
    assert reason({**first, "invocationTarget": f"{TARGET}?q=1"}) == "malformed_capability"


def test_matches_targets_only_on_a_path_boundary() -> None:
    assert target_within(TARGET, TARGET)
    assert target_within(f"{TARGET}/x", TARGET)
    assert not target_within(f"{TARGET}x", TARGET)
    assert not target_within(f"{TARGET}/", TARGET)
    assert target_within("https://api.example.com/a", "https://api.example.com/")


async def _invocation(
    method: str = "GET", url: str = f"{TARGET}/reports"
) -> tuple[Setup, dict[str, Any], dict[str, Any]]:
    s = await _setup()
    capability = await s.client.create_capability(
        invocation_target=TARGET, controller=s.bob.did, expires=FAR, allowed_action=["GET"],
        verification_method_id=s.owner.key_id, signer=s.owner.signer,
    )
    headers = await s.identity.sign_http_request(SignHttpRequestParams(
        method=method, url=url, agent_did=s.bob.did, agent_private_key=s.bob.private_key,
        verification_method_id=s.bob.key_id, capability=capability,
    ))
    return s, capability, {"method": method, "url": url, "headers": headers}


def _params(request: dict[str, Any], s: Setup) -> VerifyHttpCapabilityInvocationParams:
    return VerifyHttpCapabilityInvocationParams(**request, root_controllers={TARGET: [s.owner.did]})


async def test_accepts_an_invocation_and_records_the_nonce() -> None:
    s, capability, request = await _invocation()
    assert '"agent-did-capability";key="sig1"' in request["headers"]["Signature-Input"]
    assert parse_capability_header(request["headers"]["Agent-DID-Capability"], "sig1") == capability
    result = await s.client.verify_http_capability_invocation(_params(request, s))
    assert result.ok and result.did == s.bob.did and result.key_id == s.bob.key_id
    assert result.capability == capability and result.allowed_action == ("GET",)
    assert result.delegators == (s.owner.did,)
    assert (await s.client.verify_http_capability_invocation(_params(request, s))).reason == "nonce_replayed"


async def test_is_also_an_identity_signature_when_the_key_is_also_under_assertion_method() -> None:
    s, _capability, request = await _invocation()
    result = await s.client.verify_http_request_signature_detailed(VerifyHttpRequestSignatureParams(**request))
    assert result.ok and result.did == s.bob.did


async def test_rejects_an_invocation_key_not_under_capability_invocation() -> None:
    s = await _setup()
    capability = await s.client.create_capability(
        invocation_target=TARGET, controller=s.plain.did, expires=FAR,
        verification_method_id=s.owner.key_id, signer=s.owner.signer,
    )
    headers = await s.identity.sign_http_request(SignHttpRequestParams(
        method="GET", url=TARGET, agent_did=s.plain.did, agent_private_key=s.plain.private_key,
        verification_method_id=s.plain.key_id, capability=capability,
    ))
    result = await s.client.verify_http_capability_invocation(
        VerifyHttpCapabilityInvocationParams(
            method="GET", url=TARGET, headers=headers, root_controllers={TARGET: [s.owner.did]}
        )
    )
    assert result.reason == "keyid_not_authorized"


async def test_rejects_a_method_outside_allowed_action_and_a_url_outside_the_target() -> None:
    s, capability, request = await _invocation("POST")
    result = await s.client.verify_http_capability_invocation(_params(request, s))
    assert (result.reason, result.capability_id) == ("action_not_allowed", capability["id"])
    s, capability, request = await _invocation("GET", "https://api.example.com/filesystem")
    result = await s.client.verify_http_capability_invocation(_params(request, s))
    assert (result.reason, result.capability_id) == ("target_mismatch", capability["id"])


async def test_accepts_a_query_on_a_url_within_the_target() -> None:
    s, _capability, request = await _invocation("GET", f"{TARGET}/reports?year=2026")
    assert (await s.client.verify_http_capability_invocation(_params(request, s))).ok


async def test_rejects_a_request_without_a_covered_capability_and_a_foreign_invoker() -> None:
    s, capability, _request = await _invocation()
    url = f"{TARGET}/reports"
    plain_headers = await s.identity.sign_http_request(SignHttpRequestParams(
        method="GET", url=url, agent_did=s.alice.did, agent_private_key=s.alice.private_key,
        verification_method_id=s.alice.key_id,
    ))
    request = {"method": "GET", "url": url, "headers": plain_headers}
    assert (await s.client.verify_http_capability_invocation(_params(request, s))).reason == "capability_missing"
    with pytest.raises(ValueError, match="held by"):
        await s.identity.sign_http_request(SignHttpRequestParams(
            method="GET", url=url, agent_did=s.alice.did, agent_private_key=s.alice.private_key,
            verification_method_id=s.alice.key_id, capability=capability,
        ))
    encoded = base64.b64encode(json.dumps(capability).encode()).decode()
    stolen = {**request, "headers": {**plain_headers, "Agent-DID-Capability": f"sig1=:{encoded}:"}}
    assert (await s.client.verify_http_capability_invocation(_params(stolen, s))).reason == "capability_missing"


async def test_rejects_an_oversized_capability_field() -> None:
    s, _capability, request = await _invocation()
    big = {**request, "headers": {**request["headers"], "Agent-DID-Capability": f"sig1=:{'A' * 9000}:"}}
    assert (await s.client.verify_http_capability_invocation(_params(big, s))).reason == "capability_too_large"


async def test_rejects_a_capability_changed_in_transit() -> None:
    s, capability, request = await _invocation()
    changed = copy.deepcopy(capability)
    changed["allowedAction"] = ["GET", "DELETE"]
    encoded = base64.b64encode(canonicalize_json(changed).encode()).decode()
    headers = {**request["headers"], "Agent-DID-Capability": f"sig1=:{encoded}:"}
    result = await s.client.verify_http_capability_invocation(_params({**request, "headers": headers}, s))
    assert result.reason == "signature_invalid"
