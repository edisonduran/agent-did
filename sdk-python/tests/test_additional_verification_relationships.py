"""``CreateAgentParams.additional_verification_relationships`` (RFC-001 §6.2.1.3).

An opt-in that lists the agent key under ``capabilityDelegation`` / ``capabilityInvocation``. The TypeScript
SDK runs the same cases in ``sdk/tests/AdditionalVerificationRelationships.test.ts``.
"""

from __future__ import annotations

from typing import Any

import pytest
from pydantic import ValidationError

from agent_did_sdk import (
    ADDITIONAL_VERIFICATION_RELATIONSHIPS,
    REQUIRED_RELATIONSHIP_BY_ARTIFACT,
    AgentDidClient,
    AgentDIDDocument,
    CreateAgentParams,
    IdentityCompositionError,
    LocalKeySigner,
    assert_key_purpose,
    required_relationship_for,
)
from agent_did_sdk.core.identity import AgentIdentity, AgentIdentityConfig
from agent_did_sdk.lifecycle.documents import build_rotated_document
from agent_did_sdk.webvh.adapter import resolve_did_webvh_log

BASE: dict[str, Any] = {
    "name": "DelegatingBot",
    "core_model": "gpt-4o-mini",
    "system_prompt": "You are a test assistant.",
}


def _params(**overrides: Any) -> CreateAgentParams:
    return CreateAgentParams(**{**BASE, **overrides})


def _setup() -> tuple[AgentDidClient, AgentIdentity]:
    client = AgentDidClient()
    identity = AgentIdentity(AgentIdentityConfig(controller_signer=LocalKeySigner.generate()[0], client=client))
    return client, identity


def _dumped(document: AgentDIDDocument) -> dict[str, Any]:
    return document.model_dump_jsonld()


def test_exports_the_accepted_relationships_in_document_order() -> None:
    assert ADDITIONAL_VERIFICATION_RELATIONSHIPS == ("capabilityDelegation", "capabilityInvocation")


@pytest.mark.parametrize("requested", [None, []])
async def test_leaves_the_document_as_before(requested: list[str] | None) -> None:
    _, identity = _setup()
    document = (await identity.create(_params(additional_verification_relationships=requested))).document
    dumped = _dumped(document)
    assert "capabilityDelegation" not in dumped
    assert "capabilityInvocation" not in dumped
    assert dumped["authentication"] == [f"{document.id}#key-1"]
    assert dumped["assertionMethod"] == [f"{document.id}#key-1"]


async def test_lists_the_agent_key_under_the_requested_relationships_in_a_fixed_order() -> None:
    client, identity = _setup()
    params = CreateAgentParams(
        **BASE,
        additional_verification_relationships=["capabilityInvocation", "capabilityDelegation", "capabilityInvocation"],
    )
    document = (await identity.create(params)).document
    key_id = f"{document.id}#key-1"
    dumped = _dumped(document)
    assert dumped["capabilityDelegation"] == [key_id]
    assert dumped["capabilityInvocation"] == [key_id]
    assert [key for key in dumped if key.startswith("capability")] == ["capabilityDelegation", "capabilityInvocation"]

    # The relationships are part of the signed genesis entry of the log.
    resolved = await resolve_did_webvh_log(client.export_did_webvh_history(document.id))
    assert resolved.state["capabilityDelegation"] == [key_id]
    assert resolved.state["capabilityInvocation"] == [key_id]


async def test_lets_a_created_agent_sign_a_delegation_that_a_verifier_accepts() -> None:
    client, identity = _setup()
    result = await identity.create(_params(additional_verification_relationships=["capabilityDelegation"]))
    signature = await identity.sign_message("delegation", result.agent_private_key)
    did = result.document.id

    assert await client.verify_signature(
        did, "delegation", signature, None, REQUIRED_RELATIONSHIP_BY_ARTIFACT["delegation"]
    ) is True
    assert await client.verify_signature(
        did, "delegation", signature, None, REQUIRED_RELATIONSHIP_BY_ARTIFACT["invocation"]
    ) is False


async def test_rejects_a_delegation_from_an_agent_created_without_the_option() -> None:
    client, identity = _setup()
    result = await identity.create(CreateAgentParams(**BASE))
    signature = await identity.sign_message("delegation", result.agent_private_key)
    did = result.document.id

    assert await client.verify_signature(
        did, "delegation", signature, None, REQUIRED_RELATIONSHIP_BY_ARTIFACT["delegation"]
    ) is False
    with pytest.raises(IdentityCompositionError):
        assert_key_purpose(f"{did}#key-1", result.document, required_relationship_for("delegation"))


async def test_applies_to_the_legacy_did_agent_profile() -> None:
    _, identity = _setup()
    params = _params(did_method="agent", additional_verification_relationships=["capabilityDelegation"])
    document = (await identity.create(params)).document
    assert document.capability_delegation == [f"{document.id}#key-1"]
    assert document.capability_invocation is None


@pytest.mark.parametrize("relationship", ["assertionMethod", "keyAgreement", "authentication", ""])
def test_rejects_an_unsupported_relationship_in_the_params(relationship: str) -> None:
    with pytest.raises(ValidationError):
        CreateAgentParams(**BASE, additional_verification_relationships=[relationship])


@pytest.mark.parametrize("requested", [["assertionMethod"], ["keyAgreement"], "capabilityDelegation"])
async def test_rejects_an_unsupported_value_before_creating_anything(requested: Any) -> None:
    # model_construct skips validation, as a caller building the params by hand could.
    client, identity = _setup()
    params = CreateAgentParams.model_construct(
        **BASE,
        did_method="webvh",
        additional_verification_relationships=requested,
    )
    with pytest.raises(ValueError):
        await identity.create(params)
    assert client._did_webvh_log_store == {}
    assert client._bootstrap_controllers == {}


async def test_carries_the_relationships_over_to_the_new_key_on_rotation() -> None:
    client, identity = _setup()
    document = (
        await identity.create(CreateAgentParams(**BASE, additional_verification_relationships=["capabilityDelegation"]))
    ).document
    rotated = await client.rotate_verification_method(document.id)
    new_key_id = rotated.verification_method_id

    assert rotated.document.capability_delegation == [f"{document.id}#key-1", new_key_id]
    assert rotated.document.capability_invocation is None

    signature = await identity.sign_message("delegation", rotated.agent_private_key)
    assert await client.verify_signature(
        document.id, "delegation", signature, new_key_id, REQUIRED_RELATIONSHIP_BY_ARTIFACT["delegation"]
    ) is True


async def test_does_not_add_a_capability_relationship_on_rotation_when_the_document_had_none() -> None:
    client, identity = _setup()
    document = (await identity.create(CreateAgentParams(**BASE))).document
    rotated = await client.rotate_verification_method(document.id)
    dumped = _dumped(rotated.document)
    assert "capabilityDelegation" not in dumped
    assert "capabilityInvocation" not in dumped


def test_does_not_give_the_new_key_a_relationship_that_names_only_another_party_key() -> None:
    did = "did:example:rotation"
    existing = AgentDIDDocument.model_validate(
        {
            "@context": ["https://www.w3.org/ns/did/v1", "https://agent-did.org/v1"],
            "id": did,
            "controller": did,
            "created": "2026-11-07T00:00:00.000Z",
            "updated": "2026-11-07T00:00:00.000Z",
            "agentMetadata": {
                "name": "RotationAgent",
                "version": "1.0.0",
                "coreModelHash": "hash://sha256/00",
                "systemPromptHash": "hash://sha256/00",
            },
            "verificationMethod": [
                {
                    "id": f"{did}#key-1",
                    "type": "Ed25519VerificationKey2020",
                    "controller": did,
                    "publicKeyMultibase": "z6Mk",
                }
            ],
            "authentication": [f"{did}#key-1"],
            "assertionMethod": [f"{did}#key-1"],
            "capabilityDelegation": ["did:example:other#key-1"],
        }
    )

    document, vm_id, _ = build_rotated_document(did, existing, "2026-11-07T00:00:01.000Z")
    assert document.capability_delegation == ["did:example:other#key-1"]
    assert vm_id not in (document.capability_delegation or [])
