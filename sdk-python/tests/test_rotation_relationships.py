"""A rotated-out key leaves every verification relationship; malformed input is a failed verification.

Parity: ``sdk/tests/RotationRelationships.test.ts``.
"""

from __future__ import annotations

import pytest
from nacl.signing import VerifyKey
from pydantic import ValidationError

from agent_did_sdk import AgentDidClient
from agent_did_sdk.core.identity import AgentIdentity, AgentIdentityConfig
from agent_did_sdk.core.message_signing import message_signing_input
from agent_did_sdk.core.signer import LocalKeySigner
from agent_did_sdk.core.types import (
    AgentDIDDocument,
    CreateAgentParams,
    SignHttpRequestParams,
    UpdateAgentDocumentParams,
)
from agent_did_sdk.crypto.multibase import decode_public_key_multibase, encode_public_key_multibase
from agent_did_sdk.lifecycle.documents import build_updated_document
from agent_did_sdk.verification.signature import verify_with_active_keys

PARAMS = CreateAgentParams(
    name="RotatingBot",
    core_model="gpt-4o-mini",
    system_prompt="You are a test assistant.",
    additional_verification_relationships=["capabilityDelegation", "capabilityInvocation"],
)


def _setup() -> tuple[AgentDidClient, AgentIdentity]:
    client = AgentDidClient()
    identity = AgentIdentity(AgentIdentityConfig(controller_signer=LocalKeySigner.generate()[0], client=client))
    return client, identity


def _listed_key_ids(document: AgentDIDDocument) -> list[str]:
    return [
        *document.authentication,
        *(document.assertion_method or []),
        *(document.capability_delegation or []),
        *(document.capability_invocation or []),
    ]


def _core_style_verifies(document: AgentDIDDocument, key_id: str, payload: str, signature: str) -> bool:
    """What a DID Core verifier unaware of ``deactivated`` does: the key is listed and the signature verifies."""
    method = next((m for m in document.verification_method if m.id == key_id), None)
    if method is None or not method.public_key_multibase or key_id not in (document.assertion_method or []):
        return False
    try:
        VerifyKey(decode_public_key_multibase(method.public_key_multibase)).verify(
            message_signing_input(payload), bytes.fromhex(signature)
        )
    except Exception:
        return False
    return True


async def test_lists_no_retired_key_in_any_relationship_after_one_or_more_rotations() -> None:
    client, identity = _setup()
    document = (await identity.create(PARAMS)).document
    first = await client.rotate_verification_method(document.id)
    second = await client.rotate_verification_method(document.id)

    for rotated in (first, second):
        retired = [m.id for m in rotated.document.verification_method if m.deactivated]
        assert retired
        assert [k for k in _listed_key_ids(rotated.document) if k in retired] == []
        new_id = rotated.verification_method_id
        assert rotated.document.authentication == [new_id]
        assert rotated.document.assertion_method == [new_id]
        assert rotated.document.capability_delegation == [new_id]
        assert rotated.document.capability_invocation == [new_id]
    assert len(second.document.verification_method) == 3


async def test_a_did_core_style_verifier_does_not_accept_the_rotated_out_key() -> None:
    client, identity = _setup()
    result = await identity.create(PARAMS)
    old_key_id = result.document.verification_method[0].id
    signature = await identity.sign_message("approve", result.agent_private_key)
    assert _core_style_verifies(result.document, old_key_id, "approve", signature) is True

    rotated = await client.rotate_verification_method(result.document.id)

    assert _core_style_verifies(rotated.document, old_key_id, "approve", signature) is False


async def test_answers_false_without_raising_for_the_key_id_of_a_rotated_out_key() -> None:
    client, identity = _setup()
    result = await identity.create(PARAMS)
    old_key_id = result.document.verification_method[0].id
    signature = await identity.sign_message("approve", result.agent_private_key)

    await client.rotate_verification_method(result.document.id)

    assert await client.verify_signature(result.document.id, "approve", signature, old_key_id) is False


async def test_keeps_rejecting_a_retired_key_that_an_earlier_release_still_lists() -> None:
    client, identity = _setup()
    result = await identity.create(PARAMS)
    old_key_id = result.document.verification_method[0].id
    signature = await identity.sign_message("approve", result.agent_private_key)
    rotated = (await client.rotate_verification_method(result.document.id)).document
    legacy = rotated.model_copy(update={"assertion_method": [old_key_id, *(rotated.assertion_method or [])]})

    payload = message_signing_input("approve")
    assert verify_with_active_keys(legacy, payload, signature, old_key_id, "assertionMethod") is False
    assert verify_with_active_keys(legacy, payload, signature, None, "assertionMethod") is False


async def test_the_next_update_of_such_a_document_removes_the_retired_keys_from_the_relationships() -> None:
    client, identity = _setup()
    result = await identity.create(PARAMS)
    old_key_id = result.document.verification_method[0].id
    rotated = (await client.rotate_verification_method(result.document.id)).document
    legacy = rotated.model_copy(
        update={
            "assertion_method": [old_key_id, *(rotated.assertion_method or [])],
            "capability_delegation": [old_key_id, *(rotated.capability_delegation or [])],
        }
    )

    updated = build_updated_document(
        legacy, UpdateAgentDocumentParams(description="republished"), "2030-01-01T00:00:00.000Z"
    )

    assert old_key_id not in _listed_key_ids(updated)
    assert old_key_id in [m.id for m in updated.verification_method]


async def test_rotation_with_a_key_held_elsewhere_uses_its_public_key_and_returns_no_private_key() -> None:
    client, identity = _setup()
    result = await identity.create(PARAMS)
    kms_signer = LocalKeySigner.generate()[0]

    rotated = await client.rotate_verification_method(result.document.id, signer=kms_signer)

    assert rotated.agent_private_key == ""
    method = next(m for m in rotated.document.verification_method if m.id == rotated.verification_method_id)
    assert method.public_key_multibase == encode_public_key_multibase(await kms_signer.get_public_key())
    signature = await identity.sign_message("approve", kms_signer)
    assert await client.verify_signature(result.document.id, "approve", signature, rotated.verification_method_id)


async def test_sign_http_request_requires_the_verification_method_id() -> None:
    _, identity = _setup()
    result = await identity.create(CreateAgentParams(name="NoKeyIdBot", core_model="m", system_prompt="p"))

    with pytest.raises(ValidationError):
        SignHttpRequestParams(  # type: ignore[call-arg]
            method="GET",
            url="https://api.example.com/data",
            agent_private_key=result.agent_private_key,
            agent_did=result.document.id,
        )
    with pytest.raises(ValueError, match="verification_method_id is required"):
        await identity.sign_http_request(
            SignHttpRequestParams(
                method="GET",
                url="https://api.example.com/data",
                agent_private_key=result.agent_private_key,
                agent_did=result.document.id,
                verification_method_id=" ",
            )
        )


async def test_verify_with_active_keys_answers_false_for_malformed_input() -> None:
    _, identity = _setup()
    result = await identity.create(CreateAgentParams(name="MalformedBot", core_model="m", system_prompt="p"))
    signature = await identity.sign_message("approve", result.agent_private_key)
    key_id = result.document.verification_method[0].id

    payload = message_signing_input("approve")
    assert verify_with_active_keys(result.document, payload, signature, key_id, "assertionMethod") is True
    assert verify_with_active_keys(result.document, "approve", "zz-not-hex", key_id, "assertionMethod") is False
    assert verify_with_active_keys(result.document, "approve", "abc", key_id, "assertionMethod") is False
    assert verify_with_active_keys(result.document, "approve", signature, "", "assertionMethod") is False
