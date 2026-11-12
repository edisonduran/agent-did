"""Controller binding (RFC-001 §6.6 item 7); parity: sdk/tests/ControllerBinding.test.ts."""

from __future__ import annotations

from datetime import datetime, timezone

from agent_did_sdk import AgentDidClient, ControllerBindingError
from agent_did_sdk.core.identity import AgentIdentity, AgentIdentityConfig
from agent_did_sdk.core.signer import LocalKeySigner
from agent_did_sdk.core.types import (
    CreateAgentParams,
    CreateDidWebvhOptions,
    SignHttpRequestParams,
    UpdateAgentDocumentParams,
    VerifyHttpRequestSignatureParams,
)
from agent_did_sdk.resolver.in_memory import InMemoryDIDResolver

BASE = CreateAgentParams(name="BoundBot", core_model="gpt-4o-mini", system_prompt="You are a test assistant.")


async def _legit_party() -> tuple[AgentDidClient, AgentIdentity, object, str, LocalKeySigner]:
    """A party with its own client: it creates a bootstrap controller and an agent under it."""
    client = AgentDidClient()
    identity = AgentIdentity(AgentIdentityConfig(controller_signer=LocalKeySigner.generate()[0], client=client))
    created = await identity.create(BASE)
    assert created.controller_private_key is not None
    return client, identity, created, created.document.controller, LocalKeySigner(created.controller_private_key)


async def _verifier_with(*logs: str) -> AgentDidClient:
    """A verifier that imports the logs it is given, like a service that fetched them."""
    verifier = AgentDidClient()
    for log in logs:
        await verifier.import_did_webvh_history(log)
    return verifier


async def _forged_agent(controller_did: str, name: str) -> tuple[AgentDidClient, AgentIdentity, object]:
    """An agent published by someone else that names `controller_did` as its controller."""
    mallory = AgentDidClient()
    identity = AgentIdentity(AgentIdentityConfig(controller_signer=LocalKeySigner.generate()[0], client=mallory))
    forged = await identity.create(
        BASE.model_copy(
            update={
                "name": name,
                "webvh": CreateDidWebvhOptions(
                    domain="mallory.example",
                    controller_did=controller_did,
                    controller_signer=LocalKeySigner.generate()[0],
                ),
            }
        )
    )
    return mallory, identity, forged


async def test_verifies_an_agent_created_under_its_own_bootstrap_controller() -> None:
    client, identity, created, controller_did, _ = await _legit_party()
    signature = await identity.sign_message("approve", created.agent_private_key)  # type: ignore[attr-defined]

    assert await client.verify_signature(created.document.id, "approve", signature) is True  # type: ignore[attr-defined]

    verifier = await _verifier_with(
        client.export_did_webvh_history(controller_did),
        client.export_did_webvh_history(created.document.id),  # type: ignore[attr-defined]
    )
    assert await verifier.verify_signature(created.document.id, "approve", signature) is True  # type: ignore[attr-defined]


async def test_rejects_an_agent_that_names_a_controller_it_has_no_key_in() -> None:
    acme_client, _, _, acme_controller, _ = await _legit_party()
    mallory, identity, forged = await _forged_agent(acme_controller, "ForgedBot")
    signature = await identity.sign_message("approve", forged.agent_private_key)  # type: ignore[attr-defined]
    assert forged.document.controller == acme_controller  # type: ignore[attr-defined]

    verifier = await _verifier_with(
        acme_client.export_did_webvh_history(acme_controller),
        mallory.export_did_webvh_history(forged.document.id),  # type: ignore[attr-defined]
    )
    assert await verifier.verify_signature(forged.document.id, "approve", signature) is False  # type: ignore[attr-defined]
    assert len(await verifier.resolve_controller_chain(forged.document.id)) == 2  # type: ignore[attr-defined]


async def test_reports_controller_not_bound_for_an_http_request_signed_by_such_an_agent() -> None:
    acme_client, _, _, acme_controller, _ = await _legit_party()
    mallory, identity, forged = await _forged_agent(acme_controller, "ForgedHttpBot")
    url = "https://api.example.com/v1/orders"
    headers = await identity.sign_http_request(
        SignHttpRequestParams(
            method="POST",
            url=url,
            body="{}",
            agent_private_key=forged.agent_private_key,  # type: ignore[attr-defined]
            agent_did=forged.document.id,  # type: ignore[attr-defined]
            verification_method_id=forged.document.authentication[0],  # type: ignore[attr-defined]
        )
    )

    verifier = await _verifier_with(
        acme_client.export_did_webvh_history(acme_controller),
        mallory.export_did_webvh_history(forged.document.id),  # type: ignore[attr-defined]
    )
    result = await verifier.verify_http_request_signature_detailed(
        VerifyHttpRequestSignatureParams(method="POST", url=url, body="{}", headers=headers)
    )
    assert result.ok is False
    assert result.reason == "controller_not_bound"


async def test_verifies_an_agent_under_an_explicit_controller_whose_document_lists_the_signing_key() -> None:
    acme_client, _, _, acme_controller, acme_signer = await _legit_party()
    owner = AgentDidClient()
    identity = AgentIdentity(AgentIdentityConfig(controller_signer=LocalKeySigner.generate()[0], client=owner))
    agent = await identity.create(
        BASE.model_copy(
            update={
                "name": "SanctionedBot",
                "webvh": CreateDidWebvhOptions(
                    domain="acme.example", controller_did=acme_controller, controller_signer=acme_signer
                ),
            }
        )
    )
    signature = await identity.sign_message("approve", agent.agent_private_key)

    verifier = await _verifier_with(
        acme_client.export_did_webvh_history(acme_controller), owner.export_did_webvh_history(agent.document.id)
    )
    assert await verifier.verify_signature(agent.document.id, "approve", signature) is True


async def test_does_not_accept_a_controller_that_is_not_resolvable_or_an_agent_whose_log_is_not_available() -> None:
    client, identity, created, controller_did, _ = await _legit_party()
    signature = await identity.sign_message("approve", created.agent_private_key)  # type: ignore[attr-defined]
    agent_log = client.export_did_webvh_history(created.document.id)  # type: ignore[attr-defined]

    # The verifier does not have the controller's log
    verifier = await _verifier_with(agent_log)
    assert await verifier.verify_signature(created.document.id, "approve", signature) is False  # type: ignore[attr-defined]

    # A resolver that holds only documents cannot prove the binding either
    resolver = InMemoryDIDResolver()
    resolver.register_document(await client.resolve(created.document.id))  # type: ignore[attr-defined]
    resolver.register_document(await client.resolve(controller_did))
    document_only = AgentDidClient()
    document_only.set_resolver(resolver)
    assert await document_only.verify_signature(created.document.id, "approve", signature) is False  # type: ignore[attr-defined]


async def test_unbinds_the_agents_when_the_controller_retires_its_key_before_they_are_re_signed() -> None:
    client, identity, created, controller_did, _ = await _legit_party()
    signature = await identity.sign_message("approve", created.agent_private_key)  # type: ignore[attr-defined]
    assert await client.verify_signature(created.document.id, "approve", signature) is True  # type: ignore[attr-defined]

    await client.rotate_verification_method(controller_did)

    assert await client.verify_signature(created.document.id, "approve", signature) is False  # type: ignore[attr-defined]
    state = await client.resolve_did_webvh_state(created.document.id)  # type: ignore[attr-defined]
    assert state is not None
    assert state.provenance == "local"


async def test_rotates_the_controller_key_without_a_gap() -> None:
    client, identity, created, controller_did, _ = await _legit_party()
    signature = await identity.sign_message("approve", created.agent_private_key)  # type: ignore[attr-defined]
    new_key = LocalKeySigner.generate()[0]
    did = created.document.id  # type: ignore[attr-defined]

    # 1. the controller adds the new key; the old one still endorses
    added = await client.add_verification_method(controller_did, signer=new_key)
    assert added.agent_private_key == ""
    assert added.document.capability_invocation is not None
    assert len(added.document.capability_invocation) == 2
    assert await client.verify_signature(did, "approve", signature) is True

    # 2. the agent gets an entry signed by the new key
    await client.rotate_controller_key(did, new_controller_signer=new_key)
    await client.update_did_document(
        did, UpdateAgentDocumentParams(description="endorsed by the new key"), controller_signer=new_key
    )
    assert await client.verify_signature(did, "approve", signature) is True

    # 3. the controller retires the old key (rotation that keeps the new key as the active one)
    await client.rotate_verification_method(controller_did, signer=new_key)
    assert await client.verify_signature(did, "approve", signature) is True


async def test_applies_the_binding_to_a_result_that_would_be_valid_at_a_stated_time() -> None:
    acme_client, _, _, acme_controller, _ = await _legit_party()
    mallory, identity, forged = await _forged_agent(acme_controller, "ForgedTimedBot")
    signature = await identity.sign_message("approve", forged.agent_private_key)  # type: ignore[attr-defined]
    verifier = await _verifier_with(
        acme_client.export_did_webvh_history(acme_controller),
        mallory.export_did_webvh_history(forged.document.id),  # type: ignore[attr-defined]
    )

    result = await verifier.verify_signature_at_time(
        forged.document.id,  # type: ignore[attr-defined]
        "approve",
        signature,
        forged.document.authentication[0],  # type: ignore[attr-defined]
        stated_time=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    )
    assert result.status == "invalid"
    assert result.reason == "controller_not_bound"


async def test_describes_the_log_behind_a_did() -> None:
    client, _, created, controller_did, _ = await _legit_party()
    did = created.document.id  # type: ignore[attr-defined]
    state = await client.resolve_did_webvh_state(did)

    assert state is not None
    assert state.provenance == "local"
    assert state.document.id == did
    assert len(state.last_entry_signer_keys) == 1
    assert state.update_keys == state.last_entry_signer_keys
    controller_state = await client.resolve_did_webvh_state(controller_did)
    assert controller_state is not None
    assert controller_state.last_entry_signer_keys == state.last_entry_signer_keys

    verifier = await _verifier_with(client.export_did_webvh_history(did))
    imported = await verifier.resolve_did_webvh_state(did)
    assert imported is not None
    assert imported.provenance == "imported"
    assert await client.resolve_did_webvh_state("did:example:123") is None


def test_controller_binding_error_message() -> None:
    assert "not bound" in str(ControllerBindingError("did:a", "did:b", "x"))
