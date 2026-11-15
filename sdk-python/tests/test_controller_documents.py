"""Controller documents (RFC-001 §4.2.1): a did:webvh controller may be any DID Core document.

Only the agent's own document must be an Agent-DID document; the binding rule (§6.6 item 7) is unchanged.
Parity: sdk/tests/ControllerDocuments.test.ts.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

import pytest

from agent_did_sdk import InMemoryAgentRegistry
from agent_did_sdk.core.client import AgentDidClient, ProductionResolverProfileConfig
from agent_did_sdk.core.identity import AgentIdentity, AgentIdentityConfig
from agent_did_sdk.core.signer import LocalKeySigner
from agent_did_sdk.core.types import (
    AgentDIDDocument,
    CreateAgentParams,
    CreateDidWebvhOptions,
    IssueAgentMetadataCredentialParams,
)
from agent_did_sdk.crypto.multibase import encode_public_key_multibase
from agent_did_sdk.webvh.adapter import DID_WEBVH_PLACEHOLDER, create_did_webvh_log, derive_did_webvh_log_url

D = DID_WEBVH_PLACEHOLDER
DID_CORE_CONTEXT = ["https://www.w3.org/ns/did/v1", "https://w3id.org/security/multikey/v1"]

DocumentBuilder = Callable[[LocalKeySigner], Awaitable[dict[str, Any]]]


async def plain_controller_document(signer: LocalKeySigner) -> dict[str, Any]:
    """A plain DID Core controller document: no ``agentMetadata``, ``created``, ``updated`` or ``controller``."""
    public_key_multibase = encode_public_key_multibase(await signer.get_public_key())
    return {
        "@context": DID_CORE_CONTEXT,
        "id": D,
        "verificationMethod": [
            {"id": f"{D}#key-1", "type": "Multikey", "controller": D, "publicKeyMultibase": public_key_multibase}
        ],
        "authentication": ["#key-1"],
        "assertionMethod": ["#key-1"],
        "capabilityInvocation": ["#key-1"],
    }


class _NoDocuments:
    async def get_by_reference(self, ref: str) -> None:
        return None


@dataclass
class _Setup:
    controller_did: str
    controller_signer: LocalKeySigner
    owner: AgentDidClient
    agent: AgentDIDDocument
    signature: str
    logs: dict[str, str]

    def verifier(self) -> AgentDidClient:
        return _with_host(AgentDidClient(), self.logs)


def _with_host(client: AgentDidClient, logs: dict[str, str]) -> AgentDidClient:
    class _Host:
        async def get_by_reference(self, ref: str) -> None:
            return None

        async def get_did_log_by_reference(self, url: str) -> str | None:
            return logs.get(url)

    client.use_production_resolver(ProductionResolverProfileConfig(
        registry=InMemoryAgentRegistry(),
        document_source=_NoDocuments(),  # type: ignore[arg-type]
        webvh_document_source=_Host(),  # type: ignore[arg-type]
    ))
    return client


async def _set_up(controller_document: DocumentBuilder = plain_controller_document) -> _Setup:
    controller_signer = LocalKeySigner.generate()[0]
    controller = await create_did_webvh_log(
        domain="org.example",
        path_segments=["controllers", "acme"],
        document=await controller_document(controller_signer),
        signer=controller_signer,
    )
    logs = {derive_did_webvh_log_url(controller.did): controller.log}
    owner = _with_host(AgentDidClient(), logs)
    identity = AgentIdentity(AgentIdentityConfig(controller_signer=LocalKeySigner.generate()[0], client=owner))
    created = await identity.create(CreateAgentParams(
        name="PlainControllerBot",
        webvh=CreateDidWebvhOptions(
            domain="org.example",
            path_segments=["agents", "bot"],
            controller_did=controller.did,
            controller_signer=controller_signer,
        ),
    ))
    logs[derive_did_webvh_log_url(created.document.id)] = owner.export_did_webvh_history(created.document.id)
    signature = await identity.sign_message("approve", created.agent_private_key)
    return _Setup(controller.did, controller_signer, owner, created.document, signature, logs)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


async def test_verifies_an_agent_whose_controller_is_a_plain_did_core_document() -> None:
    setup = await _set_up()

    assert await setup.owner.verify_signature(setup.agent.id, "approve", setup.signature) is True
    assert await setup.verifier().verify_signature(setup.agent.id, "approve", setup.signature) is True


async def test_resolves_the_controller_with_resolve_document_and_in_the_chain_but_not_with_resolve() -> None:
    setup = await _set_up()
    client = setup.verifier()

    controller = await client.resolve_document(setup.controller_did)
    assert controller.id == setup.controller_did
    assert not isinstance(controller, AgentDIDDocument)
    chain = await client.resolve_controller_chain(setup.agent.id)
    assert [document.id for document in chain] == [setup.agent.id, setup.controller_did]
    with pytest.raises(ValueError, match="is not an Agent-DID document"):
        await client.resolve(setup.controller_did)


async def test_never_verifies_a_signature_for_a_did_whose_document_is_not_an_agent_did_document() -> None:
    setup = await _set_up()
    client = setup.verifier()
    key_id = f"{setup.controller_did}#key-1"

    assert await client.verify_signature(setup.controller_did, "approve", setup.signature, key_id) is False
    at_time = await client.verify_signature_at_time(
        setup.controller_did, "approve", setup.signature, key_id, stated_time=_now()
    )
    assert (at_time.status, at_time.reason) == ("invalid", "did_resolution_failed")


async def test_accepts_a_key_embedded_in_capability_invocation() -> None:
    async def embedded(signer: LocalKeySigner) -> dict[str, Any]:
        return {
            "@context": DID_CORE_CONTEXT,
            "id": D,
            "capabilityInvocation": [{
                "id": "#invoke",
                "type": "Multikey",
                "controller": D,
                "publicKeyMultibase": encode_public_key_multibase(await signer.get_public_key()),
            }],
        }

    setup = await _set_up(embedded)

    assert await setup.verifier().verify_signature(setup.agent.id, "approve", setup.signature) is True


async def test_rejects_the_agent_when_the_controller_lists_its_key_only_outside_capability_invocation() -> None:
    async def no_invocation(signer: LocalKeySigner) -> dict[str, Any]:
        document = await plain_controller_document(signer)
        del document["capabilityInvocation"]
        return document

    setup = await _set_up(no_invocation)
    client = setup.verifier()

    assert await client.verify_signature(setup.agent.id, "approve", setup.signature) is False
    at_time = await client.verify_signature_at_time(
        setup.agent.id, "approve", setup.signature, setup.agent.authentication[0], stated_time=_now()
    )
    assert (at_time.status, at_time.reason) == ("invalid", "controller_not_bound")


async def test_fails_closed_on_a_controller_whose_controller_is_a_list() -> None:
    async def listed(signer: LocalKeySigner) -> dict[str, Any]:
        return {
            **(await plain_controller_document(signer)),
            "controller": ["did:webvh:QmA:org.example:a", "did:webvh:QmB:org.example:b"],
        }

    setup = await _set_up(listed)
    client = setup.verifier()

    assert await client.verify_signature(setup.agent.id, "approve", setup.signature) is False
    with pytest.raises(ValueError, match="a list of controllers"):
        await client.resolve_controller_chain(setup.agent.id)


async def test_rejects_a_controller_log_whose_state_is_not_a_did_document() -> None:
    async def malformed(signer: LocalKeySigner) -> dict[str, Any]:
        return {**(await plain_controller_document(signer)), "capabilityInvocation": [42]}

    setup = await _set_up(malformed)
    client = setup.verifier()

    assert await client.verify_signature(setup.agent.id, "approve", setup.signature) is False
    with pytest.raises(ValueError, match="is not a DID document"):
        await client.resolve_controller_chain(setup.agent.id)


async def test_issues_and_verifies_a_credential_with_a_relative_assertion_key_of_a_plain_controller() -> None:
    setup = await _set_up()

    credential = await setup.owner.issue_agent_metadata_credential(IssueAgentMetadataCredentialParams(
        agent_did=setup.agent.id,
        signer=setup.controller_signer,
        verification_method_id=f"{setup.controller_did}#key-1",
    ))
    result = await setup.verifier().verify_agent_metadata_credential(credential)

    assert result.ok is True
    assert result.issuer == setup.controller_did
    assert result.controllers == [setup.controller_did]


async def test_rejects_the_agent_when_the_key_of_the_plain_controller_carries_deactivated() -> None:
    async def retired(signer: LocalKeySigner) -> dict[str, Any]:
        document = await plain_controller_document(signer)
        document["verificationMethod"][0]["deactivated"] = "2026-01-01T00:00:00Z"
        return document

    setup = await _set_up(retired)

    assert len(await setup.verifier().resolve_controller_chain(setup.agent.id)) == 2
    assert await setup.verifier().verify_signature(setup.agent.id, "approve", setup.signature) is False
