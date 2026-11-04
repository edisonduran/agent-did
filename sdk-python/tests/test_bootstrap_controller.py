"""Regression tests for bootstrap controller key generation."""

from __future__ import annotations

import hashlib

import pytest
from nacl.signing import SigningKey

from agent_did_sdk import InMemoryAgentRegistry
from agent_did_sdk.core.identity import AgentIdentity, AgentIdentityConfig
from agent_did_sdk.core.signer import LocalKeySigner
from agent_did_sdk.core.types import CreateAgentParams, CreateDidWebvhOptions
from agent_did_sdk.crypto.multibase import encode_public_key_multibase
from agent_did_sdk.resolver.in_memory import InMemoryDIDResolver


def _reset_state() -> None:
    AgentIdentity.set_resolver(InMemoryDIDResolver())
    AgentIdentity.set_registry(InMemoryAgentRegistry())


@pytest.fixture()
def identity() -> AgentIdentity:
    _reset_state()
    return AgentIdentity(AgentIdentityConfig(controller_signer=LocalKeySigner.generate()[0]))


def _params(name: str = "BootstrapBot", webvh: CreateDidWebvhOptions | None = None) -> CreateAgentParams:
    return CreateAgentParams(
        name=name,
        core_model="gpt-4.1-mini",
        system_prompt="You are a bootstrap test agent.",
        webvh=webvh,
    )


class TestBootstrapControllerKeys:
    async def test_returns_random_controller_key_that_controls_the_controller_document(
        self, identity: AgentIdentity
    ) -> None:
        result = await identity.create(_params())
        controller_private_key = result.controller_private_key

        assert controller_private_key is not None
        assert len(controller_private_key) == 64
        int(controller_private_key, 16)

        controller_document = await AgentIdentity.resolve(result.document.controller)
        expected_public_key = bytes(SigningKey(bytes.fromhex(controller_private_key)).verify_key)
        assert controller_document.verification_method[0].public_key_multibase == encode_public_key_multibase(
            expected_public_key
        )

        signature = await identity.sign_message("controller-statement", controller_private_key)
        assert await AgentIdentity.verify_signature(result.document.controller, "controller-statement", signature)

    async def test_never_derives_controller_key_from_public_data(self, identity: AgentIdentity) -> None:
        result = await identity.create(_params())
        controller_did = result.document.controller
        publicly_derivable_seed = hashlib.sha256(f"{controller_did}:bootstrap-key".encode()).hexdigest()

        assert result.controller_private_key != publicly_derivable_seed

        forged_signature = SigningKey(bytes.fromhex(publicly_derivable_seed)).sign(b"forged-statement").signature.hex()
        assert not await AgentIdentity.verify_signature(controller_did, "forged-statement", forged_signature)

    async def test_generates_fresh_controller_key_for_each_new_bootstrap(self, identity: AgentIdentity) -> None:
        first = await identity.create(_params())

        _reset_state()
        second = await identity.create(_params())

        # did:webvh v1.0 derives the SCID from the genesis entry, so a new bootstrap is a new controller DID.
        assert second.document.controller != first.document.controller
        assert second.controller_private_key is not None
        assert second.controller_private_key != first.controller_private_key

    async def test_returns_controller_key_only_when_controller_document_is_created(
        self, identity: AgentIdentity
    ) -> None:
        first = await identity.create(_params())
        controller_before = await AgentIdentity.resolve(first.document.controller)

        second = await identity.create(_params(name="BootstrapBot-2"))

        assert second.document.controller == first.document.controller
        assert second.controller_private_key is None
        assert "controllerPrivateKey" not in second.model_dump(by_alias=True, exclude_none=True)
        assert await AgentIdentity.resolve(first.document.controller) == controller_before

    async def test_does_not_fabricate_an_explicitly_supplied_controller(self, identity: AgentIdentity) -> None:
        controller_did = "did:webvh:QmControllerScid:agents.example:organizations:acme-support"
        result = await identity.create(
            _params(
                webvh=CreateDidWebvhOptions(
                    domain="agents.example",
                    controller_did=controller_did,
                    controller_signer=LocalKeySigner("7c" * 32),
                    path_segments=["agents", "bootstrap-bot"],
                )
            )
        )

        assert result.document.controller == controller_did
        assert result.controller_private_key is None
        with pytest.raises(Exception):
            await AgentIdentity.resolve(controller_did)
        resolved = await AgentIdentity.resolve(result.document.id)
        assert resolved.id == result.document.id
