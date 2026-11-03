"""did:webvh v1.0 lifecycle authorization (parity: the matching describe block in sdk/tests/AgentIdentity.test.ts)."""

from __future__ import annotations

import json

import pytest

from agent_did_sdk import (
    AgentIdentity,
    AgentIdentityConfig,
    CreateAgentParams,
    CreateDidWebvhOptions,
    InMemoryAgentRegistry,
    InMemoryDIDResolver,
    LocalKeySigner,
    UpdateAgentDocumentParams,
)
from agent_did_sdk.webvh.adapter import DidWebvhError, did_webvh_update_key_for, resolve_did_webvh_log

CONTROLLER_SIGNER = LocalKeySigner("7c" * 32)


def _reset_process() -> None:
    AgentIdentity.set_resolver(InMemoryDIDResolver())
    AgentIdentity.set_registry(InMemoryAgentRegistry())
    AgentIdentity._history_store = {}
    AgentIdentity._did_webvh_log_store = {}
    AgentIdentity._did_webvh_signer_store = {}
    AgentIdentity._bootstrap_controllers = {}


def _params(**webvh_overrides: object) -> CreateAgentParams:
    webvh: dict[str, object] = {
        "domain": "agents.example",
        "controller_did": "did:webvh:QmControllerScid:agents.example:organizations:acme-support",
        "controller_signer": CONTROLLER_SIGNER,
        "path_segments": ["agents", "lifecycle-bot"],
        **webvh_overrides,
    }
    return CreateAgentParams(
        name="LifecycleBot", core_model="gpt-4o-mini", system_prompt="lifecycle prompt", webvh=webvh
    )


async def _import_into_fresh_process(did: str) -> None:
    """Simulate another process: the log is known (imported), the controller signer is not."""
    log = AgentIdentity.export_did_webvh_history(did)
    _reset_process()
    await AgentIdentity.import_did_webvh_history(log)


@pytest.fixture()
def identity() -> AgentIdentity:
    _reset_process()
    return AgentIdentity(AgentIdentityConfig(signer_address="0xLifecycleController1234567890"))


class TestDidWebvhLifecycleAuthorization:
    async def test_controller_key_not_agent_key_is_the_only_update_key(self, identity: AgentIdentity) -> None:
        result = await identity.create(_params())
        resolved = await resolve_did_webvh_log(AgentIdentity.export_did_webvh_history(result.document.id))

        assert resolved.metadata.update_keys == [await did_webvh_update_key_for(CONTROLLER_SIGNER)]
        assert result.document.verification_method[0].public_key_multibase not in resolved.metadata.update_keys

    def test_requires_controller_signer_for_the_explicit_profile(self) -> None:
        with pytest.raises(ValueError, match="controller_signer"):
            CreateDidWebvhOptions(domain="agents.example", controller_did="did:webvh:QmX:agents.example")

    def test_rejects_scid_which_v1_derives_from_the_genesis_entry(self) -> None:
        with pytest.raises(ValueError, match="scid"):
            _params(scid="QmChosen")

    async def test_requires_the_controller_signer_to_change_an_imported_did(self, identity: AgentIdentity) -> None:
        did = (await identity.create(_params())).document.id
        await _import_into_fresh_process(did)

        with pytest.raises(ValueError, match="controller signer is required"):
            await AgentIdentity.update_did_document(did, UpdateAgentDocumentParams(version="2.0.0"))
        with pytest.raises(ValueError, match="controller signer is required"):
            await AgentIdentity.rotate_verification_method(did)
        with pytest.raises(ValueError, match="controller signer is required"):
            await AgentIdentity.revoke_did(did)
        assert (await AgentIdentity.resolve(did)).id == did

    async def test_rejects_a_signer_that_is_not_the_controller(self, identity: AgentIdentity) -> None:
        did = (await identity.create(_params())).document.id
        await _import_into_fresh_process(did)
        not_the_controller = LocalKeySigner("9e" * 32)

        with pytest.raises(DidWebvhError) as excinfo:
            await AgentIdentity.update_did_document(
                did, UpdateAgentDocumentParams(version="2.0.0"), controller_signer=not_the_controller
            )
        assert excinfo.value.code == "unauthorized"
        with pytest.raises(DidWebvhError):
            await AgentIdentity.revoke_did(did, controller_signer=not_the_controller)
        assert (await AgentIdentity.resolve(did)).id == did

    async def test_accepts_the_controller_signer_for_an_imported_did(self, identity: AgentIdentity) -> None:
        did = (await identity.create(_params())).document.id
        await _import_into_fresh_process(did)

        updated = await AgentIdentity.update_did_document(
            did, UpdateAgentDocumentParams(version="2.0.0"), controller_signer=CONTROLLER_SIGNER
        )
        rotated = await AgentIdentity.rotate_verification_method(did, controller_signer=CONTROLLER_SIGNER)
        await AgentIdentity.revoke_did(did, controller_signer=CONTROLLER_SIGNER)

        assert updated.agent_metadata.version == "2.0.0"
        assert rotated.verification_method_id == f"{did}#key-2"
        with pytest.raises(ValueError, match="revoked"):
            await AgentIdentity.resolve(did)
        log = await resolve_did_webvh_log(AgentIdentity.export_did_webvh_history(did))
        assert log.metadata.version_number == 4
        assert log.metadata.deactivated is True

    async def test_refuses_to_import_a_log_that_fails_verification(self, identity: AgentIdentity) -> None:
        did = (await identity.create(_params())).document.id
        entry = json.loads(AgentIdentity.export_did_webvh_history(did).splitlines()[0])
        entry["state"]["controller"] = "did:webvh:QmAttacker:attacker.example"
        _reset_process()

        with pytest.raises(DidWebvhError):
            await AgentIdentity.import_did_webvh_history(json.dumps(entry) + "\n")
        with pytest.raises(ValueError):
            await AgentIdentity.resolve(did)

    async def test_imports_a_deactivated_log_as_revoked(self, identity: AgentIdentity) -> None:
        did = (await identity.create(_params())).document.id
        await AgentIdentity.revoke_did(did)
        await _import_into_fresh_process(did)

        with pytest.raises(ValueError, match="revoked"):
            await AgentIdentity.resolve(did)
        assert [entry.action for entry in AgentIdentity.get_document_history(did)] == ["created", "revoked"]
