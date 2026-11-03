"""Tests for AgentIdentity — the main SDK class."""

from __future__ import annotations

import asyncio
import json
import re
import time

import httpx
import pytest

from agent_did_sdk import InMemoryAgentRegistry, ProductionHttpResolverProfileConfig
from agent_did_sdk.core.identity import AgentIdentity, AgentIdentityConfig
from agent_did_sdk.core.identity_composition import (
    IdentityCompositionError,
    assert_key_purpose,
    assert_signing_purpose,
)
from agent_did_sdk.core.signer import LocalKeySigner
from agent_did_sdk.core.types import (
    AgentDIDDocument,
    CreateAgentParams,
    SignHttpRequestParams,
    UpdateAgentDocumentParams,
    VerifyHttpRequestSignatureParams,
)
from agent_did_sdk.resolver.in_memory import InMemoryDIDResolver
from agent_did_sdk.webvh.adapter import resolve_did_webvh_log

from .webvh_helpers import create_agent_webvh_log


@pytest.fixture()
def identity() -> AgentIdentity:
    AgentIdentity.set_resolver(InMemoryDIDResolver())
    AgentIdentity.set_registry(InMemoryAgentRegistry())
    AgentIdentity.get_default_client()._history_store = {}
    AgentIdentity.get_default_client()._did_webvh_log_store = {}
    AgentIdentity.get_default_client()._did_webvh_signer_store = {}
    AgentIdentity.get_default_client()._bootstrap_controllers = {}
    return AgentIdentity(AgentIdentityConfig(signer_address="0xTestController1234567890"))


class TestAgentIdentityCreate:
    async def test_create_valid_agent(self, identity: AgentIdentity) -> None:
        result = await identity.create(CreateAgentParams(
            name="TestBot",
            core_model="gpt-4-turbo",
            system_prompt="You are helpful.",
        ))
        doc = result.document
        assert doc.id.startswith("did:webvh:")
        assert doc.controller.startswith("did:webvh:")
        assert doc.agent_metadata.name == "TestBot"
        assert doc.agent_metadata.version == "1.0.0"
        assert doc.created.endswith("Z")
        assert doc.updated.endswith("Z")
        assert len(doc.verification_method) == 1
        assert doc.verification_method[0].public_key_multibase is not None
        assert doc.verification_method[0].blockchain_account_id is None
        assert doc.assertion_method == [doc.verification_method[0].id]
        chain = await AgentIdentity.resolve_controller_chain(doc.id)
        assert [entry.id for entry in chain] == [doc.id, doc.controller]
        assert len(result.agent_private_key) == 64  # 32 bytes hex

    async def test_create_legacy_agent_when_explicitly_requested(self, identity: AgentIdentity) -> None:
        result = await identity.create(CreateAgentParams(
            name="LegacyBot",
            core_model="gpt-4-turbo",
            system_prompt="You are a legacy compatibility agent.",
            did_method="agent",
        ))
        doc = result.document
        assert doc.id.startswith("did:agent:polygon:")
        assert doc.controller.startswith("did:ethr:")
        assert doc.verification_method[0].blockchain_account_id is not None

    async def test_create_webvh_agent_when_requested(self, identity: AgentIdentity) -> None:
        result = await identity.create(CreateAgentParams(
            name="WebvhBot",
            description="A web-native agent identity",
            core_model="gpt-4.1-mini",
            system_prompt="You are a web-native agent.",
            did_method="webvh",
            webvh={
                "domain": "agents.example",
                "path_segments": ["agents", "webvh-bot"],
                "controller_did": "did:webvh:QmControllerScid:agents.example:organizations:acme-support",
                "controller_signer": LocalKeySigner("7c" * 32),
            },
        ))

        doc = result.document
        expected_did = doc.id
        # did:webvh v1.0: the SCID is derived from the genesis log entry.
        assert re.fullmatch(r"did:webvh:Qm[1-9A-HJ-NP-Za-km-z]{44}:agents\.example:agents:webvh-bot", expected_did)
        assert doc.controller == "did:webvh:QmControllerScid:agents.example:organizations:acme-support"
        assert doc.verification_method[0].id == f"{expected_did}#key-1"
        assert doc.verification_method[0].controller == doc.controller
        assert doc.verification_method[0].blockchain_account_id is None
        assert doc.authentication == [f"{expected_did}#key-1"]
        assert doc.assertion_method == [f"{expected_did}#key-1"]

        resolved = await AgentIdentity.resolve(expected_did)
        assert resolved.id == expected_did
        assert resolved.controller == doc.controller

    async def test_create_webvh_requires_controller_for_custom_domain(self, identity: AgentIdentity) -> None:
        with pytest.raises(ValueError, match="webvh.controller_did"):
            await identity.create(CreateAgentParams(
                name="BrokenWebvhBot",
                core_model="gpt-4.1-mini",
                system_prompt="broken",
                did_method="webvh",
                webvh={
                    "domain": "agents.example",
                    "controller_did": "",
                    "controller_signer": LocalKeySigner("7c" * 32),
                },
            ))

    async def test_create_with_all_params(self, identity: AgentIdentity) -> None:
        result = await identity.create(CreateAgentParams(
            name="FullBot",
            description="A complete bot",
            version="2.0.0",
            core_model="claude-3",
            system_prompt="Be precise.",
            capabilities=["search", "code"],
            member_of="did:agent:fleet:1",
        ))
        doc = result.document
        assert doc.agent_metadata.description == "A complete bot"
        assert doc.agent_metadata.version == "2.0.0"
        assert doc.agent_metadata.capabilities == ["search", "code"]
        assert doc.agent_metadata.member_of == "did:agent:fleet:1"

    async def test_rfc001_context(self, identity: AgentIdentity) -> None:
        result = await identity.create(CreateAgentParams(
            name="Bot", core_model="m", system_prompt="p",
        ))
        assert result.document.context == [
            "https://www.w3.org/ns/did/v1",
            "https://agent-did.org/v1",
        ]


class TestAgentIdentitySignVerify:
    async def test_sign_and_verify_payload(self, identity: AgentIdentity) -> None:
        result = await identity.create(CreateAgentParams(
            name="Signer", core_model="m", system_prompt="p",
        ))
        payload = "test-payload-123"
        signature = await identity.sign_message(payload, result.agent_private_key)
        assert len(signature) == 128  # 64 bytes hex
        is_valid = await AgentIdentity.verify_signature(
            result.document.id, payload, signature,
        )
        assert is_valid is True

    async def test_verify_wrong_payload(self, identity: AgentIdentity) -> None:
        result = await identity.create(CreateAgentParams(
            name="Signer", core_model="m", system_prompt="p",
        ))
        signature = await identity.sign_message("correct", result.agent_private_key)
        is_valid = await AgentIdentity.verify_signature(
            result.document.id, "wrong", signature,
        )
        assert is_valid is False

    async def test_verify_revoked_returns_false(self, identity: AgentIdentity) -> None:
        result = await identity.create(CreateAgentParams(
            name="Revoked", core_model="m", system_prompt="p",
        ))
        sig = await identity.sign_message("data", result.agent_private_key)
        await AgentIdentity.revoke_did(result.document.id)
        is_valid = await AgentIdentity.verify_signature(result.document.id, "data", sig)
        assert is_valid is False

    async def test_assert_key_purpose_reports_found_relationships(self, identity: AgentIdentity) -> None:
        result = await identity.create(CreateAgentParams(
            name="PurposeHelper", core_model="m", system_prompt="p",
        ))
        key_id = result.document.verification_method[0].id
        misbound_doc = result.document.model_copy(
            update={"authentication": [], "assertion_method": [], "key_agreement": [key_id]},
            deep=True,
        )

        with pytest.raises(IdentityCompositionError) as exc:
            assert_key_purpose(key_id, misbound_doc, "assertionMethod")

        assert exc.value.reason == "key_purpose_violation"
        assert exc.value.key_id == key_id
        assert exc.value.required_purpose == "assertionMethod"
        assert exc.value.found_in == ["keyAgreement"]

    async def test_verify_rejects_key_outside_assertion_method(self, identity: AgentIdentity) -> None:
        result = await identity.create(CreateAgentParams(
            name="PurposeVerifier", core_model="m", system_prompt="p",
        ))
        key_id = result.document.verification_method[0].id
        payload = "approve:purpose:1"
        signature = await identity.sign_message(payload, result.agent_private_key)
        misbound_doc = result.document.model_copy(
            update={"authentication": [], "assertion_method": [], "key_agreement": [key_id]},
            deep=True,
        )
        controller_chain = await AgentIdentity.resolve_controller_chain(result.document.id)

        resolver = InMemoryDIDResolver()
        resolver.register_document(misbound_doc)
        resolver.register_document(controller_chain[1])
        AgentIdentity.set_resolver(resolver)
        AgentIdentity.set_registry(InMemoryAgentRegistry())

        with pytest.raises(IdentityCompositionError) as exc:
            await AgentIdentity.verify_signature(result.document.id, payload, signature, key_id)

        assert exc.value.reason == "key_purpose_violation"
        assert exc.value.key_id == key_id
        assert exc.value.required_purpose == "assertionMethod"
        assert exc.value.found_in == ["keyAgreement"]

    async def test_verify_rejects_key_agreement_as_signing_purpose(self, identity: AgentIdentity) -> None:
        result = await identity.create(CreateAgentParams(
            name="KeyAgreement", core_model="m", system_prompt="p",
        ))
        key_id = result.document.verification_method[0].id
        payload = "approve:key-agreement:1"
        signature = await identity.sign_message(payload, result.agent_private_key)

        with pytest.raises(IdentityCompositionError) as exc:
            await AgentIdentity.verify_signature(
                result.document.id,
                payload,
                signature,
                key_id,
                required_purpose="keyAgreement",
            )

        assert exc.value.reason == "key_purpose_violation"
        assert exc.value.required_purpose == "keyAgreement"

    async def test_verify_rejects_unknown_key_with_key_purpose_violation(self, identity: AgentIdentity) -> None:
        result = await identity.create(CreateAgentParams(
            name="UnknownPurpose", core_model="m", system_prompt="p",
        ))
        payload = "approve:unknown-key:1"
        signature = await identity.sign_message(payload, result.agent_private_key)
        unknown_key_id = f"{result.document.id}#key-999"

        with pytest.raises(IdentityCompositionError) as exc:
            await AgentIdentity.verify_signature(result.document.id, payload, signature, unknown_key_id)

        assert exc.value.reason == "key_purpose_violation"
        assert exc.value.key_id == unknown_key_id
        assert exc.value.found_in == []

    async def test_assert_key_purpose_accepts_key_agreement_membership(self, identity: AgentIdentity) -> None:
        result = await identity.create(CreateAgentParams(
            name="Membership", core_model="m", system_prompt="p",
        ))
        key_id = result.document.verification_method[0].id
        key_agreement_doc = result.document.model_copy(
            update={"key_agreement": [key_id]},
            deep=True,
        )

        # Membership predicate must accept the key when keyAgreement is the requested relationship.
        assert_key_purpose(key_id, key_agreement_doc, "keyAgreement")

        # Signing-purpose policy must still reject keyAgreement for signing flows.
        with pytest.raises(IdentityCompositionError) as exc:
            assert_signing_purpose("keyAgreement", key_agreement_doc, key_id)
        assert exc.value.reason == "key_purpose_violation"
        assert exc.value.required_purpose == "keyAgreement"


class TestAgentIdentityHttpSignature:
    async def test_sign_and_verify_http(self, identity: AgentIdentity) -> None:
        result = await identity.create(CreateAgentParams(
            name="HttpBot", core_model="m", system_prompt="p",
        ))
        headers = await identity.sign_http_request(SignHttpRequestParams(
            method="POST",
            url="https://api.example.com/v1/test",
            body='{"data":true}',
            agent_private_key=result.agent_private_key,
            agent_did=result.document.id,
        ))
        assert "Signature" in headers
        assert "Signature-Input" in headers
        assert "Content-Digest" in headers

        is_valid = await AgentIdentity.verify_http_request_signature(
            VerifyHttpRequestSignatureParams(
                method="POST",
                url="https://api.example.com/v1/test",
                body='{"data":true}',
                headers=headers,
                max_created_skew_seconds=300,
            )
        )
        assert is_valid is True

    async def test_verify_returns_false_when_controller_chain_is_inactive(self, identity: AgentIdentity) -> None:
        result = await identity.create(CreateAgentParams(
            name="ChainVerifier", core_model="m", system_prompt="p",
        ))
        payload = "approve:controller-chain:1"
        signature = await identity.sign_message(payload, result.agent_private_key)
        chain = await AgentIdentity.resolve_controller_chain(result.document.id)

        await AgentIdentity.revoke_did(chain[1].id)

        is_valid = await AgentIdentity.verify_signature(result.document.id, payload, signature)
        assert is_valid is False

    async def test_sign_http_missing_method(self, identity: AgentIdentity) -> None:
        with pytest.raises(ValueError, match="method"):
            await identity.sign_http_request(SignHttpRequestParams(
                method="", url="https://example.com", body=None,
                agent_private_key="aa" * 32, agent_did="did:agent:test",
            ))

    async def test_reject_expired_signature(
        self, identity: AgentIdentity, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        result = await identity.create(CreateAgentParams(
            name="ExpiredBot", core_model="m", system_prompt="p",
        ))
        signed_at = time.time() - 120
        with monkeypatch.context() as patched:
            patched.setattr(time, "time", lambda: signed_at)
            headers = await identity.sign_http_request(SignHttpRequestParams(
                method="POST",
                url="https://api.example.com/v1/test",
                body='{"expired":true}',
                agent_private_key=result.agent_private_key,
                agent_did=result.document.id,
                expires_in_seconds=30,
            ))

        is_valid = await AgentIdentity.verify_http_request_signature(
            VerifyHttpRequestSignatureParams(
                method="POST",
                url="https://api.example.com/v1/test",
                body='{"expired":true}',
                headers=headers,
            )
        )
        assert is_valid is False

    async def test_reject_replay_with_rewritten_created_and_expires(self, identity: AgentIdentity) -> None:
        result = await identity.create(CreateAgentParams(
            name="ParamTamperBot", core_model="m", system_prompt="p",
        ))
        url, body = "https://api.example.com/v1/transfer", '{"amount":500}'
        headers = await identity.sign_http_request(SignHttpRequestParams(
            method="POST", url=url, body=body,
            agent_private_key=result.agent_private_key, agent_did=result.document.id,
        ))
        now = int(time.time())
        rewritten = dict(headers)
        rewritten["Signature-Input"] = re.sub(
            r"expires=\d+", f"expires={now + 86_400}",
            re.sub(r"created=\d+", f"created={now}", headers["Signature-Input"]),
        )
        without_expires = dict(headers)
        without_expires["Signature-Input"] = re.sub(r";expires=\d+", "", headers["Signature-Input"])

        async def verify(h: dict[str, str]) -> bool:
            return await AgentIdentity.verify_http_request_signature(
                VerifyHttpRequestSignatureParams(method="POST", url=url, body=body, headers=h)
            )

        assert await verify(headers) is True
        assert await verify(rewritten) is False
        assert await verify(without_expires) is False

    async def test_enforce_max_created_skew_within_and_beyond_60_seconds(
        self, identity: AgentIdentity, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        result = await identity.create(CreateAgentParams(
            name="SkewBot", core_model="m", system_prompt="p",
        ))

        async def sign_at(seconds_ago: int) -> dict[str, str]:
            signed_at = time.time() - seconds_ago
            with monkeypatch.context() as patched:
                patched.setattr(time, "time", lambda: signed_at)
                return await identity.sign_http_request(SignHttpRequestParams(
                    method="POST",
                    url="https://api.example.com/v1/test",
                    body='{"skew":true}',
                    agent_private_key=result.agent_private_key,
                    agent_did=result.document.id,
                    expires_in_seconds=120,
                ))

        within_headers = await sign_at(55)
        outside_headers = await sign_at(65)

        assert await AgentIdentity.verify_http_request_signature(
            VerifyHttpRequestSignatureParams(
                method="POST",
                url="https://api.example.com/v1/test",
                body='{"skew":true}',
                headers=within_headers,
                max_created_skew_seconds=60,
            )
        ) is True
        assert await AgentIdentity.verify_http_request_signature(
            VerifyHttpRequestSignatureParams(
                method="POST",
                url="https://api.example.com/v1/test",
                body='{"skew":true}',
                headers=outside_headers,
                max_created_skew_seconds=60,
            )
        ) is False

class TestAgentIdentityResolve:
    async def test_resolve_existing(self, identity: AgentIdentity) -> None:
        result = await identity.create(CreateAgentParams(
            name="Resolvable", core_model="m", system_prompt="p",
        ))
        doc = await AgentIdentity.resolve(result.document.id)
        assert doc.id == result.document.id

    async def test_resolve_webvh_controller_chain(self, identity: AgentIdentity) -> None:
        root_signer = LocalKeySigner("3d" * 32)
        controller_result = await identity.create(CreateAgentParams(
            name="ControllerRoot",
            core_model="controller-model",
            system_prompt="You are the controller root.",
            did_method="webvh",
            webvh={
                "domain": "agents.example",
                "path_segments": ["organizations", "acme-support"],
                # "{DID}" is replaced with the generated DID: a self-controlled root.
                "controller_did": "{DID}",
                "controller_signer": root_signer,
            },
        ))
        agent_result = await identity.create(CreateAgentParams(
            name="SupportBot",
            core_model="agent-model",
            system_prompt="You are a support agent.",
            did_method="webvh",
            webvh={
                "domain": "agents.example",
                "path_segments": ["agents", "supportbot-x"],
                "controller_did": controller_result.document.id,
                "controller_signer": root_signer,
            },
        ))

        chain = await AgentIdentity.resolve_controller_chain(agent_result.document.id)

        assert controller_result.document.controller == controller_result.document.id
        assert [doc.id for doc in chain] == [agent_result.document.id, controller_result.document.id]

    async def test_resolve_controller_chain_rejects_cycles(self) -> None:
        def make_chain_document(did: str, controller: str) -> AgentDIDDocument:
            return AgentDIDDocument(**{
                "@context": ["https://www.w3.org/ns/did/v1", "https://agent-did.org/v1"],
                "id": did,
                "controller": controller,
                "created": "2026-05-06T00:00:00.000Z",
                "updated": "2026-05-06T00:00:00.000Z",
                "agentMetadata": {
                    "name": "CycleBot",
                    "version": "1.0.0",
                    "coreModelHash": "hash://sha256/cycle-model",
                    "systemPromptHash": "hash://sha256/cycle-prompt",
                },
                "verificationMethod": [
                    {
                        "id": f"{did}#key-1",
                        "type": "Ed25519VerificationKey2020",
                        "controller": controller,
                        "publicKeyMultibase": "z6MkjTsREfRXe13mbS7GZQ9DKcrTuexb5YYdpbSFkwtWdRva",
                    }
                ],
                "authentication": [f"{did}#key-1"],
                "assertionMethod": [f"{did}#key-1"],
            })

        cycle_a_did = "did:webvh:QmCycleA:agents.example:agents:cycle-a"
        cycle_b_did = "did:webvh:QmCycleB:agents.example:agents:cycle-b"
        resolver = InMemoryDIDResolver()
        resolver.register_document(make_chain_document(cycle_a_did, cycle_b_did))
        resolver.register_document(make_chain_document(cycle_b_did, cycle_a_did))
        AgentIdentity.set_resolver(resolver)
        AgentIdentity.set_registry(InMemoryAgentRegistry())

        with pytest.raises(ValueError, match="Controller chain cycle detected"):
            await AgentIdentity.resolve_controller_chain(cycle_a_did)

    async def test_resolve_revoked_raises(self, identity: AgentIdentity) -> None:
        result = await identity.create(CreateAgentParams(
            name="ToRevoke", core_model="m", system_prompt="p",
        ))
        await AgentIdentity.revoke_did(result.document.id)
        with pytest.raises(ValueError, match="revoked"):
            await AgentIdentity.resolve(result.document.id)

    async def test_resolve_did_wba_uses_http_bootstrap_client(self) -> None:
        did = "did:wba:agents.example:profiles:weather-bot"
        expected_url = "https://agents.example/profiles/weather-bot/did.json"
        payload = {
            "@context": ["https://www.w3.org/ns/did/v1", "https://agent-did.org/v1"],
            "id": did,
            "controller": "did:web:agents.example",
            "created": "2026-03-22T00:00:00Z",
            "updated": "2026-03-22T00:00:00Z",
            "agentMetadata": {
                "name": "WeatherBot",
                "version": "1.0.0",
                "coreModelHash": "hash://sha256/weather-model",
                "systemPromptHash": "hash://sha256/weather-prompt",
            },
            "verificationMethod": [
                {
                    "id": f"{did}#key-1",
                    "type": "Ed25519VerificationKey2020",
                    "controller": "did:web:agents.example",
                    "publicKeyMultibase": "z6MkexampleWeatherBotKey",
                }
            ],
            "authentication": [f"{did}#key-1"],
        }

        def mock_send(request: httpx.Request) -> httpx.Response:
            if str(request.url) != expected_url:
                return httpx.Response(status_code=404, json={})
            return httpx.Response(status_code=200, json=payload)

        async with httpx.AsyncClient(transport=httpx.MockTransport(mock_send)) as http_client:
            AgentIdentity.set_registry(InMemoryAgentRegistry())
            AgentIdentity.use_production_resolver_from_http(
                ProductionHttpResolverProfileConfig(
                    registry=InMemoryAgentRegistry(),
                    http_client=http_client,
                )
            )

            resolved = await AgentIdentity.resolve(did)

        assert resolved.id == did
        assert resolved.agent_metadata.name == "WeatherBot"

    async def test_resolve_did_webvh_uses_http_bootstrap_client(self) -> None:
        created = await create_agent_webvh_log("agents.example", ["profiles", "weather-bot"])
        did = created.did
        expected_url = "https://agents.example/profiles/weather-bot/did.jsonl"
        did_log = created.log

        def mock_send(request: httpx.Request) -> httpx.Response:
            if str(request.url) != expected_url:
                return httpx.Response(status_code=404, json={})
            return httpx.Response(status_code=200, text=did_log)

        async with httpx.AsyncClient(transport=httpx.MockTransport(mock_send)) as http_client:
            AgentIdentity.set_registry(InMemoryAgentRegistry())
            AgentIdentity.use_production_resolver_from_http(
                ProductionHttpResolverProfileConfig(
                    registry=InMemoryAgentRegistry(),
                    http_client=http_client,
                )
            )

            resolved = await AgentIdentity.resolve(did)

        assert resolved.id == did
        assert resolved.agent_metadata.name == "WebvhResolverBot"


class TestAgentIdentityUpdate:
    async def test_update_document(self, identity: AgentIdentity) -> None:
        result = await identity.create(CreateAgentParams(
            name="Updatable", core_model="m", system_prompt="p",
        ))
        updated = await AgentIdentity.update_did_document(
            result.document.id,
            UpdateAgentDocumentParams(version="2.0.0", description="updated"),
        )
        assert updated.agent_metadata.version == "2.0.0"
        assert updated.agent_metadata.description == "updated"
        assert updated.updated != result.document.updated

    async def test_update_empty_did_raises(self) -> None:
        with pytest.raises(ValueError, match="required"):
            await AgentIdentity.update_did_document("", UpdateAgentDocumentParams())


class TestAgentIdentityRotateKey:
    async def test_rotate_once(self, identity: AgentIdentity) -> None:
        result = await identity.create(CreateAgentParams(
            name="Rotatable", core_model="m", system_prompt="p",
        ))
        rotated = await AgentIdentity.rotate_verification_method(result.document.id)
        assert rotated.verification_method_id.endswith("#key-2")
        assert len(rotated.document.verification_method) == 2
        assert rotated.document.authentication == [rotated.verification_method_id]
        assert rotated.document.assertion_method == [
            f"{result.document.id}#key-1",
            rotated.verification_method_id,
        ]

    async def test_rotate_twice(self, identity: AgentIdentity) -> None:
        result = await identity.create(CreateAgentParams(
            name="R2", core_model="m", system_prompt="p",
        ))
        await AgentIdentity.rotate_verification_method(result.document.id)
        r2 = await AgentIdentity.rotate_verification_method(result.document.id)
        assert r2.verification_method_id.endswith("#key-3")
        assert len(r2.document.verification_method) == 3

    async def test_sign_with_rotated_key(self, identity: AgentIdentity) -> None:
        result = await identity.create(CreateAgentParams(
            name="RotSig", core_model="m", system_prompt="p",
        ))
        rotated = await AgentIdentity.rotate_verification_method(result.document.id)
        sig = await identity.sign_message("payload", rotated.agent_private_key)
        is_valid = await AgentIdentity.verify_signature(
            result.document.id, "payload", sig, rotated.verification_method_id,
        )
        assert is_valid is True

    async def test_old_key_deactivated_after_rotation(self, identity: AgentIdentity) -> None:
        result = await identity.create(CreateAgentParams(
            name="Deactivation", core_model="m", system_prompt="p",
        ))
        rotated = await AgentIdentity.rotate_verification_method(result.document.id)
        old_key = next(
            m for m in rotated.document.verification_method
            if m.id == f"{result.document.id}#key-1"
        )
        assert old_key.deactivated is not None

        new_key = next(
            m for m in rotated.document.verification_method
            if m.id == rotated.verification_method_id
        )
        assert new_key.deactivated is None

    async def test_verify_historical_signature_after_rotation(self, identity: AgentIdentity) -> None:
        result = await identity.create(CreateAgentParams(
            name="HistoryBot", core_model="m", system_prompt="p",
        ))
        payload = "approve:historical:1"
        old_key_id = f"{result.document.id}#key-1"
        old_sig = await identity.sign_message(payload, result.agent_private_key)

        await AgentIdentity.rotate_verification_method(result.document.id)

        # Active verification should fail (old key no longer in authentication)
        active_valid = await AgentIdentity.verify_signature(
            result.document.id, payload, old_sig, old_key_id,
        )
        assert active_valid is False

        # Historical verification should succeed
        historical_valid = await AgentIdentity.verify_historical_signature(
            result.document.id, payload, old_sig, old_key_id,
        )
        assert historical_valid is True

    async def test_verify_historical_unknown_key_fails(self, identity: AgentIdentity) -> None:
        result = await identity.create(CreateAgentParams(
            name="UnknownKey", core_model="m", system_prompt="p",
        ))
        fake_sig = "00" * 64
        with pytest.raises(IdentityCompositionError) as exc:
            await AgentIdentity.verify_historical_signature(
                result.document.id, "payload", fake_sig, f"{result.document.id}#key-999",
            )
        assert exc.value.reason == "key_purpose_violation"
        assert exc.value.found_in == []

    async def test_preserve_historical_verification_after_three_did_webvh_rotation_cycles(
        self,
        identity: AgentIdentity,
    ) -> None:
        result = await identity.create(CreateAgentParams(
            name="ThreeCycleBot", core_model="m", system_prompt="p",
        ))
        payload = "approve:historical:three-cycle"
        oldest_key_id = f"{result.document.id}#key-1"
        oldest_sig = await identity.sign_message(payload, result.agent_private_key)

        assert result.document.id.startswith("did:webvh:")

        await AgentIdentity.rotate_verification_method(result.document.id)
        await AgentIdentity.rotate_verification_method(result.document.id)
        third_rotation = await AgentIdentity.rotate_verification_method(result.document.id)

        assert third_rotation.verification_method_id.endswith("#key-4")
        assert third_rotation.document.authentication == [third_rotation.verification_method_id]
        assert len(third_rotation.document.verification_method) == 4

        active_valid = await AgentIdentity.verify_signature(
            result.document.id, payload, oldest_sig, oldest_key_id,
        )
        historical_valid = await AgentIdentity.verify_historical_signature(
            result.document.id, payload, oldest_sig, oldest_key_id,
        )

        assert active_valid is False
        assert historical_valid is True


class TestSignerAbstraction:
    async def test_create_with_external_signer(self, identity: AgentIdentity) -> None:
        from agent_did_sdk.core.signer import LocalKeySigner
        signer, _ = LocalKeySigner.generate()
        result = await identity.create(CreateAgentParams(
            name="ProductionBot", core_model="gpt-4o", system_prompt="production prompt",
            signer=signer,
        ))
        assert result.document is not None
        assert result.document.verification_method[0].public_key_multibase.startswith("z6Mk")
        assert result.agent_private_key == ""

    async def test_sign_and_verify_with_signer(self, identity: AgentIdentity) -> None:
        from agent_did_sdk.core.signer import LocalKeySigner
        signer, private_key_hex = LocalKeySigner.generate()
        result = await identity.create(CreateAgentParams(
            name="SignerTestBot", core_model="test", system_prompt="test",
            signer=signer,
        ))
        payload = "signer-test-payload"
        sig_via_signer = await identity.sign_message(payload, signer)
        sig_via_key = await identity.sign_message(payload, private_key_hex)
        assert sig_via_signer == sig_via_key
        valid = await AgentIdentity.verify_signature(result.document.id, payload, sig_via_signer)
        assert valid is True

    async def test_sign_http_request_with_signer(self, identity: AgentIdentity) -> None:
        from agent_did_sdk.core.signer import LocalKeySigner
        signer, _ = LocalKeySigner.generate()
        result = await identity.create(CreateAgentParams(
            name="HttpSignerBot", core_model="test", system_prompt="test",
            signer=signer,
        ))
        headers = await identity.sign_http_request(SignHttpRequestParams(
            method="POST",
            url="https://api.example.com/v1/action",
            body='{"action":"approve"}',
            signer=signer,
            agent_did=result.document.id,
        ))
        assert "Signature" in headers
        assert "X-Request-Nonce" not in headers
        valid = await AgentIdentity.verify_http_request_signature(VerifyHttpRequestSignatureParams(
            method="POST",
            url="https://api.example.com/v1/action",
            body='{"action":"approve"}',
            headers=headers,
        ))
        assert valid is True


class TestAgentIdentityHistory:
    async def test_history_after_lifecycle(self, identity: AgentIdentity) -> None:
        result = await identity.create(CreateAgentParams(
            name="H", core_model="m", system_prompt="p",
        ))
        did = result.document.id
        await AgentIdentity.update_did_document(did, UpdateAgentDocumentParams(version="2.0.0"))
        await AgentIdentity.rotate_verification_method(did)

        history = AgentIdentity.get_document_history(did)
        assert len(history) == 3
        assert history[0].action == "created"
        assert history[1].action == "updated"
        assert history[2].action == "rotated-key"

    async def test_export_did_webvh_history_as_jsonl(self, identity: AgentIdentity) -> None:
        result = await identity.create(CreateAgentParams(
            name="HistoryExportBot", core_model="m", system_prompt="p",
        ))
        did = result.document.id

        await AgentIdentity.update_did_document(did, UpdateAgentDocumentParams(version="2.0.0"))
        await AgentIdentity.rotate_verification_method(did)
        await AgentIdentity.revoke_did(did)

        exported = AgentIdentity.export_did_webvh_history(did)
        lines = [json.loads(line) for line in exported.splitlines()]

        # create, update, rotate-key, revoke (deactivation): one controller-signed entry each
        assert len(lines) == 4
        assert [line["versionId"].split("-")[0] for line in lines] == ["1", "2", "3", "4"]
        assert all(line["proof"][0]["cryptosuite"] == "eddsa-jcs-2022" for line in lines)
        assert lines[0]["parameters"]["method"] == "did:webvh:1.0"
        assert lines[0]["state"]["id"] == did
        assert lines[1]["state"]["agentMetadata"]["version"] == "2.0.0"
        assert lines[2]["state"]["authentication"] == [f"{did}#key-2"]
        assert any(method["id"] == f"{did}#key-2" for method in lines[2]["state"]["verificationMethod"])
        assert lines[3]["parameters"]["deactivated"] is True

        verified = await resolve_did_webvh_log(exported, did=did)
        assert verified.metadata.deactivated is True

    async def test_import_did_webvh_history_restores_runtime_state(self, identity: AgentIdentity) -> None:
        result = await identity.create(CreateAgentParams(
            name="HistoryImportBot", core_model="m", system_prompt="p",
        ))
        did = result.document.id

        await AgentIdentity.update_did_document(
            did,
            UpdateAgentDocumentParams(version="2.0.0", description="restored from did log"),
        )
        await AgentIdentity.rotate_verification_method(did)

        did_log = AgentIdentity.export_did_webvh_history(did)

        AgentIdentity.set_resolver(InMemoryDIDResolver())
        AgentIdentity.set_registry(InMemoryAgentRegistry())
        AgentIdentity.get_default_client()._history_store = {}
        AgentIdentity.get_default_client()._did_webvh_log_store = {}
        AgentIdentity.get_default_client()._did_webvh_signer_store = {}
        AgentIdentity.get_default_client()._bootstrap_controllers = {}

        restored = await AgentIdentity.import_did_webvh_history(did_log)
        resolved = await AgentIdentity.resolve(did)
        history = AgentIdentity.get_document_history(did)

        assert restored.id == did
        assert resolved.authentication == [f"{did}#key-2"]
        assert [entry.action for entry in history] == ["created", "updated", "rotated-key"]
        assert AgentIdentity.export_did_webvh_history(did) == did_log

    async def test_persist_and_restore_did_webvh_history_via_file(self, identity: AgentIdentity, tmp_path) -> None:
        result = await identity.create(CreateAgentParams(
            name="HistoryFileBot", core_model="m", system_prompt="p",
        ))
        did = result.document.id

        await AgentIdentity.update_did_document(
            did,
            UpdateAgentDocumentParams(version="2.0.0", description="saved to disk"),
        )
        await AgentIdentity.rotate_verification_method(did)

        did_log_path = tmp_path / "history.did.jsonl"
        AgentIdentity.save_did_webvh_history_to_file(did, did_log_path)
        saved_did_log = did_log_path.read_text(encoding="utf-8")

        AgentIdentity.set_resolver(InMemoryDIDResolver())
        AgentIdentity.set_registry(InMemoryAgentRegistry())
        AgentIdentity.get_default_client()._history_store = {}
        AgentIdentity.get_default_client()._did_webvh_log_store = {}
        AgentIdentity.get_default_client()._did_webvh_signer_store = {}
        AgentIdentity.get_default_client()._bootstrap_controllers = {}

        restored = await AgentIdentity.load_did_webvh_history_from_file(did_log_path)

        assert saved_did_log == AgentIdentity.export_did_webvh_history(did)
        assert restored.authentication == [f"{did}#key-2"]
        assert (await AgentIdentity.resolve(did)).id == did

    async def test_persist_and_restore_did_webvh_history_via_backend_source(self, identity: AgentIdentity) -> None:
        result = await identity.create(CreateAgentParams(
            name="HistorySourceBot", core_model="m", system_prompt="p",
        ))
        did = result.document.id

        await AgentIdentity.update_did_document(
            did,
            UpdateAgentDocumentParams(version="2.0.0", description="saved to source backend"),
        )
        await AgentIdentity.rotate_verification_method(did)

        class InMemoryDidLogSource:
            def __init__(self) -> None:
                self.logs: dict[str, str] = {}
                self.stored_refs: list[str] = []
                self.loaded_refs: list[str] = []

            async def get_by_reference(self, document_ref: str) -> AgentDIDDocument | None:
                await asyncio.sleep(0)
                return None

            async def store_did_log_by_reference(self, document_ref: str, did_log: str) -> None:
                await asyncio.sleep(0)
                self.stored_refs.append(document_ref)
                self.logs[document_ref] = did_log

            async def get_did_log_by_reference(self, document_ref: str) -> str | None:
                await asyncio.sleep(0)
                self.loaded_refs.append(document_ref)
                return self.logs.get(document_ref)

        source = InMemoryDidLogSource()
        document_ref = "history://agentdid/source-bot"

        await AgentIdentity.persist_did_webvh_history_to_source(did, document_ref, source)

        AgentIdentity.set_resolver(InMemoryDIDResolver())
        AgentIdentity.set_registry(InMemoryAgentRegistry())
        AgentIdentity.get_default_client()._history_store = {}
        AgentIdentity.get_default_client()._did_webvh_log_store = {}
        AgentIdentity.get_default_client()._did_webvh_signer_store = {}
        AgentIdentity.get_default_client()._bootstrap_controllers = {}

        restored = await AgentIdentity.restore_did_webvh_history_from_source(document_ref, source)

        assert restored.authentication == [f"{did}#key-2"]
        assert source.stored_refs == [document_ref]
        assert source.loaded_refs == [document_ref]
        assert (await AgentIdentity.resolve(did)).id == did

    async def test_export_did_webvh_history_rejects_legacy_did(self, identity: AgentIdentity) -> None:
        result = await identity.create(CreateAgentParams(
            name="LegacyHistoryBot",
            core_model="m",
            system_prompt="p",
            did_method="agent",
        ))

        with pytest.raises(ValueError, match="did:webvh DID is required"):
            AgentIdentity.export_did_webvh_history(result.document.id)
