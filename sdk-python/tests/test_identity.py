"""Tests for AgentIdentity — the main SDK class."""

from __future__ import annotations

import httpx
import pytest

from agent_did_sdk import InMemoryAgentRegistry, ProductionHttpResolverProfileConfig
from agent_did_sdk.core.identity import AgentIdentity, AgentIdentityConfig
from agent_did_sdk.core.types import (
    CreateAgentParams,
    SignHttpRequestParams,
    UpdateAgentDocumentParams,
    VerifyHttpRequestSignatureParams,
)


@pytest.fixture()
def identity() -> AgentIdentity:
    return AgentIdentity(AgentIdentityConfig(signer_address="0xTestController1234567890"))


class TestAgentIdentityCreate:
    async def test_create_valid_agent(self, identity: AgentIdentity) -> None:
        result = await identity.create(CreateAgentParams(
            name="TestBot",
            core_model="gpt-4-turbo",
            system_prompt="You are helpful.",
        ))
        doc = result.document
        assert doc.id.startswith("did:agent:polygon:")
        assert doc.controller.startswith("did:ethr:")
        assert doc.agent_metadata.name == "TestBot"
        assert doc.agent_metadata.version == "1.0.0"
        assert doc.created.endswith("Z")
        assert doc.updated.endswith("Z")
        assert len(doc.verification_method) == 1
        assert doc.verification_method[0].public_key_multibase is not None
        assert len(result.agent_private_key) == 64  # 32 bytes hex

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

    async def test_sign_http_missing_method(self, identity: AgentIdentity) -> None:
        with pytest.raises(ValueError, match="method"):
            await identity.sign_http_request(SignHttpRequestParams(
                method="", url="https://example.com", body=None,
                agent_private_key="aa" * 32, agent_did="did:agent:test",
            ))

    async def test_anti_replay_headers_present(self, identity: AgentIdentity) -> None:
        result = await identity.create(CreateAgentParams(
            name="AntiReplayBot", core_model="m", system_prompt="p",
        ))
        headers = await identity.sign_http_request(SignHttpRequestParams(
            method="POST",
            url="https://api.example.com/v1/test",
            body='{"nonce":true}',
            agent_private_key=result.agent_private_key,
            agent_did=result.document.id,
            expires_in_seconds=60,
        ))
        assert "X-Request-Nonce" in headers
        assert len(headers["X-Request-Nonce"]) > 0
        assert '"x-request-nonce"' in headers["Signature-Input"]
        assert "expires=" in headers["Signature-Input"]

        is_valid = await AgentIdentity.verify_http_request_signature(
            VerifyHttpRequestSignatureParams(
                method="POST",
                url="https://api.example.com/v1/test",
                body='{"nonce":true}',
                headers=headers,
            )
        )
        assert is_valid is True

    async def test_reject_expired_signature(self, identity: AgentIdentity) -> None:
        result = await identity.create(CreateAgentParams(
            name="ExpiredBot", core_model="m", system_prompt="p",
        ))
        headers = await identity.sign_http_request(SignHttpRequestParams(
            method="POST",
            url="https://api.example.com/v1/test",
            body='{"expired":true}',
            agent_private_key=result.agent_private_key,
            agent_did=result.document.id,
            expires_in_seconds=1,
        ))
        import re
        headers["Signature-Input"] = re.sub(r"expires=\d+", "expires=1000000000", headers["Signature-Input"])

        is_valid = await AgentIdentity.verify_http_request_signature(
            VerifyHttpRequestSignatureParams(
                method="POST",
                url="https://api.example.com/v1/test",
                body='{"expired":true}',
                headers=headers,
            )
        )
        assert is_valid is False

    async def test_reject_missing_nonce_header(self, identity: AgentIdentity) -> None:
        result = await identity.create(CreateAgentParams(
            name="NoNonceBot", core_model="m", system_prompt="p",
        ))
        headers = await identity.sign_http_request(SignHttpRequestParams(
            method="POST",
            url="https://api.example.com/v1/test",
            body='{"no-nonce":true}',
            agent_private_key=result.agent_private_key,
            agent_did=result.document.id,
        ))
        del headers["X-Request-Nonce"]

        is_valid = await AgentIdentity.verify_http_request_signature(
            VerifyHttpRequestSignatureParams(
                method="POST",
                url="https://api.example.com/v1/test",
                body='{"no-nonce":true}',
                headers=headers,
            )
        )
        assert is_valid is False


class TestAgentIdentityResolve:
    async def test_resolve_existing(self, identity: AgentIdentity) -> None:
        result = await identity.create(CreateAgentParams(
            name="Resolvable", core_model="m", system_prompt="p",
        ))
        doc = await AgentIdentity.resolve(result.document.id)
        assert doc.id == result.document.id

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
        valid = await AgentIdentity.verify_historical_signature(
            result.document.id, "payload", fake_sig, f"{result.document.id}#key-999",
        )
        assert valid is False


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
        assert "X-Request-Nonce" in headers
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
