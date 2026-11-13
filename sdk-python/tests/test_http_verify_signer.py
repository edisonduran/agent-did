"""Who signed an HTTP request and whom to accept (parity: sdk/tests/HttpVerifySigner.test.ts)."""

from __future__ import annotations

from typing import Any
from unittest.mock import patch

from agent_did_sdk.core.client import AgentDidClient
from agent_did_sdk.core.identity import AgentIdentity, AgentIdentityConfig
from agent_did_sdk.core.nonce_store import InMemoryNonceStore
from agent_did_sdk.core.signer import LocalKeySigner
from agent_did_sdk.core.types import CreateAgentParams, SignHttpRequestParams, VerifyHttpRequestSignatureParams

OTHER_AGENT = "did:webvh:QmOther:example.com:agents:other"
OTHER_CONTROLLER = "did:webvh:QmOther:example.com:organizations:other"


async def _signed_request() -> tuple[AgentDidClient, Any, dict[str, Any]]:
    client = AgentDidClient()
    identity = AgentIdentity(AgentIdentityConfig(controller_signer=LocalKeySigner.generate()[0], client=client))
    result = await identity.create(CreateAgentParams(name="SignerBot", core_model="test", system_prompt="test"))
    did = result.document.id
    request = {"method": "POST", "url": "https://api.example.com/v1/tasks?x=1", "body": '{"task":1}'}
    headers = await identity.sign_http_request(SignHttpRequestParams(
        **request,
        agent_did=did,
        agent_private_key=result.agent_private_key,
        verification_method_id=f"{did}#key-1",
    ))
    return client, result.document, {**request, "headers": headers}


def _params(request: dict[str, Any], **extra: Any) -> VerifyHttpRequestSignatureParams:
    store = extra.pop("nonce_store", InMemoryNonceStore())
    return VerifyHttpRequestSignatureParams(**request, nonce_store=store, **extra)


async def test_returns_the_signer_did_the_key_and_the_controller_chain() -> None:
    client, document, request = await _signed_request()

    result = await client.verify_http_request_signature_detailed(_params(request))

    assert result.ok is True
    assert result.did == document.id
    assert result.key_id == f"{document.id}#key-1"
    assert result.controllers == [document.controller]


async def test_rejects_a_did_outside_allowed_dids_before_resolving_it() -> None:
    client, document, request = await _signed_request()

    with patch.object(client, "resolve", wraps=client.resolve) as resolve:
        refused = await client.verify_http_request_signature_detailed(_params(request, allowed_dids=[OTHER_AGENT]))
        assert refused.ok is False
        assert refused.reason == "did_not_allowed"
        resolve.assert_not_called()

    accepted = await client.verify_http_request_signature_detailed(_params(request, allowed_dids=[document.id]))
    assert accepted.ok is True


async def test_accepts_only_agents_under_an_allowed_controller_without_burning_the_nonce() -> None:
    client, document, request = await _signed_request()
    store = InMemoryNonceStore()

    refused = await client.verify_http_request_signature_detailed(
        _params(request, allowed_controllers=[OTHER_CONTROLLER], nonce_store=store)
    )
    assert refused.ok is False
    assert refused.reason == "controller_not_allowed"

    accepted = await client.verify_http_request_signature_detailed(
        _params(request, allowed_controllers=[document.controller], nonce_store=store)
    )
    assert accepted.ok is True


async def test_applies_both_lists_when_both_are_set() -> None:
    client, document, request = await _signed_request()

    result = await client.verify_http_request_signature_detailed(
        _params(request, allowed_dids=[document.id], allowed_controllers=[OTHER_CONTROLLER])
    )

    assert result.ok is False
    assert result.reason == "controller_not_allowed"
