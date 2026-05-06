from __future__ import annotations

import httpx
import pytest
from agent_did_sdk import (
    AgentDIDDocument,
    AgentIdentity,
    AgentIdentityConfig,
    CreateAgentResult,
    InMemoryAgentRegistry,
    ProductionHttpResolverProfileConfig,
    VerifyHttpRequestSignatureParams,
)
from nacl.signing import SigningKey

from agent_did_langchain import create_agent_did_langchain_integration

ACTIVE_DID = "did:wba:agents.example:profiles:weather-bot"
PARTNER_DID = "did:wba:agents.example:partners:dispatch-router"
ACTIVE_DOCUMENT_URL = "https://agents.example/profiles/weather-bot/did.json"
PARTNER_DOCUMENT_URL = "https://agents.example/partners/dispatch-router/did.json"
SIGNED_REQUEST_URL = "https://api.example.com/tasks"
SIGNED_REQUEST_BODY = '{"taskId":42,"route":"storm-front"}'


def _build_did_document(
    *,
    did: str,
    name: str,
    description: str,
    public_key_multibase: str,
    capabilities: list[str],
) -> AgentDIDDocument:
    return AgentDIDDocument(
        **{
            "@context": ["https://www.w3.org/ns/did/v1", "https://agent-did.org/v1"],
            "id": did,
            "controller": "did:web:agents.example",
            "created": "2026-03-22T00:00:00Z",
            "updated": "2026-03-22T00:00:00Z",
            "agentMetadata": {
                "name": name,
                "description": description,
                "version": "1.0.0",
                "coreModelHash": f"hash://sha256/{name.lower()}-model",
                "systemPromptHash": f"hash://sha256/{name.lower()}-prompt",
                "capabilities": capabilities,
            },
            "verificationMethod": [
                {
                    "id": f"{did}#key-1",
                    "type": "Ed25519VerificationKey2020",
                    "controller": "did:web:agents.example",
                    "publicKeyMultibase": public_key_multibase,
                }
            ],
            "authentication": [f"{did}#key-1"],
            "assertionMethod": [f"{did}#key-1"],
        }
    )


def _build_runtime_identity() -> CreateAgentResult:
    signing_key = SigningKey.generate()
    document = _build_did_document(
        did=ACTIVE_DID,
        name="WeatherBot",
        description="did:wba runtime identity for integrated LangChain testing",
        public_key_multibase=f"z{signing_key.verify_key.encode().hex()}",
        capabilities=["weather:forecast", "http:sign", "partner:resolve"],
    )
    return CreateAgentResult(document=document, agentPrivateKey=signing_key.encode().hex())


def _build_partner_document() -> AgentDIDDocument:
    signing_key = SigningKey.generate()
    return _build_did_document(
        did=PARTNER_DID,
        name="DispatchRouter",
        description="Remote did:wba partner resolved over HTTPS",
        public_key_multibase=f"z{signing_key.verify_key.encode().hex()}",
        capabilities=["dispatch:receive", "dispatch:ack"],
    )


def _mock_send(request: httpx.Request, documents_by_url: dict[str, AgentDIDDocument]) -> httpx.Response:
    document = documents_by_url.get(str(request.url))
    if document is None:
        return httpx.Response(status_code=404, json={})
    return httpx.Response(status_code=200, json=document.model_dump(by_alias=True, exclude_none=True))


@pytest.mark.asyncio
async def test_did_wba_runtime_identity_supports_resolve_and_http_signature_verification() -> None:
    registry = InMemoryAgentRegistry()
    runtime_identity = _build_runtime_identity()
    partner_document = _build_partner_document()
    documents_by_url = {
        ACTIVE_DOCUMENT_URL: runtime_identity.document,
        PARTNER_DOCUMENT_URL: partner_document,
    }
    resolution_events: list[tuple[str, str]] = []

    AgentIdentity.set_registry(registry)

    transport = httpx.MockTransport(lambda request: _mock_send(request, documents_by_url))
    async with httpx.AsyncClient(transport=transport) as http_client:
        AgentIdentity.use_production_resolver_from_http(
            ProductionHttpResolverProfileConfig(
                registry=registry,
                http_client=http_client,
                on_resolution_event=lambda event: resolution_events.append((event.did, event.stage)),
            )
        )

        identity = AgentIdentity(AgentIdentityConfig(signer_address="0x9898989898989898989898989898989898989898"))
        integration = create_agent_did_langchain_integration(
            agent_identity=identity,
            runtime_identity=runtime_identity,
            expose={"sign_http": True},
        )
        tools_by_name = {tool.name: tool for tool in integration.tools}

        current_identity = await tools_by_name["agent_did_get_current_identity"].ainvoke({})
        resolved_partner = await tools_by_name["agent_did_resolve_did"].ainvoke({"did": PARTNER_DID})
        signed_request = await tools_by_name["agent_did_sign_http_request"].ainvoke(
            {"method": "POST", "url": SIGNED_REQUEST_URL, "body": SIGNED_REQUEST_BODY}
        )
        verified = await AgentIdentity.verify_http_request_signature(
            VerifyHttpRequestSignatureParams(
                method="POST",
                url=SIGNED_REQUEST_URL,
                body=SIGNED_REQUEST_BODY,
                headers=signed_request["headers"],
            )
        )

    assert current_identity["did"] == ACTIVE_DID
    assert resolved_partner["id"] == PARTNER_DID
    assert resolved_partner["agentMetadata"]["name"] == "DispatchRouter"
    assert signed_request["did"] == ACTIVE_DID
    assert verified is True
    assert (PARTNER_DID, "resolved") in resolution_events
    assert (ACTIVE_DID, "resolved") in resolution_events
