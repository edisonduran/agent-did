"""Integrated did:wba + LangChain Python demo for Agent-DID."""

from __future__ import annotations

import asyncio
import json
from typing import Any

import httpx
from agent_did_sdk import (
    AgentDIDDocument,
    AgentIdentity,
    AgentIdentityConfig,
    CreateAgentResult,
    InMemoryAgentRegistry,
    ProductionHttpResolverProfileConfig,
    VerifyHttpRequestSignatureParams,
)
from langchain.agents import create_agent
from langchain_core.language_models.fake_chat_models import FakeMessagesListChatModel
from langchain_core.messages import AIMessage
from nacl.signing import SigningKey

from agent_did_langchain import create_agent_did_langchain_integration

ACTIVE_DID = "did:wba:agents.example:profiles:weather-bot"
PARTNER_DID = "did:wba:agents.example:partners:dispatch-router"
ACTIVE_DOCUMENT_URL = "https://agents.example/profiles/weather-bot/did.json"
PARTNER_DOCUMENT_URL = "https://agents.example/partners/dispatch-router/did.json"
SIGNED_REQUEST_URL = "https://api.example.com/tasks"
SIGNED_REQUEST_BODY = '{"taskId":42,"route":"storm-front"}'


class ToolReadyFakeMessagesListChatModel(FakeMessagesListChatModel):
    """Fake chat model that satisfies create_agent tool binding for local demos."""

    def bind_tools(self, tools: list[Any], **kwargs: Any) -> ToolReadyFakeMessagesListChatModel:
        return self


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
        description="Integrated did:wba runtime identity for LangChain Python",
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


async def main() -> None:
    registry = InMemoryAgentRegistry()
    runtime_identity = _build_runtime_identity()
    partner_document = _build_partner_document()
    documents_by_url = {
        ACTIVE_DOCUMENT_URL: runtime_identity.document,
        PARTNER_DOCUMENT_URL: partner_document,
    }
    resolution_events: list[dict[str, str | None]] = []

    AgentIdentity.set_registry(registry)

    transport = httpx.MockTransport(lambda request: _mock_send(request, documents_by_url))
    async with httpx.AsyncClient(transport=transport) as http_client:
        AgentIdentity.use_production_resolver_from_http(
            ProductionHttpResolverProfileConfig(
                registry=registry,
                http_client=http_client,
                on_resolution_event=lambda event: resolution_events.append(
                    {"did": event.did, "stage": event.stage, "message": event.message}
                ),
            )
        )

        identity = AgentIdentity(AgentIdentityConfig(signer_address="0x9797979797979797979797979797979797979797"))
        integration = create_agent_did_langchain_integration(
            agent_identity=identity,
            runtime_identity=runtime_identity,
            expose={"sign_http": True},
            additional_system_context=(
                "Resolve remote did:wba partners before delegating work and sign only explicit outbound HTTP requests."
            ),
        )
        tools_by_name = {tool.name: tool for tool in integration.tools}

        fake_model = ToolReadyFakeMessagesListChatModel(
            responses=[
                AIMessage(
                    content="",
                    tool_calls=[
                        {
                            "name": "agent_did_get_current_identity",
                            "args": {},
                            "id": "call_identity",
                            "type": "tool_call",
                        },
                        {
                            "name": "agent_did_resolve_did",
                            "args": {"did": PARTNER_DID},
                            "id": "call_partner",
                            "type": "tool_call",
                        },
                        {
                            "name": "agent_did_sign_http_request",
                            "args": {
                                "method": "POST",
                                "url": SIGNED_REQUEST_URL,
                                "body": SIGNED_REQUEST_BODY,
                            },
                            "id": "call_http",
                            "type": "tool_call",
                        },
                    ],
                ),
                AIMessage(
                    content=(
                        "Identidad local inspeccionada, contraparte did:wba resuelta y solicitud HTTP "
                        "preparada con firma Agent-DID."
                    )
                ),
            ]
        )

        agent = create_agent(
            model=fake_model,
            tools=integration.tools,
            system_prompt=integration.compose_system_prompt(
                "Usa herramientas Agent-DID antes de declarar identidad, confianza o autorizacion."
            ),
        )
        agent_result = await agent.ainvoke(
            {
                "messages": [
                    {
                        "role": "user",
                        "content": (
                            "Identifica tu DID actual, resuelve a tu partner did:wba y prepara una firma HTTP para "
                            "POST https://api.example.com/tasks con body {\"taskId\":42,\"route\":\"storm-front\"}."
                        ),
                    }
                ]
            }
        )

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

        final_message = getattr(agent_result["messages"][-1], "content", str(agent_result["messages"][-1]))
        summary = {
            "active_did": current_identity["did"],
            "partner_did": resolved_partner["id"],
            "partner_name": resolved_partner["agentMetadata"]["name"],
            "http_signature_verified": verified,
            "signed_header_names": sorted(signed_request["headers"].keys()),
            "agent_final_message": final_message,
            "resolution_events": resolution_events,
        }
        print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    asyncio.run(main())
