from __future__ import annotations

import asyncio

import httpx

from agent_did_sdk import (
    AgentIdentity,
    InMemoryAgentRegistry,
    ProductionHttpResolverProfileConfig,
)

DID = "did:wba:agents.example:profiles:weather-bot"
EXPECTED_URL = "https://agents.example/profiles/weather-bot/did.json"

DID_DOCUMENT = {
    "@context": ["https://www.w3.org/ns/did/v1", "https://agent-did.org/v1"],
    "id": DID,
    "controller": "did:web:agents.example",
    "created": "2026-03-22T00:00:00Z",
    "updated": "2026-03-22T00:00:00Z",
    "agentMetadata": {
        "name": "WeatherBot",
        "description": "Minimal did:wba example",
        "version": "1.0.0",
        "coreModelHash": "hash://sha256/weather-model",
        "systemPromptHash": "hash://sha256/weather-prompt",
    },
    "verificationMethod": [
        {
            "id": f"{DID}#key-1",
            "type": "Ed25519VerificationKey2020",
            "controller": "did:web:agents.example",
            "publicKeyMultibase": "z6MkexampleWeatherBotKey",
        }
    ],
    "authentication": [f"{DID}#key-1"],
}


def _mock_send(request: httpx.Request) -> httpx.Response:
    if str(request.url) != EXPECTED_URL:
        return httpx.Response(status_code=404, json={})
    return httpx.Response(status_code=200, json=DID_DOCUMENT)


async def main() -> None:
    transport = httpx.MockTransport(_mock_send)
    async with httpx.AsyncClient(transport=transport) as http_client:
        AgentIdentity.set_registry(InMemoryAgentRegistry())
        AgentIdentity.use_production_resolver_from_http(
            ProductionHttpResolverProfileConfig(
                registry=InMemoryAgentRegistry(),
                http_client=http_client,
                on_resolution_event=lambda event: print(f"[resolver:{event.stage}] {event.message or ''}"),
            )
        )

        resolved = await AgentIdentity.resolve(DID)

        print("Resolved DID:", resolved.id)
        print("Resolved from:", EXPECTED_URL)
        print("Agent name:", resolved.agent_metadata.name)


if __name__ == "__main__":
    asyncio.run(main())
