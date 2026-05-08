from __future__ import annotations

import asyncio
import json
import sys

import httpx

from smoke_utils import (
    reset_agent_identity_state,
)

from agent_did_sdk import AgentIdentity, ProductionHttpResolverProfileConfig
from agent_did_sdk.core.http_security import HttpTargetValidationOptions
from agent_did_sdk.registry.in_memory import InMemoryAgentRegistry
from agent_did_sdk.resolver.in_memory import InMemoryDIDResolver


async def main() -> int:
    reset_agent_identity_state()

    did = "did:webvh:QmHaDrillScid:agents.example:profiles:ha-bot"
    document = {
        "@context": ["https://www.w3.org/ns/did/v1", "https://agent-did.org/v1"],
        "id": did,
        "controller": "did:webvh:QmHaControllerScid:agents.example:organizations:ops-root",
        "created": "2026-01-01T00:00:00.000Z",
        "updated": "2026-01-01T00:00:00.000Z",
        "agentMetadata": {
            "name": "HaDrillBot",
            "version": "1.0.0",
            "coreModelHash": "hash://sha256/model",
            "systemPromptHash": "hash://sha256/prompt",
        },
        "verificationMethod": [
            {
                "id": f"{did}#key-1",
                "type": "Ed25519VerificationKey2020",
                "controller": did,
                "publicKeyMultibase": "zabc",
            }
        ],
        "authentication": [f"{did}#key-1"],
        "assertionMethod": [f"{did}#key-1"],
    }
    did_log = "\n".join([
        json.dumps({"versionId": "1-QmHaDrillScid", "state": {**document, "updated": "2025-12-31T00:00:00.000Z"}}),
        json.dumps({"versionId": "2-QmHaDrillScid", "state": document}),
    ])
    candidate_urls = [
        "https://resolver-primary.example/profiles/ha-bot/did.jsonl",
        "https://resolver-secondary.example/profiles/ha-bot/did.jsonl",
        "https://resolver-tertiary.example/profiles/ha-bot/did.jsonl",
    ]
    requested_urls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requested_urls.append(str(request.url))
        if str(request.url) == candidate_urls[0]:
            return httpx.Response(503)
        if str(request.url) == candidate_urls[1]:
            return httpx.Response(404)
        if str(request.url) == candidate_urls[2]:
            return httpx.Response(200, text=did_log)
        return httpx.Response(500, text="unexpected URL")

    registry = InMemoryAgentRegistry()
    AgentIdentity.set_registry(registry)
    AgentIdentity.set_resolver(InMemoryDIDResolver())

    events: list[str] = []
    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http_client:
        AgentIdentity.use_production_resolver_from_http(
            ProductionHttpResolverProfileConfig(
                registry=registry,
                cache_ttl_ms=60_000,
                reference_to_urls=lambda _document_ref: candidate_urls,
                http_client=http_client,
                on_resolution_event=lambda event: events.append(event.stage),
                http_security=HttpTargetValidationOptions(),
            )
        )

        first = await AgentIdentity.resolve(did)
        second = await AgentIdentity.resolve(did)
        if first.id != did or second.id != did:
            raise RuntimeError("DID resolution failed during HA drill")

    required_stages = {"cache-miss", "source-fetch", "source-fetched", "resolved", "cache-hit"}
    missing = required_stages.difference(events)
    if missing:
        raise RuntimeError(f"Required HA resolver events missing: {', '.join(sorted(missing))}")

    if requested_urls != candidate_urls:
        raise RuntimeError(f"Failover did:webvh did not visit expected candidate URLs: {requested_urls}")

    print("✅ HA resolver drill completed successfully")
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
