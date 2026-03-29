from __future__ import annotations

import asyncio
import sys

from smoke_utils import (
    JsonRpcResponse,
    JsonRpcTestServer,
    build_sample_document,
    reset_agent_identity_state,
)

from agent_did_sdk import AgentIdentity, ProductionJsonRpcResolverProfileConfig
from agent_did_sdk.core.http_security import HttpTargetValidationOptions
from agent_did_sdk.registry.in_memory import InMemoryAgentRegistry
from agent_did_sdk.resolver.in_memory import InMemoryDIDResolver


async def main() -> int:
    reset_agent_identity_state()

    did = "did:agent:polygon:0xha"
    document_ref = "hash://sha256/ha-doc"
    document = build_sample_document(did)

    primary_down = JsonRpcTestServer(
        lambda payload: JsonRpcResponse(
            payload={
                "jsonrpc": "2.0",
                "id": payload.get("id"),
                "error": {"code": -32000, "message": "primary down"},
            },
            http_status=503,
        )
    )

    secondary_not_found = JsonRpcTestServer(
        lambda payload: JsonRpcResponse(
            payload={
                "jsonrpc": "2.0",
                "id": payload.get("id"),
                "error": {"code": -32004, "message": "not found on secondary"},
            }
        )
    )

    def tertiary_handler(payload: dict[str, object]) -> JsonRpcResponse:
        params = payload.get("params") if isinstance(payload.get("params"), list) else []
        requested_ref = params[0] if params else None
        if payload.get("method") != "agent_resolveDocumentRef":
            return JsonRpcResponse(
                payload={
                    "jsonrpc": "2.0",
                    "id": payload.get("id"),
                    "error": {"code": -32601, "message": "method not found"},
                }
            )
        if requested_ref != document_ref:
            return JsonRpcResponse(
                payload={
                    "jsonrpc": "2.0",
                    "id": payload.get("id"),
                    "error": {"code": -32004, "message": "not found"},
                }
            )
        return JsonRpcResponse(
            payload={
                "jsonrpc": "2.0",
                "id": payload.get("id"),
                "result": document.model_dump_jsonld(),
            }
        )

    tertiary_healthy = JsonRpcTestServer(tertiary_handler)

    primary_port = primary_down.start()
    secondary_port = secondary_not_found.start()
    tertiary_port = tertiary_healthy.start()

    try:
        registry = InMemoryAgentRegistry()
        await registry.register(did, document.controller, document_ref)

        AgentIdentity.set_registry(registry)
        AgentIdentity.set_resolver(InMemoryDIDResolver())

        events: list[str] = []
        AgentIdentity.use_production_resolver_from_json_rpc(
            ProductionJsonRpcResolverProfileConfig(
                registry=registry,
                cache_ttl_ms=60_000,
                endpoints=[
                    f"http://127.0.0.1:{primary_port}",
                    f"http://127.0.0.1:{secondary_port}",
                    f"http://127.0.0.1:{tertiary_port}",
                ],
                on_resolution_event=lambda event: events.append(event.stage),
                http_security=HttpTargetValidationOptions(allow_private_targets=True),
            )
        )

        first = await AgentIdentity.resolve(did)
        second = await AgentIdentity.resolve(did)
        if first.id != did or second.id != did:
            raise RuntimeError("DID resolution failed during HA drill")

        required_stages = {"cache-miss", "registry-lookup", "source-fetch", "source-fetched", "resolved", "cache-hit"}
        missing = required_stages.difference(events)
        if missing:
            raise RuntimeError(f"Required HA resolver events missing: {', '.join(sorted(missing))}")

        print("✅ HA resolver drill completed successfully")
        return 0
    finally:
        primary_down.stop()
        secondary_not_found.stop()
        tertiary_healthy.stop()


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
