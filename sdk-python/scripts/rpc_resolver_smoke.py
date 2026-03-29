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

    did = "did:agent:polygon:0xrpcsmoke"
    document_ref = "hash://sha256/rpc-smoke-doc"
    sample_document = build_sample_document(did)

    failing_server = JsonRpcTestServer(
        lambda payload: JsonRpcResponse(
            payload={
                "jsonrpc": "2.0",
                "id": payload.get("id"),
                "error": {"code": -32000, "message": "temporary unavailable"},
            },
            http_status=503,
        )
    )

    def healthy_handler(payload: dict[str, object]) -> JsonRpcResponse:
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
                    "error": {"code": -32004, "message": "document not found"},
                }
            )
        return JsonRpcResponse(
            payload={
                "jsonrpc": "2.0",
                "id": payload.get("id"),
                "result": sample_document.model_dump_jsonld(),
            }
        )

    healthy_server = JsonRpcTestServer(healthy_handler)

    failing_port = failing_server.start()
    healthy_port = healthy_server.start()

    try:
        registry = InMemoryAgentRegistry()
        await registry.register(did, sample_document.controller, document_ref)

        AgentIdentity.set_registry(registry)
        AgentIdentity.set_resolver(InMemoryDIDResolver())

        events: list[str] = []
        AgentIdentity.use_production_resolver_from_json_rpc(
            ProductionJsonRpcResolverProfileConfig(
                registry=registry,
                endpoints=[f"http://127.0.0.1:{failing_port}", f"http://127.0.0.1:{healthy_port}"],
                on_resolution_event=lambda event: events.append(event.stage),
                http_security=HttpTargetValidationOptions(allow_private_targets=True),
            )
        )

        resolved = await AgentIdentity.resolve(did)
        if resolved.id != did:
            raise RuntimeError(f"Resolved DID mismatch. Expected {did}, got {resolved.id}")
        if "source-fetch" not in events or "resolved" not in events:
            raise RuntimeError(f"Expected resolver events not emitted. Events: {', '.join(events)}")

        print("✅ RPC resolver smoke test completed successfully")
        return 0
    finally:
        failing_server.stop()
        healthy_server.stop()


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
