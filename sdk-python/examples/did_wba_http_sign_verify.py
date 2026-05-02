"""End-to-end example: create a did:wba agent, sign an HTTP request, and verify
the signature using a mock HTTP resolver — no live network required."""

from __future__ import annotations

import asyncio
import httpx

from agent_did_sdk import (
    AgentIdentity,
    AgentIdentityConfig,
    CreateAgentParams,
    InMemoryAgentRegistry,
    ProductionHttpResolverProfileConfig,
    SignHttpRequestParams,
    VerifyHttpRequestSignatureParams,
)


async def main() -> None:
    # 1. Set up registry and identity
    registry = InMemoryAgentRegistry()
    AgentIdentity.set_registry(registry)

    identity = AgentIdentity(
        AgentIdentityConfig(
            signer_address="0x9292929292929292929292929292929292929292"
        )
    )

    created = await identity.create(
        CreateAgentParams(
            name="wba-example",
            core_model="gpt-4.1-mini",
            system_prompt="Sign outbound API requests.",
        )
    )

    # 2. Prepare DID document and expected resolution URL
    did_doc = created.document

    # Extract path from DID (did:wba:example.com:agent → agent)
    did_suffix = created.document.id.split(":")[-1]
    expected_url = f"https://example.com/{did_suffix}/did.json"

    # 3. Mock HTTP resolver
    def handler(request: httpx.Request) -> httpx.Response:
        if str(request.url) == expected_url:
            # Depending on SDK version: use model_dump() or dict()
            try:
                return httpx.Response(200, json=did_doc.model_dump())
            except AttributeError:
                return httpx.Response(200, json=did_doc.dict())
        return httpx.Response(404, json={})

    transport = httpx.MockTransport(handler)

    # 4. Setup resolver with AsyncClient
    async with httpx.AsyncClient(transport=transport) as http_client:
        AgentIdentity.use_production_resolver_from_http(
            ProductionHttpResolverProfileConfig(
                registry=registry,
                http_client=http_client,
            )
        )

        # 5. Sign HTTP request
        headers = await identity.sign_http_request(
            SignHttpRequestParams(
                method="POST",
                url="https://api.example.com/tasks",
                body='{"taskId":7}',
                agent_private_key=created.agent_private_key,
                agent_did=created.document.id,
            )
        )

        # 6. Verify HTTP request (resolver will fetch DID via mock)
        ok = await AgentIdentity.verify_http_request_signature(
            VerifyHttpRequestSignatureParams(
                method="POST",
                url="https://api.example.com/tasks",
                body='{"taskId":7}',
                headers=headers,
            )
        )

        # 7. Assert and print result
        assert ok, "signature verification should succeed"

        print({
            "did": created.document.id,
            "ok": ok,
            "header_names": sorted(headers.keys()),
        })


if __name__ == "__main__":
    asyncio.run(main())
