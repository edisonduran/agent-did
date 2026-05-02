
from __future__ import annotations

import asyncio

from agent_did_sdk import (
    AgentIdentity,
    AgentIdentityConfig,
    CreateAgentParams,
    InMemoryAgentRegistry,
    SignHttpRequestParams,
    VerifyHttpRequestSignatureParams,
)


async def main() -> None:
    # 1. In-memory registry
    AgentIdentity.set_registry(InMemoryAgentRegistry())

    # 2. Create identity
    identity = AgentIdentity(
        AgentIdentityConfig(
            signer_address="0x9292929292929292929292929292929292929292",
        )
    )
    created = await identity.create(
        CreateAgentParams(
            name="example-bot",
            core_model="gpt-4.1-mini",
            system_prompt="Sign outbound API requests.",
        )
    )

    # 3. Sign HTTP request
    headers = await identity.sign_http_request(
        SignHttpRequestParams(
            method="POST",
            url="https://api.example.com/tasks",
            body='{"taskId":7}',
            agent_private_key=created.agent_private_key,
            agent_did=created.document.id,
        )
    )

    # 4. Verify HTTP request
    ok = await AgentIdentity.verify_http_request_signature(
        VerifyHttpRequestSignatureParams(
            method="POST",
            url="https://api.example.com/tasks",
            body='{"taskId":7}',
            headers=headers,
        )
    )

    assert ok, "signature verification should succeed"

    print({
        "did": created.document.id,
        "ok": ok,
        "header_names": sorted(headers.keys()),
    })


if __name__ == "__main__":
    asyncio.run(main())
