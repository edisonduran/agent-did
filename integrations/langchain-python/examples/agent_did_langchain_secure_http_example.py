"""Secure HTTP signing and verification example for Agent-DID LangChain Python."""

from __future__ import annotations

import asyncio
import json

from agent_did_sdk import (
    AgentIdentity,
    AgentIdentityConfig,
    CreateAgentParams,
    InMemoryAgentRegistry,
    LocalKeySigner,
    VerifyHttpRequestSignatureParams,
)

from agent_did_langchain import create_agent_did_langchain_integration


async def main() -> None:
    AgentIdentity.set_registry(InMemoryAgentRegistry())

    identity = AgentIdentity(AgentIdentityConfig(controller_signer=LocalKeySigner.generate()[0]))
    runtime_identity = await identity.create(
        CreateAgentParams(
            name="http_signer_bot",
            description="HTTP signing demo for Agent-DID tools",
            core_model="gpt-4.1-mini",
            system_prompt="Sign only explicit outbound requests.",
            capabilities=["http:sign", "http:verify"],
        )
    )

    integration = create_agent_did_langchain_integration(
        agent_identity=identity,
        runtime_identity=runtime_identity,
        expose={"sign_http": True},
    )
    tool = {tool.name: tool for tool in integration.tools}["agent_did_sign_http_request"]

    signed = await tool.ainvoke(
        {
            "method": "POST",
            "url": "https://api.example.com/tasks",
            "body": '{"taskId":7}',
        }
    )

    is_valid = await AgentIdentity.verify_http_request_signature(
        VerifyHttpRequestSignatureParams(
            method="POST",
            url="https://api.example.com/tasks",
            body='{"taskId":7}',
            headers=signed["headers"],
        )
    )

    print(json.dumps({"signed": signed, "verified": is_valid}, indent=2))


if __name__ == "__main__":
    asyncio.run(main())
