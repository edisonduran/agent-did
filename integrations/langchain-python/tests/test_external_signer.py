"""An agent whose key lives in an external signer (KMS, HSM) works through the integration tools."""

from __future__ import annotations

import pytest
from agent_did_sdk import (
    AgentDidClient,
    AgentIdentity,
    AgentIdentityConfig,
    CreateAgentParams,
    LocalKeySigner,
)

from agent_did_langchain import create_agent_did_langchain_integration


class _ExternalSigner:
    """Stands for a KMS or HSM key: the private key never leaves it."""

    def __init__(self) -> None:
        self._inner = LocalKeySigner.generate()[0]

    async def sign(self, payload: bytes) -> str:
        return await self._inner.sign(payload)

    async def get_public_key(self) -> bytes:
        return await self._inner.get_public_key()


@pytest.mark.asyncio
async def test_signs_through_an_external_signer_and_refuses_tool_rotation() -> None:
    client = AgentDidClient()
    identity = AgentIdentity(AgentIdentityConfig(controller_signer=LocalKeySigner.generate()[0], client=client))
    runtime_identity = await identity.create(
        CreateAgentParams(name="KmsBot", core_model="gpt-4.1-mini", system_prompt="kms test", signer=_ExternalSigner())
    )
    assert runtime_identity.agent_private_key == ""

    integration = create_agent_did_langchain_integration(
        agent_identity=identity,
        runtime_identity=runtime_identity,
        expose={"sign_payload": True, "sign_http": True, "rotate_keys": True},
    )
    tools_by_name = {tool.name: tool for tool in integration.tools}

    signed = await tools_by_name["agent_did_sign_payload"].ainvoke({"payload": "approve:1"})
    assert "error" not in signed
    assert await client.verify_signature(runtime_identity.document.id, "approve:1", signed["signature"]) is True

    headers = await tools_by_name["agent_did_sign_http_request"].ainvoke(
        {"method": "POST", "url": "https://api.example.com/v1/tasks", "body": "{}"}
    )
    assert "error" not in headers

    rotated = await tools_by_name["agent_did_rotate_key"].ainvoke({})
    assert "external signer" in rotated["error"]
