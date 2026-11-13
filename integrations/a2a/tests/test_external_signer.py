"""A2A requests are signed through an external signer (KMS, HSM) when the agent has one."""

from __future__ import annotations

import pytest
from agent_did_sdk import AgentDidClient, AgentIdentity, AgentIdentityConfig, CreateAgentParams, LocalKeySigner

from agent_did_a2a.jsonrpc import build_task_send_request, sign_a2a_request, verify_a2a_request


class _ExternalSigner:
    """Stands for a KMS or HSM key: the private key never leaves it."""

    def __init__(self) -> None:
        self._inner = LocalKeySigner.generate()[0]

    async def sign(self, payload: bytes) -> str:
        return await self._inner.sign(payload)

    async def get_public_key(self) -> bytes:
        return await self._inner.get_public_key()


@pytest.mark.asyncio
async def test_signs_a2a_requests_through_an_external_signer() -> None:
    client = AgentDidClient()
    identity = AgentIdentity(AgentIdentityConfig(controller_signer=LocalKeySigner.generate()[0], client=client))
    runtime_identity = await identity.create(
        CreateAgentParams(
            name="KmsSender", core_model="gpt-4.1-mini", system_prompt="kms test", signer=_ExternalSigner()
        )
    )
    assert runtime_identity.agent_private_key == ""

    signed = await sign_a2a_request(
        agent_identity=identity,
        runtime_identity=runtime_identity,
        target_url="https://remote-agent.example.com/a2a",
        jsonrpc_request=build_task_send_request(request_id=1, task_id="t-1", message={"role": "user", "parts": []}),
    )

    assert await verify_a2a_request(
        agent_identity=identity, method=signed.method, url=signed.url, headers=dict(signed.headers), body=signed.body
    )
