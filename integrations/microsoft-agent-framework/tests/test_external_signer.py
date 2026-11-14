"""Handoffs and tools sign through an external signer (KMS, HSM) when the agent has one."""

from __future__ import annotations

import asyncio

from agent_did_sdk import AgentDidClient, AgentIdentity, AgentIdentityConfig, CreateAgentParams, LocalKeySigner

from agent_did_microsoft_agent_framework import create_agent_did_microsoft_agent_framework_integration
from agent_did_microsoft_agent_framework.handoff import build_handoff_envelope, sign_handoff


class _ExternalSigner:
    """Stands for a KMS or HSM key: the private key never leaves it."""

    def __init__(self) -> None:
        self._inner = LocalKeySigner.generate()[0]

    async def sign(self, payload: bytes) -> str:
        return await self._inner.sign(payload)

    async def get_public_key(self) -> bytes:
        return await self._inner.get_public_key()


def test_signs_handoffs_and_payloads_through_an_external_signer_and_refuses_tool_rotation() -> None:
    async def scenario() -> None:
        client = AgentDidClient()
        identity = AgentIdentity(AgentIdentityConfig(controller_signer=LocalKeySigner.generate()[0], client=client))
        runtime_identity = await identity.create(
            CreateAgentParams(name="KmsPlanner", core_model="test", system_prompt="kms test", signer=_ExternalSigner())
        )
        did = runtime_identity.document.id
        assert runtime_identity.agent_private_key == ""

        message = await sign_handoff(
            agent_identity=identity, runtime_identity=runtime_identity, payload={"task": 1}, destination="writer"
        )
        envelope = build_handoff_envelope(
            did=did,
            key_id=message.key_id,
            signed_at=message.signed_at,
            destination="writer",
            nonce=str(message.nonce),
            payload={"task": 1},
        )
        assert await client.verify_signature(did, envelope, message.signature, message.key_id) is True

        integration = create_agent_did_microsoft_agent_framework_integration(
            agent_identity=identity,
            runtime_identity=runtime_identity,
            expose={"sign_payload": True, "rotate_keys": True},
        )
        signed = await integration.get_tool("agent_did_sign_payload").func(payload="approve:1")
        assert await client.verify_signature(did, "approve:1", signed["signature"]) is True
        rotated = await integration.get_tool("agent_did_rotate_key").func()
        assert "external signer" in str(rotated)

    asyncio.run(scenario())
