"""The external signer of an agent key in create / rotate results (parity: sdk/tests/ResultSigner.test.ts)."""

from __future__ import annotations

from agent_did_sdk.core.client import AgentDidClient
from agent_did_sdk.core.identity import AgentIdentity, AgentIdentityConfig
from agent_did_sdk.core.signer import LocalKeySigner
from agent_did_sdk.core.types import CreateAgentParams


async def test_is_carried_by_the_result_without_being_serialized() -> None:
    client = AgentDidClient()
    identity = AgentIdentity(AgentIdentityConfig(controller_signer=LocalKeySigner.generate()[0], client=client))
    external = LocalKeySigner.generate()[0]
    created = await identity.create(
        CreateAgentParams(name="KmsBot", core_model="test", system_prompt="test", signer=external)
    )

    assert created.signer is external
    assert created.agent_private_key == ""
    assert "signer" not in created.model_dump()
    assert "signer" not in created.model_dump_json()

    following = LocalKeySigner.generate()[0]
    rotated = await client.rotate_verification_method(created.document.id, signer=following)
    assert rotated.signer is following
    assert rotated.agent_private_key == ""

    local = await client.rotate_verification_method(created.document.id)
    assert local.signer is None
    assert len(local.agent_private_key) == 64
