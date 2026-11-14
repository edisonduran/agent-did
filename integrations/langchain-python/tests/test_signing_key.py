"""The integration signs with an assertionMethod key, which is what verifiers require."""

from __future__ import annotations

import pytest
from agent_did_sdk import AgentDidClient, AgentIdentity, AgentIdentityConfig, CreateAgentParams, LocalKeySigner

from agent_did_langchain.snapshot import get_active_signing_key_id


@pytest.mark.asyncio
async def test_picks_the_first_active_assertion_method_key_not_the_authentication_key() -> None:
    config = AgentIdentityConfig(controller_signer=LocalKeySigner.generate()[0], client=AgentDidClient())
    identity = AgentIdentity(config)
    created = await identity.create(CreateAgentParams(name="KeyBot", core_model="test", system_prompt="test"))
    did = created.document.id

    other = created.model_copy(deep=True)
    other.document.authentication = [f"{did}#auth-only"]
    assert get_active_signing_key_id(other) == f"{did}#key-1"

    other.document.verification_method[0].deactivated = "2026-01-01T00:00:00Z"
    assert get_active_signing_key_id(other) is None
