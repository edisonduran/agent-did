"""Tests for AgentDidClient — instance-owned identity state."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from agent_did_sdk import AgentDidClient, AgentDidClientOptions, LocalKeySigner
from agent_did_sdk.core.identity import AgentIdentity, AgentIdentityConfig
from agent_did_sdk.core.types import CreateAgentParams

PARAMS = CreateAgentParams(
    name="ClientBot",
    description="Agent used to test AgentDidClient isolation",
    core_model="gpt-4o-mini",
    system_prompt="You are a test assistant.",
)
ADDRESS = "0x" + "ab" * 20


def _identity(client: AgentDidClient | None = None) -> AgentIdentity:
    return AgentIdentity(AgentIdentityConfig(controller_signer=LocalKeySigner.generate()[0], client=client))


async def test_state_is_isolated_between_clients() -> None:
    a, b = AgentDidClient(), AgentDidClient()
    document = (await _identity(a).create(PARAMS)).document

    assert (await a.resolve(document.id)).id == document.id
    assert len(a.get_document_history(document.id)) == 1
    with pytest.raises(Exception):  # noqa: B017 - any resolution failure
        await b.resolve(document.id)
    assert b.get_document_history(document.id) == []


async def test_explicit_client_leaves_default_client_untouched() -> None:
    client = AgentDidClient()
    document = (await _identity(client).create(PARAMS)).document
    assert AgentIdentity.get_default_client().get_document_history(document.id) == []


async def test_verify_signature_through_client() -> None:
    client = AgentDidClient()
    identity = _identity(client)
    result = await identity.create(PARAMS)
    signature = await identity.sign_message("hello", result.agent_private_key)
    assert await client.verify_signature(result.document.id, "hello", signature) is True


async def test_injected_clock_drives_timestamps() -> None:
    fixed = datetime(2030, 1, 2, 3, 4, 5, tzinfo=timezone.utc)
    client = AgentDidClient(AgentDidClientOptions(clock=lambda: fixed))
    document = (await _identity(client).create(PARAMS)).document
    assert document.created.startswith("2030-01-02T03:04:05")


async def test_class_level_api_delegates_to_replaceable_default_client() -> None:
    previous = AgentIdentity.get_default_client()
    fresh = AgentDidClient()
    AgentIdentity.set_default_client(fresh)
    try:
        document = (await _identity().create(PARAMS)).document
        assert (await AgentIdentity.resolve(document.id)).id == document.id
        assert len(fresh.get_document_history(document.id)) == 1
    finally:
        AgentIdentity.set_default_client(previous)
