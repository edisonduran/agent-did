"""History derived from an imported did:webvh log (parity: sdk/tests/HistoryLabels.test.ts)."""

from __future__ import annotations

from agent_did_sdk.core.client import AgentDidClient
from agent_did_sdk.core.identity import AgentIdentity, AgentIdentityConfig
from agent_did_sdk.core.signer import LocalKeySigner
from agent_did_sdk.core.types import CreateAgentParams


async def test_labels_an_added_key_as_an_update_and_a_retired_key_as_a_rotation() -> None:
    owner = AgentDidClient()
    identity = AgentIdentity(AgentIdentityConfig(controller_signer=LocalKeySigner.generate()[0], client=owner))
    created = await identity.create(CreateAgentParams(name="HistoryBot", core_model="test", system_prompt="test"))
    did = created.document.id
    await owner.add_verification_method(did)
    await owner.rotate_verification_method(did)

    reader = AgentDidClient()
    await reader.import_did_webvh_history(owner.export_did_webvh_history(created.document.controller))
    await reader.import_did_webvh_history(owner.export_did_webvh_history(did))

    assert [entry.action for entry in reader.get_document_history(did)] == ["created", "updated", "rotated-key"]
