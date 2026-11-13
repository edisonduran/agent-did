"""External Agent-DID documents are validated (parity: sdk/tests/DocumentGuard.test.ts)."""

from __future__ import annotations

from typing import Any

import pytest

from agent_did_sdk.core.client import AgentDidClient
from agent_did_sdk.core.signer import LocalKeySigner
from agent_did_sdk.core.types import AgentDIDDocument
from agent_did_sdk.webvh.adapter import create_did_webvh_log, update_did_webvh_log

VALID: dict[str, Any] = {
    "@context": ["https://www.w3.org/ns/did/v1"],
    "id": "did:example:a",
    "controller": "did:example:c",
    "created": "2026-01-01T00:00:00Z",
    "updated": "2026-01-01T00:00:00Z",
    "agentMetadata": {"name": "a", "version": "1", "coreModelHash": "h", "systemPromptHash": "h"},
    "verificationMethod": [
        {"id": "did:example:a#key-1", "type": "Multikey", "controller": "did:example:c", "publicKeyMultibase": "z"}
    ],
    "authentication": ["did:example:a#key-1"],
}


def test_accepts_a_document_with_the_required_members_and_optional_ones_set_to_null() -> None:
    AgentDIDDocument.model_validate(VALID)
    AgentDIDDocument.model_validate({**VALID, "assertionMethod": None, "complianceCertifications": None})


@pytest.mark.parametrize(
    "document",
    [
        [],
        {k: v for k, v in VALID.items() if k != "agentMetadata"},
        {**VALID, "verificationMethod": [{"type": "Multikey", "controller": "c"}]},
        {**VALID, "authentication": "did:example:a#key-1"},
        {**VALID, "id": 7},
    ],
    ids=["not-an-object", "no-agent-metadata", "method-without-id", "authentication-not-a-list", "numeric-id"],
)
def test_rejects_a_malformed_document(document: Any) -> None:
    with pytest.raises(ValueError):
        AgentDIDDocument.model_validate(document)


async def test_refuses_to_import_a_did_webvh_log_whose_state_is_not_an_agent_did_document() -> None:
    signer = LocalKeySigner.generate()[0]
    created = await create_did_webvh_log(
        domain="example.com",
        path_segments=["plain"],
        document={"@context": ["https://www.w3.org/ns/did/v1"], "id": "{DID}"},
        signer=signer,
    )
    updated = await update_did_webvh_log(log=created.log, signer=signer, document=dict(created.state))

    with pytest.raises(ValueError):
        await AgentDidClient().import_did_webvh_history(updated.log)
