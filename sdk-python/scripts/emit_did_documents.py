"""Emit DID documents created by the Python SDK, for the W3C DID Core test suite check (WP-7).

    python sdk-python/scripts/emit_did_documents.py <domain>   > documents.json

Prints ``{"documents": [...]}``. Each item names a scenario and carries, for one DID:

- ``resolved``: the document ``AgentDidClient.resolve`` returns (what Agent-DID consumers receive);
- ``webvh``: the document and DID document metadata from verifying the DID's ``did.jsonl`` with the
  SDK's did:webvh adapter (the did:webvh resolution result, with the implicit services).

Mirrors the TypeScript half in scripts/did-core-test-suite/run.js.
"""

from __future__ import annotations

import asyncio
import json
import sys
from typing import Any

from agent_did_sdk import AgentDidClient, AgentDidClientOptions, AgentIdentity, AgentIdentityConfig
from agent_did_sdk.core.signer import LocalKeySigner
from agent_did_sdk.core.types import CreateAgentParams, UpdateAgentDocumentParams
from agent_did_sdk.webvh.adapter import DidWebvhMetadata, resolve_did_webvh_log


def _metadata(meta: DidWebvhMetadata) -> dict[str, Any]:
    """The adapter's metadata with the property names the TypeScript SDK and did:webvh use."""
    return {
        "versionId": meta.version_id,
        "versionTime": meta.version_time,
        "created": meta.created,
        "updated": meta.updated,
        "scid": meta.scid,
        "updateKeys": list(meta.update_keys),
        "nextKeyHashes": list(meta.next_key_hashes),
        "deactivated": meta.deactivated,
        "ttl": meta.ttl,
    }


async def _entry(client: AgentDidClient, scenario: str, did: str) -> dict[str, Any]:
    resolved = await client.resolve(did)
    webvh = await resolve_did_webvh_log(client.export_did_webvh_history(did), did=did)
    return {
        "scenario": scenario,
        "did": did,
        "resolved": resolved.model_dump(by_alias=True, exclude_none=True, mode="json"),
        "webvh": {"document": webvh.document, "metadata": _metadata(webvh.metadata)},
    }


async def main(domain: str) -> None:
    controller_signer, _ = LocalKeySigner.generate()
    client = AgentDidClient(AgentDidClientOptions(webvh_domain=domain))
    identity = AgentIdentity(AgentIdentityConfig(controller_signer=controller_signer, client=client))
    single = await identity.create(
        CreateAgentParams(name="DidCorePy", core_model="did-core-check-model", system_prompt="did-core-check")
    )
    multi = await identity.create(
        CreateAgentParams(name="DidCorePyMulti", core_model="did-core-check-model", system_prompt="did-core-check")
    )
    await client.update_did_document(
        multi.document.id, UpdateAgentDocumentParams(description="updated by the DID Core check")
    )
    await client.rotate_verification_method(multi.document.id)

    controller = single.document.controller
    if not isinstance(controller, str):
        sys.exit("expected a single controller DID")
    documents = [
        await _entry(client, "agent (single entry)", single.document.id),
        await _entry(client, "agent after update and key rotation", multi.document.id),
        await _entry(client, "controller", controller),
    ]
    sys.stdout.write(json.dumps({"documents": documents}))


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit("usage: emit_did_documents.py <domain>")
    asyncio.run(main(sys.argv[1]))
