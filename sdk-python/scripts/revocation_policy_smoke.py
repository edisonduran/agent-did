"""Revocation policy smoke on the canonical did:webvh path (RFC-001 §6.6).

Only the controller's update key can revoke or change a DID; a third party's key cannot, and neither can a
registry record on its own. After a controller-signed deactivation, no further change is accepted.

TypeScript parity: ``scripts/revocation-policy-smoke.js``.
"""

from __future__ import annotations

import asyncio
import sys
from collections.abc import Awaitable, Callable
from typing import Any

from agent_did_sdk import AgentDidClient, AgentDidClientOptions, LocalKeySigner
from agent_did_sdk.core.identity import AgentIdentity, AgentIdentityConfig
from agent_did_sdk.core.types import CreateAgentParams, UpdateAgentDocumentParams
from agent_did_sdk.registry.in_memory import InMemoryAgentRegistry


async def expect_rejected(action: Callable[[], Awaitable[Any]], label: str) -> None:
    try:
        await action()
    except Exception:  # noqa: BLE001 - any rejection counts
        return
    raise RuntimeError(f"{label} must be rejected")


async def main() -> int:
    registry = InMemoryAgentRegistry()
    client = AgentDidClient(AgentDidClientOptions(registry=registry))
    attacker = LocalKeySigner.generate()[0]
    identity = AgentIdentity(AgentIdentityConfig(controller_signer=LocalKeySigner.generate()[0], client=client))

    result = await identity.create(
        CreateAgentParams(
            name="PolicySmokeBot",
            core_model="gpt-4o-mini",
            system_prompt="You are a revocation policy smoke test.",
        )
    )
    did = result.document.id
    payload = "policy-smoke"
    signature = await identity.sign_message(payload, result.agent_private_key)

    async def still_valid() -> None:
        if not await client.verify_signature(did, payload, signature):
            raise RuntimeError("DID must stay active")

    print("[smoke] A third party cannot revoke, rotate or update the DID...")
    await expect_rejected(lambda: client.revoke_did(did, controller_signer=attacker), "revocation by a third-party key")
    await expect_rejected(
        lambda: client.rotate_verification_method(did, controller_signer=attacker), "key rotation by a third-party key"
    )
    await expect_rejected(
        lambda: client.update_did_document(
            did, UpdateAgentDocumentParams(description="hijacked"), controller_signer=attacker
        ),
        "update by a third-party key",
    )
    await still_valid()

    print("[smoke] A registry record alone does not revoke a did:webvh DID...")
    await registry.revoke(did)
    await still_valid()

    print("[smoke] The controller revokes; nothing changes the DID afterwards...")
    await client.revoke_did(did)
    if await client.verify_signature(did, payload, signature):
        raise RuntimeError("DID must be revoked by its controller")
    await expect_rejected(lambda: client.rotate_verification_method(did), "key rotation after deactivation")
    await expect_rejected(
        lambda: client.update_did_document(did, UpdateAgentDocumentParams(description="revived")),
        "update after deactivation",
    )

    print("Revocation policy smoke completed successfully")
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
