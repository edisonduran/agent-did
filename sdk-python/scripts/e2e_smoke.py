"""End-to-end smoke on the canonical did:webvh path (RFC-001 MUST-09).

Create an agent, sign, verify, revoke with a controller-signed deactivation entry, and check that the signature
no longer verifies, both in the client that revoked and in a fresh verifier that only has the published logs
(agent and controller).

TypeScript parity: ``scripts/e2e-smoke.js``.
"""

from __future__ import annotations

import asyncio
import json
import sys

from agent_did_sdk import AgentDidClient, LocalKeySigner
from agent_did_sdk.core.identity import AgentIdentity, AgentIdentityConfig
from agent_did_sdk.core.types import CreateAgentParams
from agent_did_sdk.webvh.adapter import resolve_did_webvh_log


def check(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


async def main() -> int:
    client = AgentDidClient()
    identity = AgentIdentity(AgentIdentityConfig(controller_signer=LocalKeySigner.generate()[0], client=client))

    print("[smoke] Creating a did:webvh agent...")
    result = await identity.create(
        CreateAgentParams(
            name="E2ESmokeBot",
            core_model="gpt-4o-mini",
            system_prompt="You are an end-to-end smoke test.",
        )
    )
    did = result.document.id
    check(did.startswith("did:webvh:"), f"expected a did:webvh DID, got {did}")

    print("[smoke] Signing and verifying a payload...")
    payload = json.dumps({"action": "transfer", "amount": 10})
    signature = await identity.sign_message(payload, result.agent_private_key)
    check(await client.verify_signature(did, payload, signature), "signature must verify before revocation")
    check(not await client.verify_signature(did, payload + " ", signature), "a tampered payload must not verify")

    # A verifier resolves the whole controller chain, so it needs the controller's published log too.
    print("[smoke] Verifying from the published logs only...")
    controller_log = client.export_did_webvh_history(result.document.controller)
    published_before = client.export_did_webvh_history(did)
    verifier_before = AgentDidClient()
    await verifier_before.import_did_webvh_history(controller_log)
    await verifier_before.import_did_webvh_history(published_before)
    check(await verifier_before.verify_signature(did, payload, signature), "a fresh verifier must accept it")

    print("[smoke] Revoking with a controller-signed deactivation entry...")
    await client.revoke_did(did)
    published_after = client.export_did_webvh_history(did)
    resolved = await resolve_did_webvh_log(published_after, did=did)
    check(resolved.metadata.deactivated, "the log must end in a deactivation entry")
    check(not await client.verify_signature(did, payload, signature), "signature must not verify after revocation")

    verifier_after = AgentDidClient()
    await verifier_after.import_did_webvh_history(controller_log)
    await verifier_after.import_did_webvh_history(published_after)
    check(
        not await verifier_after.verify_signature(did, payload, signature),
        "a fresh verifier with the published log must reject it",
    )

    print("E2E smoke test completed successfully")
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
