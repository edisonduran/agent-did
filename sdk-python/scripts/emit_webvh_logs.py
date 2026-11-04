"""Emit did:webvh logs created by the Python SDK, for the third-party resolver check (M-17).

    python sdk-python/scripts/emit_webvh_logs.py <domain>   > logs.json

Prints ``{"agent": <did>, "logs": {<did>: <did.jsonl text>}}`` for a fresh agent and its bootstrap controller.
Mirrors the TypeScript half in scripts/third-party-resolver/run.js.
"""

from __future__ import annotations

import asyncio
import json
import sys

from agent_did_sdk import AgentDidClient, AgentDidClientOptions, AgentIdentity, AgentIdentityConfig
from agent_did_sdk.core.signer import LocalKeySigner
from agent_did_sdk.core.types import CreateAgentParams


async def main(domain: str) -> None:
    controller_signer, _ = LocalKeySigner.generate()
    client = AgentDidClient(AgentDidClientOptions(webvh_domain=domain))
    identity = AgentIdentity(AgentIdentityConfig(controller_signer=controller_signer, client=client))
    result = await identity.create(
        CreateAgentParams(name="ThirdPartyPy", core_model="resolver-check-model", system_prompt="resolver-check")
    )
    agent = result.document.id
    controller = result.document.controller
    logs = {did: client.export_did_webvh_history(did) for did in (agent, controller)}
    sys.stdout.write(json.dumps({"agent": agent, "logs": logs}))


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit("usage: emit_webvh_logs.py <domain>")
    asyncio.run(main(sys.argv[1]))
