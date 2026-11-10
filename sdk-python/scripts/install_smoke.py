"""Smoke test of an installed ``agent-did-sdk`` (platform matrix, ci-python-platforms.yml).

    python -I sdk-python/scripts/install_smoke.py

Run it against the installed package, not the source tree. It goes through the paths that need the
native dependencies: a did:webvh log is created and extended (signed with ``pynacl``, verified by
``did-webvh``, whose proof check uses ``aries-askar``), a message is signed and verified, and the
exported log is verified again from its text. Exits non-zero on any failure.
"""

from __future__ import annotations

import asyncio
import platform
import sys

from agent_did_sdk import AgentDidClient, AgentDidClientOptions, AgentIdentity, AgentIdentityConfig
from agent_did_sdk.core.signer import LocalKeySigner
from agent_did_sdk.core.types import CreateAgentParams, UpdateAgentDocumentParams
from agent_did_sdk.webvh.adapter import resolve_did_webvh_log


async def main() -> None:
    controller_signer, _ = LocalKeySigner.generate()
    client = AgentDidClient(AgentDidClientOptions(webvh_domain="agent-did.test"))
    identity = AgentIdentity(AgentIdentityConfig(controller_signer=controller_signer, client=client))
    created = await identity.create(
        CreateAgentParams(name="InstallSmoke", core_model="install-smoke-model", system_prompt="install-smoke")
    )
    did = created.document.id
    await client.update_did_document(did, UpdateAgentDocumentParams(description="install smoke"))

    signature = await identity.sign_message("install smoke", created.agent_private_key)
    if not await client.verify_signature(did, "install smoke", signature):
        sys.exit("a valid signature was rejected")
    if await client.verify_signature(did, "install smoke (altered)", signature):
        sys.exit("a signature over another payload was accepted")

    resolved = await resolve_did_webvh_log(client.export_did_webvh_history(did), did=did)
    if resolved.version_number != 2:
        sys.exit(f"expected 2 log entries, got {resolved.version_number}")
    print(f"install smoke OK on {platform.system()} {platform.machine()}, Python {platform.python_version()}")


if __name__ == "__main__":
    asyncio.run(main())
