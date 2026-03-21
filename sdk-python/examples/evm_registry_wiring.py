from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path

from web3 import HTTPProvider, Web3

from agent_did_sdk import AgentIdentity, AgentIdentityConfig, EvmAgentRegistry, Web3AgentRegistryContractClient
from agent_did_sdk.core.types import CreateAgentParams
from agent_did_sdk.registry.evm_types import EvmAgentRegistryAdapterConfig


ABI_PATH = Path(__file__).resolve().parent / "abi" / "AgentRegistry.abi.json"


def load_agent_registry_abi() -> list[dict[str, object]]:
    if not ABI_PATH.exists():
        raise RuntimeError(f"ABI file not found at {ABI_PATH}. Run contracts export first: npm run export:abi")
    return json.loads(ABI_PATH.read_text(encoding="utf-8"))


async def main() -> None:
    rpc_url = os.getenv("RPC_URL")
    signer_address = os.getenv("SIGNER_ADDRESS")
    registry_address = os.getenv("AGENT_REGISTRY_ADDRESS")

    if not rpc_url or not signer_address or not registry_address:
        raise RuntimeError("Missing required env vars: RPC_URL, SIGNER_ADDRESS, AGENT_REGISTRY_ADDRESS")

    provider = Web3(HTTPProvider(rpc_url))
    abi = load_agent_registry_abi()
    contract = provider.eth.contract(address=Web3.to_checksum_address(registry_address), abi=abi)

    registry = EvmAgentRegistry(
        EvmAgentRegistryAdapterConfig(
            contract_client=Web3AgentRegistryContractClient(contract),
            await_transaction_confirmation=True,
        )
    )

    AgentIdentity.set_registry(registry)

    identity = AgentIdentity(
        AgentIdentityConfig(
            signer_address=Web3.to_checksum_address(signer_address),
            network="polygon",
        )
    )

    result = await identity.create(
        CreateAgentParams(
            name="EvmLinkedBot",
            core_model="gpt-4o-mini",
            system_prompt="You are a compliant enterprise assistant",
        )
    )

    payload = "approve:order:456"
    signature = await identity.sign_message(payload, result.agent_private_key)
    is_valid = await AgentIdentity.verify_signature(result.document.id, payload, signature)

    print("DID:", result.document.id)
    print("Signature valid:", is_valid)

    await AgentIdentity.revoke_did(result.document.id)
    is_valid_after_revocation = await AgentIdentity.verify_signature(result.document.id, payload, signature)
    print("Signature valid after revocation:", is_valid_after_revocation)


if __name__ == "__main__":
    asyncio.run(main())