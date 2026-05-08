from __future__ import annotations

import asyncio
import sys

from smoke_utils import (
    CONTRACTS_DIR,
    NPM_COMMAND,
    load_contract_abi,
    load_contract_bytecode,
    reset_agent_identity_state,
    run,
    spawn_hardhat_node,
    stop_process_tree,
    wait_for_hardhat_node,
)
from web3 import HTTPProvider, Web3

from agent_did_sdk import AgentIdentity, AgentIdentityConfig
from agent_did_sdk.core.types import CreateAgentParams
from agent_did_sdk.registry.evm_registry import EvmAgentRegistry
from agent_did_sdk.registry.evm_types import EvmAgentRegistryAdapterConfig
from agent_did_sdk.registry.web3_client import Web3AgentRegistryContractClient
from agent_did_sdk.resolver.in_memory import InMemoryDIDResolver


async def main() -> int:
    node_process = spawn_hardhat_node()
    try:
        wait_for_hardhat_node(node_process)

        print("[smoke] Building contracts...")
        run([NPM_COMMAND, "run", "build"], CONTRACTS_DIR)

        provider = Web3(HTTPProvider("http://127.0.0.1:8545"))
        provider.eth.default_account = provider.eth.accounts[1]
        abi = load_contract_abi()
        bytecode = load_contract_bytecode()
        deployment = provider.eth.contract(abi=abi, bytecode=bytecode)

        print("[smoke] Deploying AgentRegistry on localhost...")
        tx_hash = deployment.constructor().transact({"from": provider.eth.accounts[0]})
        receipt = provider.eth.wait_for_transaction_receipt(tx_hash)
        deployed_address = receipt.contractAddress
        contract = provider.eth.contract(address=Web3.to_checksum_address(deployed_address), abi=abi)

        reset_agent_identity_state()
        registry = EvmAgentRegistry(
            EvmAgentRegistryAdapterConfig(
                contract_client=Web3AgentRegistryContractClient(contract),
                await_transaction_confirmation=False,
            )
        )

        AgentIdentity.set_registry(registry)
        AgentIdentity.set_resolver(InMemoryDIDResolver())

        identity = AgentIdentity(
            AgentIdentityConfig(signer_address=provider.eth.default_account, network="localhost")
        )
        result = await identity.create(
            CreateAgentParams(
                name="SmokeBot",
                core_model="gpt-4o-mini",
                system_prompt="You are a smoke test bot",
                did_method="agent",
            )
        )

        record = await registry.get_record(result.document.id)
        if record is None or record.did != result.document.id:
            raise RuntimeError("Expected DID to be registered on the local contract")

        payload = "approve:smoke:1"
        signature = await identity.sign_message(payload, result.agent_private_key)

        valid_before_revocation = await AgentIdentity.verify_signature(result.document.id, payload, signature)
        if not valid_before_revocation:
            raise RuntimeError("Expected signature to be valid before revocation")

        await AgentIdentity.revoke_did(result.document.id)

        valid_after_revocation = await AgentIdentity.verify_signature(result.document.id, payload, signature)
        if valid_after_revocation:
            raise RuntimeError("Expected signature to be invalid after revocation")

        print("✅ E2E smoke test completed successfully")
        return 0
    finally:
        stop_process_tree(node_process)


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
