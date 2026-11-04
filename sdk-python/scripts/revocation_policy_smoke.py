from __future__ import annotations

import sys

from eth_account import Account
from eth_account.messages import encode_typed_data
from smoke_utils import (
    CONTRACTS_DIR,
    NPM_COMMAND,
    load_contract_abi,
    load_contract_bytecode,
    run,
    spawn_hardhat_node,
    stop_process_tree,
    wait_for_hardhat_node,
)
from web3 import HTTPProvider, Web3

# Well-known Hardhat development account #0 (the deployer, hence the registrar).
HARDHAT_ACCOUNT_0_KEY = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"


def wait_for_tx(web3: Web3, tx_hash: bytes) -> None:
    web3.eth.wait_for_transaction_receipt(tx_hash)


def expect_revert(action, expected_message: str) -> None:
    try:
        action()
    except Exception as exc:  # noqa: BLE001
        if expected_message not in str(exc):
            raise RuntimeError(
                f"Unexpected revert message. Expected to include '{expected_message}', got: {exc}"
            ) from exc
        return
    raise RuntimeError(f"Expected revert with message containing: {expected_message}")


def register_attested(web3: Web3, contract, did: str, owner: str) -> None:
    controller = f"did:ethr:{owner}"
    deadline = web3.eth.get_block("latest")["timestamp"] + 3600
    message = {
        "types": {
            "EIP712Domain": [
                {"name": "name", "type": "string"},
                {"name": "version", "type": "string"},
                {"name": "chainId", "type": "uint256"},
                {"name": "verifyingContract", "type": "address"},
            ],
            "Registration": [
                {"name": "did", "type": "string"},
                {"name": "controller", "type": "string"},
                {"name": "documentRef", "type": "string"},
                {"name": "owner", "type": "address"},
                {"name": "deadline", "type": "uint256"},
            ],
        },
        "primaryType": "Registration",
        "domain": {
            "name": "AgentRegistry",
            "version": "1",
            "chainId": web3.eth.chain_id,
            "verifyingContract": contract.address,
        },
        "message": {
            "did": did,
            "controller": controller,
            "documentRef": "",
            "owner": owner,
            "deadline": deadline,
        },
    }
    signature = Account.sign_message(encode_typed_data(full_message=message), HARDHAT_ACCOUNT_0_KEY).signature
    attestation = (owner, deadline, signature)
    wait_for_tx(
        web3,
        contract.functions.registerAgentAttested(did, controller, "", attestation).transact({"from": owner}),
    )


def main() -> int:
    node_process = spawn_hardhat_node()
    try:
        wait_for_hardhat_node(node_process)

        run([NPM_COMMAND, "run", "build"], CONTRACTS_DIR)
        web3 = Web3(HTTPProvider("http://127.0.0.1:8545"))
        abi = load_contract_abi()
        bytecode = load_contract_bytecode()
        deployment = web3.eth.contract(abi=abi, bytecode=bytecode)
        deployment_hash = deployment.constructor().transact({"from": web3.eth.accounts[0]})
        deployment_receipt = web3.eth.wait_for_transaction_receipt(deployment_hash)
        deployed_address = deployment_receipt.contractAddress
        contract = web3.eth.contract(address=Web3.to_checksum_address(deployed_address), abi=abi)

        owner = web3.eth.accounts[1]
        delegate = web3.eth.accounts[2]
        new_owner = web3.eth.accounts[3]

        did_one = "did:agent:polygon:0xpolicy1"
        register_attested(web3, contract, did_one, owner)

        expect_revert(lambda: contract.functions.revokeAgent(did_one).transact({"from": delegate}), "not authorized")

        wait_for_tx(
            web3,
            contract.functions.setRevocationDelegate(did_one, delegate, True).transact({"from": owner}),
        )

        if not contract.functions.isRevocationDelegate(did_one, delegate).call():
            raise RuntimeError("Delegate should be authorized after setRevocationDelegate")

        wait_for_tx(web3, contract.functions.revokeAgent(did_one).transact({"from": delegate}))
        if not contract.functions.isRevoked(did_one).call():
            raise RuntimeError("DID should be revoked by authorized delegate")

        did_two = "did:agent:polygon:0xpolicy2"
        register_attested(web3, contract, did_two, owner)
        wait_for_tx(
            web3,
            contract.functions.transferAgentOwnership(did_two, new_owner).transact({"from": owner}),
        )

        expect_revert(
            lambda: contract.functions.setRevocationDelegate(did_two, delegate, True).transact({"from": owner}),
            "only owner",
        )

        wait_for_tx(
            web3,
            contract.functions.setRevocationDelegate(did_two, delegate, True).transact({"from": new_owner}),
        )
        wait_for_tx(web3, contract.functions.revokeAgent(did_two).transact({"from": delegate}))

        if not contract.functions.isRevoked(did_two).call():
            raise RuntimeError("DID should be revoked after ownership transfer + delegation")

        print("✅ Revocation policy smoke completed successfully")
        return 0
    finally:
        stop_process_tree(node_process)


if __name__ == "__main__":
    sys.exit(main())
