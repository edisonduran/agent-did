"""EIP-712 definitions for the registrar attestation required by ``registerAgentAttested``.

The registrar signs these with its own wallet (for example ``eth_account``'s
``encode_typed_data`` + ``sign_message``) after verifying, off-chain, that ``owner`` controls
the DID. TypeScript parity: ``evm/src/attestation.ts``.
"""

from __future__ import annotations

from typing import Any

from .evm_types import RegistrationAttestationRequest

__all__ = [
    "REGISTRATION_ATTESTATION_TYPES",
    "registration_attestation_domain",
    "registration_attestation_message",
]

REGISTRATION_ATTESTATION_TYPES: dict[str, list[dict[str, str]]] = {
    "Registration": [
        {"name": "did", "type": "string"},
        {"name": "controller", "type": "string"},
        {"name": "documentRef", "type": "string"},
        {"name": "owner", "type": "address"},
        {"name": "deadline", "type": "uint256"},
    ]
}


def registration_attestation_domain(chain_id: int, verifying_contract: str) -> dict[str, Any]:
    return {
        "name": "AgentRegistry",
        "version": "1",
        "chainId": chain_id,
        "verifyingContract": verifying_contract,
    }


def registration_attestation_message(
    request: RegistrationAttestationRequest, owner: str, deadline: int
) -> dict[str, Any]:
    """The typed-data message the registrar signs."""
    return {
        "did": request.did,
        "controller": request.controller,
        "documentRef": request.document_ref or "",
        "owner": owner,
        "deadline": deadline,
    }
