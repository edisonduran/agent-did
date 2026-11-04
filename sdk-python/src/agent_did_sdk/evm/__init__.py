"""Optional EVM registry adapter (install with ``pip install "agent-did-sdk[evm]"``).

Nothing in the core SDK imports this package.
"""

from __future__ import annotations

from .attestation import (
    REGISTRATION_ATTESTATION_TYPES,
    registration_attestation_domain,
    registration_attestation_message,
)
from .evm_registry import EvmAgentRegistry
from .evm_types import (
    EvmAgentRegistryAdapterConfig,
    EvmAgentRegistryContract,
    EvmTxResponse,
    RegistrationAttestation,
    RegistrationAttestationProvider,
    RegistrationAttestationRequest,
)
from .web3_client import Web3AgentRegistryContractClient

__all__ = [
    "REGISTRATION_ATTESTATION_TYPES",
    "EvmAgentRegistry",
    "EvmAgentRegistryAdapterConfig",
    "EvmAgentRegistryContract",
    "EvmTxResponse",
    "RegistrationAttestation",
    "RegistrationAttestationProvider",
    "RegistrationAttestationRequest",
    "Web3AgentRegistryContractClient",
    "registration_attestation_domain",
    "registration_attestation_message",
]
