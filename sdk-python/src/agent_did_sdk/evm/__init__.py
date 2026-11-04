"""Optional EVM registry adapter (install with ``pip install "agent-did-sdk[evm]"``).

Nothing in the core SDK imports this package.
"""

from __future__ import annotations

from .evm_registry import EvmAgentRegistry
from .evm_types import EvmAgentRegistryAdapterConfig, EvmAgentRegistryContract, EvmTxResponse
from .web3_client import Web3AgentRegistryContractClient

__all__ = [
    "EvmAgentRegistry",
    "EvmAgentRegistryAdapterConfig",
    "EvmAgentRegistryContract",
    "EvmTxResponse",
    "Web3AgentRegistryContractClient",
]
