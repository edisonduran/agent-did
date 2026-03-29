"""EVM-specific types for contract interaction."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol, runtime_checkable

from .types import AgentRegistryRecord


@dataclass
class EvmTxResponse:
    wait: object | None = None  # Callable or None


@runtime_checkable
class EvmAgentRegistryContract(Protocol):
    async def register_agent(
        self, did: str, controller: str, document_ref: str | None = None,
    ) -> EvmTxResponse | None: ...
    async def register_agent_with_document(
        self, did: str, controller: str, document_ref: str,
    ) -> EvmTxResponse | None: ...
    async def set_document_ref(
        self, did: str, document_ref: str,
    ) -> EvmTxResponse | None: ...
    async def revoke_agent(self, did: str) -> EvmTxResponse | None: ...
    async def get_agent_record(self, did: str) -> AgentRegistryRecord | None: ...
    async def is_revoked(self, did: str) -> bool: ...


@dataclass
class EvmAgentRegistryAdapterConfig:
    contract_client: EvmAgentRegistryContract
    await_transaction_confirmation: bool = True
