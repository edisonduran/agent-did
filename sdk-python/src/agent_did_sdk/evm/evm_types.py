"""EVM-specific types for contract interaction."""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Protocol, runtime_checkable

from ..registry.types import AgentRegistryRecord


@dataclass
class EvmTxResponse:
    wait: object | None = None  # Callable or None


@dataclass
class RegistrationAttestation:
    """Registrar-signed authorization for one registration (see ``attestation.py``)."""

    owner: str
    """Address that becomes the record owner."""
    deadline: int
    """Unix seconds after which the attestation is no longer accepted."""
    signature: bytes
    """65-byte EIP-712 signature by the contract's current registrar."""


@dataclass
class RegistrationAttestationRequest:
    did: str
    controller: str
    document_ref: str | None = None


RegistrationAttestationProvider = Callable[[RegistrationAttestationRequest], Awaitable[RegistrationAttestation]]
"""Obtains an attestation for a registration, typically by calling the registrar service."""


@runtime_checkable
class EvmAgentRegistryContract(Protocol):
    async def register_agent_attested(
        self, did: str, controller: str, document_ref: str, attestation: RegistrationAttestation,
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
    attestation_provider: RegistrationAttestationProvider | None = None
    """Required to call ``register``: the contract only accepts registrar-attested registrations."""
