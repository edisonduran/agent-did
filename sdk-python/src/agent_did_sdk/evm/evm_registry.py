"""EVM adapter — wraps an EvmAgentRegistryContract into an AgentRegistry."""

from __future__ import annotations

from ..registry.types import AgentRegistryRecord
from .evm_types import EvmAgentRegistryAdapterConfig, EvmTxResponse, RegistrationAttestationRequest


class EvmAgentRegistry:
    """Adapter that converts ``EvmAgentRegistryContract`` calls into the ``AgentRegistry`` interface."""

    def __init__(self, config: EvmAgentRegistryAdapterConfig) -> None:
        self._contract = config.contract_client
        self._await_tx = config.await_transaction_confirmation
        self._attestation_provider = config.attestation_provider

    async def register(self, did: str, controller: str, document_ref: str | None = None) -> None:
        if self._attestation_provider is None:
            raise RuntimeError(
                "EvmAgentRegistry.register requires an attestation_provider: "
                "the contract only accepts registrar-attested registrations"
            )

        attestation = await self._attestation_provider(
            RegistrationAttestationRequest(did=did, controller=controller, document_ref=document_ref)
        )
        tx = await self._contract.register_agent_attested(did, controller, document_ref or "", attestation)
        await self._wait_if_needed(tx)

    async def set_document_reference(self, did: str, document_ref: str) -> None:
        tx = await self._contract.set_document_ref(did, document_ref)
        await self._wait_if_needed(tx)

    async def revoke(self, did: str) -> None:
        tx = await self._contract.revoke_agent(did)
        await self._wait_if_needed(tx)

    async def get_record(self, did: str) -> AgentRegistryRecord | None:
        return await self._contract.get_agent_record(did)

    async def is_revoked(self, did: str) -> bool:
        return await self._contract.is_revoked(did)

    async def _wait_if_needed(self, tx: EvmTxResponse | None) -> None:
        if not self._await_tx or tx is None:
            return
        wait_fn = getattr(tx, "wait", None)
        if callable(wait_fn):
            await wait_fn()
