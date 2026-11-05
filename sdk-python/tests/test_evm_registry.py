"""Tests for EvmAgentRegistry adapter."""

from __future__ import annotations

import pytest

from agent_did_sdk.evm import (
    REGISTRATION_ATTESTATION_TYPES,
    RegistrationAttestation,
    RegistrationAttestationRequest,
    registration_attestation_domain,
    registration_attestation_message,
)
from agent_did_sdk.evm.evm_registry import EvmAgentRegistry
from agent_did_sdk.evm.evm_types import EvmAgentRegistryAdapterConfig, EvmTxResponse
from agent_did_sdk.registry.types import AgentRegistryRecord

ATTESTATION = RegistrationAttestation(
    owner="0x0000000000000000000000000000000000000001", deadline=1_700_000_000, signature=b"\x01" * 65,
)


class FakeContract:
    """Minimal fake contract that implements EvmAgentRegistryContract."""

    def __init__(self) -> None:
        self._records: dict[str, AgentRegistryRecord] = {}
        self.attested_calls: list[tuple[str, str, str, RegistrationAttestation]] = []

    async def register_agent_attested(
        self, did: str, controller: str, document_ref: str, attestation: RegistrationAttestation,
    ) -> EvmTxResponse | None:
        self.attested_calls.append((did, controller, document_ref, attestation))
        self._records[did] = AgentRegistryRecord(
            did=did, controller=controller, createdAt="2024-01-01T00:00:00Z", documentRef=document_ref or None,
        )
        return None

    async def set_document_ref(self, did: str, document_ref: str) -> EvmTxResponse | None:
        rec = self._records.get(did)
        if rec:
            self._records[did] = rec.model_copy(update={"document_ref": document_ref})
        return None

    async def revoke_agent(self, did: str) -> EvmTxResponse | None:
        rec = self._records.get(did)
        if rec:
            self._records[did] = rec.model_copy(update={"revoked_at": "2024-06-01T00:00:00Z"})
        return None

    async def get_agent_record(self, did: str) -> AgentRegistryRecord | None:
        return self._records.get(did)

    async def is_revoked(self, did: str) -> bool:
        rec = self._records.get(did)
        return bool(rec and rec.revoked_at)


async def _provider(request: RegistrationAttestationRequest) -> RegistrationAttestation:
    return ATTESTATION


@pytest.fixture()
def contract() -> FakeContract:
    return FakeContract()


@pytest.fixture()
def evm_registry(contract: FakeContract) -> EvmAgentRegistry:
    return EvmAgentRegistry(
        EvmAgentRegistryAdapterConfig(contract_client=contract, attestation_provider=_provider)  # type: ignore[arg-type]
    )


class TestEvmAgentRegistry:
    async def test_register_and_get(self, evm_registry: EvmAgentRegistry) -> None:
        await evm_registry.register("did:agent:test:1", "did:ethr:0xabc")
        record = await evm_registry.get_record("did:agent:test:1")
        assert record is not None
        assert record.did == "did:agent:test:1"

    async def test_register_passes_attestation_and_document_ref(
        self, evm_registry: EvmAgentRegistry, contract: FakeContract
    ) -> None:
        await evm_registry.register("did:agent:test:1", "did:ethr:0xabc", "hash://sha256/doc")
        await evm_registry.register("did:agent:test:2", "did:ethr:0xabc")
        assert contract.attested_calls == [
            ("did:agent:test:1", "did:ethr:0xabc", "hash://sha256/doc", ATTESTATION),
            ("did:agent:test:2", "did:ethr:0xabc", "", ATTESTATION),
        ]

    async def test_register_requires_attestation_provider(self, contract: FakeContract) -> None:
        registry = EvmAgentRegistry(EvmAgentRegistryAdapterConfig(contract_client=contract))  # type: ignore[arg-type]
        with pytest.raises(RuntimeError, match="attestation_provider"):
            await registry.register("did:agent:test:1", "did:ethr:0xabc")
        assert contract.attested_calls == []

    async def test_revoke(self, evm_registry: EvmAgentRegistry) -> None:
        await evm_registry.register("did:agent:test:1", "did:ethr:0xabc")
        await evm_registry.revoke("did:agent:test:1")
        assert await evm_registry.is_revoked("did:agent:test:1") is True

    async def test_set_document_reference(self, evm_registry: EvmAgentRegistry) -> None:
        await evm_registry.register("did:agent:test:1", "did:ethr:0xabc")
        await evm_registry.set_document_reference("did:agent:test:1", "hash://sha256/abc")
        record = await evm_registry.get_record("did:agent:test:1")
        assert record is not None
        assert record.document_ref == "hash://sha256/abc"


class TestAttestationTypedData:
    def test_types_match_the_contract_typehash(self) -> None:
        fields = REGISTRATION_ATTESTATION_TYPES["Registration"]
        encoded = "Registration(" + ",".join(f"{f['type']} {f['name']}" for f in fields) + ")"
        assert encoded == (
            "Registration(string did,string controller,string documentRef,address owner,uint256 deadline)"
        )

    def test_domain_and_message(self) -> None:
        assert registration_attestation_domain(31337, "0xabc") == {
            "name": "AgentRegistry", "version": "1", "chainId": 31337, "verifyingContract": "0xabc",
        }
        message = registration_attestation_message(
            RegistrationAttestationRequest(did="did:agent:test:1", controller="did:ethr:0xabc"), "0x01", 5,
        )
        assert message["documentRef"] == ""
        assert message["owner"] == "0x01"
        assert message["deadline"] == 5
