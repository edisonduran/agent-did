"""AgentMetadataCredential (RFC-001 §4.4, ADR-006 D-8d); parity: sdk/tests/AgentMetadataCredential.test.ts."""

from __future__ import annotations

import copy
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

import pytest

from agent_did_sdk import (
    AGENT_METADATA_CREDENTIAL_CONTEXT,
    AgentDidClient,
    AgentDidClientOptions,
    IssueAgentMetadataCredentialParams,
)
from agent_did_sdk.core.identity import AgentIdentity, AgentIdentityConfig
from agent_did_sdk.core.signer import LocalKeySigner
from agent_did_sdk.core.types import CreateAgentParams, CreateAgentResult, CreateDidWebvhOptions

BASE = CreateAgentParams(
    name="CredentialBot",
    description="Answers billing questions",
    version="2.1.0",
    capabilities=["billing:read", "tickets:write"],
)

_NOW = {"value": datetime(2026, 11, 15, 12, 0, 0, tzinfo=timezone.utc)}


def _clock() -> datetime:
    return _NOW["value"]


@pytest.fixture(autouse=True)
def _reset_clock() -> None:
    _NOW["value"] = datetime(2026, 11, 15, 12, 0, 0, tzinfo=timezone.utc)


@dataclass
class Party:
    client: AgentDidClient
    created: CreateAgentResult
    agent_did: str
    controller_did: str
    controller_key_id: str
    controller_signer: LocalKeySigner


async def _party() -> Party:
    client = AgentDidClient(AgentDidClientOptions(clock=_clock))
    identity = AgentIdentity(AgentIdentityConfig(controller_signer=LocalKeySigner.generate()[0], client=client))
    created = await identity.create(BASE)
    assert created.controller_private_key is not None
    controller_document = await client.resolve(created.document.controller)
    assert controller_document.assertion_method
    return Party(
        client=client,
        created=created,
        agent_did=created.document.id,
        controller_did=created.document.controller,
        controller_key_id=controller_document.assertion_method[0],
        controller_signer=LocalKeySigner(created.controller_private_key),
    )


async def _verifier_with(*logs: str) -> AgentDidClient:
    verifier = AgentDidClient(AgentDidClientOptions(clock=_clock))
    for log in logs:
        await verifier.import_did_webvh_history(log)
    return verifier


async def _issue(p: Party, **extra: Any) -> dict[str, Any]:
    return await p.client.issue_agent_metadata_credential(
        IssueAgentMetadataCredentialParams(
            agent_did=p.agent_did, signer=p.controller_signer, verification_method_id=p.controller_key_id, **extra
        )
    )


async def test_issued_by_the_controller_and_verified_in_another_client() -> None:
    p = await _party()
    credential = await _issue(p, valid_until="2027-11-15T12:00:00Z")

    assert credential["@context"] == list(AGENT_METADATA_CREDENTIAL_CONTEXT)
    assert credential["type"] == ["VerifiableCredential", "AgentMetadataCredential"]
    assert credential["issuer"] == p.controller_did
    assert credential["validFrom"] == "2026-11-15T12:00:00.000Z"
    assert credential["credentialSubject"] == {
        "id": p.agent_did,
        "agentMetadata": {
            "name": "CredentialBot",
            "description": "Answers billing questions",
            "version": "2.1.0",
            "capabilities": ["billing:read", "tickets:write"],
        },
    }
    assert {key: credential["proof"][key] for key in credential["proof"] if key != "proofValue"} == {
        "type": "DataIntegrityProof",
        "cryptosuite": "eddsa-jcs-2022",
        "created": "2026-11-15T12:00:00.000Z",
        "verificationMethod": p.controller_key_id,
        "proofPurpose": "assertionMethod",
        "@context": credential["@context"],
    }

    verifier = await _verifier_with(
        p.client.export_did_webvh_history(p.controller_did), p.client.export_did_webvh_history(p.agent_did)
    )
    result = await verifier.verify_agent_metadata_credential(copy.deepcopy(credential), expected_agent_did=p.agent_did)
    assert result.ok
    assert result.agent_did == p.agent_did
    assert result.issuer == p.controller_did
    assert result.verification_method == p.controller_key_id
    assert result.agent_metadata == credential["credentialSubject"]["agentMetadata"]
    assert result.controllers == [p.controller_did]


async def test_shares_a_subset_of_the_metadata() -> None:
    p = await _party()
    credential = await _issue(
        p,
        agent_metadata={"name": "CredentialBot", "capabilities": ["billing:read"]},
        credential_id="urn:uuid:7f1d3c1e-2f43-4a51-9a0e-6c1f0c2b9d11",
    )
    assert credential["id"] == "urn:uuid:7f1d3c1e-2f43-4a51-9a0e-6c1f0c2b9d11"
    subset = {"name": "CredentialBot", "capabilities": ["billing:read"]}
    assert credential["credentialSubject"]["agentMetadata"] == subset
    assert (await p.client.verify_agent_metadata_credential(credential)).ok


async def test_a_self_controlled_agent_issues_its_own_credential() -> None:
    client = AgentDidClient(AgentDidClientOptions(clock=_clock))
    identity = AgentIdentity(AgentIdentityConfig(controller_signer=LocalKeySigner.generate()[0], client=client))
    created = await identity.create(
        BASE.model_copy(
            update={
                "webvh": CreateDidWebvhOptions(
                    domain="agents.example", controller_did="{DID}", controller_signer=LocalKeySigner.generate()[0]
                )
            }
        )
    )
    assert created.document.assertion_method
    credential = await client.issue_agent_metadata_credential(
        IssueAgentMetadataCredentialParams(
            agent_did=created.document.id,
            signer=LocalKeySigner(created.agent_private_key),
            verification_method_id=created.document.assertion_method[0],
        )
    )
    assert credential["issuer"] == created.document.id
    result = await client.verify_agent_metadata_credential(credential)
    assert result.ok and result.issuer == created.document.id and result.controllers == []


class TestIssueRefuses:
    async def test_a_key_that_is_not_an_assertion_method_key_of_the_controller(self) -> None:
        p = await _party()
        assert p.created.document.assertion_method
        with pytest.raises(ValueError, match="must be a key of the agent's controller"):
            await p.client.issue_agent_metadata_credential(
                IssueAgentMetadataCredentialParams(
                    agent_did=p.agent_did,
                    signer=LocalKeySigner(p.created.agent_private_key),
                    verification_method_id=p.created.document.assertion_method[0],
                )
            )
        with pytest.raises(ValueError, match="not an active Ed25519 assertionMethod key"):
            await p.client.issue_agent_metadata_credential(
                IssueAgentMetadataCredentialParams(
                    agent_did=p.agent_did, signer=p.controller_signer, verification_method_id=f"{p.controller_did}#nope"
                )
            )

    async def test_a_signer_that_does_not_hold_the_key(self) -> None:
        p = await _party()
        with pytest.raises(ValueError, match="does not hold"):
            await p.client.issue_agent_metadata_credential(
                IssueAgentMetadataCredentialParams(
                    agent_did=p.agent_did,
                    signer=LocalKeySigner.generate()[0],
                    verification_method_id=p.controller_key_id,
                )
            )

    async def test_bad_metadata_and_dates(self) -> None:
        p = await _party()
        with pytest.raises(TypeError):
            await _issue(p, agent_metadata={})
        with pytest.raises(TypeError, match="not an agentMetadata member"):
            await _issue(p, agent_metadata={"name": "x", "extra": 1})
        with pytest.raises(TypeError):
            await _issue(p, valid_from="2026-11-15")
        with pytest.raises(TypeError):
            await _issue(p, valid_from="2026-11-15T00:00:00Z", valid_until="2026-11-14T00:00:00Z")

    async def test_a_deactivated_agent(self) -> None:
        p = await _party()
        await p.client.revoke_did(p.agent_did)
        with pytest.raises(Exception, match="revoked"):
            await _issue(p)


class TestVerifyRejects:
    @pytest.fixture
    async def issued(self) -> tuple[Party, dict[str, Any]]:
        p = await _party()
        return p, await _issue(p, valid_until="2026-12-15T12:00:00Z")

    @staticmethod
    async def _reason(p: Party, value: object, expected_agent_did: str | None = None) -> str:
        result = await p.client.verify_agent_metadata_credential(value, expected_agent_did=expected_agent_did)
        return "ok" if result.ok else str(result.reason)

    async def test_a_malformed_credential(self, issued: tuple[Party, dict[str, Any]]) -> None:
        p, credential = issued
        assert await self._reason(p, None) == "malformed_credential"
        for patch in (
            {"@context": ["https://www.w3.org/ns/credentials/v2"]},
            {"type": ["VerifiableCredential"]},
            {"issuer": {"id": p.controller_did}},
            {"credentialStatus": {"id": "x"}},
            {"validFrom": "yesterday"},
        ):
            assert await self._reason(p, {**copy.deepcopy(credential), **patch}) == "malformed_credential"
        no_metadata = copy.deepcopy(credential)
        del no_metadata["credentialSubject"]["agentMetadata"]
        assert await self._reason(p, no_metadata) == "malformed_credential"

    async def test_an_unsupported_proof(self, issued: tuple[Party, dict[str, Any]]) -> None:
        p, credential = issued
        proof_set = {**copy.deepcopy(credential), "proof": [credential["proof"]]}
        assert await self._reason(p, proof_set) == "unsupported_proof"
        without_proof = {key: value for key, value in credential.items() if key != "proof"}
        assert await self._reason(p, without_proof) == "unsupported_proof"
        for patch in (
            {"cryptosuite": "eddsa-rdfc-2022"},
            {"proofPurpose": "authentication"},
            {"verificationMethod": f"{p.agent_did}#key-1"},
            {"proofValue": "zabc"},
            {"created": "now"},
        ):
            changed = {**copy.deepcopy(credential), "proof": {**credential["proof"], **patch}}
            assert await self._reason(p, changed) == "unsupported_proof"

    async def test_outside_the_validity_period(self, issued: tuple[Party, dict[str, Any]]) -> None:
        p, credential = issued
        _NOW["value"] = datetime(2026, 11, 15, 11, 59, 59, tzinfo=timezone.utc)
        assert await self._reason(p, credential) == "not_yet_valid"
        _NOW["value"] = datetime(2026, 12, 15, 12, 0, 1, tzinfo=timezone.utc)
        assert await self._reason(p, credential) == "expired"

    async def test_another_subject_than_expected(self, issued: tuple[Party, dict[str, Any]]) -> None:
        p, credential = issued
        assert await self._reason(p, credential, expected_agent_did=p.controller_did) == "subject_mismatch"

    async def test_a_changed_claim_or_proof_member(self, issued: tuple[Party, dict[str, Any]]) -> None:
        p, credential = issued
        tampered = copy.deepcopy(credential)
        tampered["credentialSubject"]["agentMetadata"]["capabilities"] = ["admin"]
        assert await self._reason(p, tampered) == "signature_invalid"
        other_created = copy.deepcopy(credential)
        other_created["proof"]["created"] = "2026-11-15T12:00:01.000Z"
        assert await self._reason(p, other_created) == "signature_invalid"
        other_context = copy.deepcopy(credential)
        other_context["proof"]["@context"] = ["https://www.w3.org/ns/credentials/v2"]
        assert await self._reason(p, other_context) == "signature_invalid"

    async def test_an_issuer_that_is_not_the_controller(self, issued: tuple[Party, dict[str, Any]]) -> None:
        p, _credential = issued
        other = await _party()
        retargeted = await _issue(other)
        retargeted["credentialSubject"]["id"] = p.agent_did
        verifier = await _verifier_with(
            p.client.export_did_webvh_history(p.controller_did),
            p.client.export_did_webvh_history(p.agent_did),
            other.client.export_did_webvh_history(other.controller_did),
        )
        result = await verifier.verify_agent_metadata_credential(retargeted)
        assert not result.ok and result.reason == "issuer_not_controller"

    async def test_a_key_the_issuer_does_not_list_under_assertion_method(
        self, issued: tuple[Party, dict[str, Any]]
    ) -> None:
        p, credential = issued
        wrong_key = copy.deepcopy(credential)
        wrong_key["proof"]["verificationMethod"] = f"{p.controller_did}#key-9"
        assert await self._reason(p, wrong_key) == "key_not_authorized"

    async def test_a_deactivated_agent(self, issued: tuple[Party, dict[str, Any]]) -> None:
        p, credential = issued
        await p.client.revoke_did(p.agent_did)
        assert await self._reason(p, credential) == "did_deactivated"

    async def test_an_unknown_agent(self, issued: tuple[Party, dict[str, Any]]) -> None:
        _p, credential = issued
        verifier = AgentDidClient(AgentDidClientOptions(clock=_clock))
        result = await verifier.verify_agent_metadata_credential(credential)
        assert not result.ok and result.reason == "did_resolution_failed"

    async def test_an_agent_that_is_not_bound_to_its_controller(self, issued: tuple[Party, dict[str, Any]]) -> None:
        p, credential = issued
        mallory = AgentDidClient(AgentDidClientOptions(clock=_clock))
        identity = AgentIdentity(AgentIdentityConfig(controller_signer=LocalKeySigner.generate()[0], client=mallory))
        forged = await identity.create(
            BASE.model_copy(
                update={
                    "name": "ForgedBot",
                    "webvh": CreateDidWebvhOptions(
                        domain="mallory.example",
                        controller_did=p.controller_did,
                        controller_signer=LocalKeySigner.generate()[0],
                    ),
                }
            )
        )
        claim = copy.deepcopy(credential)
        claim["credentialSubject"]["id"] = forged.document.id
        verifier = await _verifier_with(
            p.client.export_did_webvh_history(p.controller_did), mallory.export_did_webvh_history(forged.document.id)
        )
        result = await verifier.verify_agent_metadata_credential(claim)
        assert not result.ok and result.reason == "controller_not_bound"
