"""Salted metadata commitments (systemPromptHash / coreModelHash)."""

from __future__ import annotations

import hashlib
import json
import pathlib
import re

import pytest

from agent_did_sdk import InMemoryAgentRegistry, LocalKeySigner
from agent_did_sdk.core.identity import AgentIdentity, AgentIdentityConfig
from agent_did_sdk.core.types import CreateAgentParams, UpdateAgentDocumentParams
from agent_did_sdk.crypto.hash import (
    create_metadata_commitment,
    generate_commitment_salt,
    verify_metadata_commitment,
)
from agent_did_sdk.resolver.in_memory import InMemoryDIDResolver

_COMMITMENT_RE = re.compile(r"^hash://hmac-sha256/[0-9a-f]{64}$")
_PROMPT = "You are a helpful assistant."
_MODEL = "gpt-4o-mini"


@pytest.fixture()
def vectors() -> dict:
    path = pathlib.Path(__file__).resolve().parents[2] / "fixtures" / "metadata-commitment-vectors.json"
    return json.loads(path.read_text(encoding="utf-8"))


@pytest.fixture()
def identity() -> AgentIdentity:
    AgentIdentity.set_resolver(InMemoryDIDResolver())
    AgentIdentity.set_registry(InMemoryAgentRegistry())
    return AgentIdentity(AgentIdentityConfig(controller_signer=LocalKeySigner.generate()[0]))


def _params(**overrides: str) -> CreateAgentParams:
    return CreateAgentParams(name="CommitmentBot", core_model=_MODEL, system_prompt=_PROMPT, **overrides)


class TestCommitmentPrimitives:
    def test_shared_hmac_sha256_vectors(self, vectors: dict) -> None:
        for vector in vectors["hmacSha256"]:
            assert create_metadata_commitment(vector["value"], vector["salt"]) == vector["expected"], vector["name"]
            assert verify_metadata_commitment(vector["expected"], vector["value"], vector["salt"])
            assert verify_metadata_commitment(vector["expected"], vector["value"], vector["salt"].upper())

    def test_legacy_unsalted_sha256_commitments(self, vectors: dict) -> None:
        for vector in vectors["legacySha256"]:
            assert verify_metadata_commitment(vector["expected"], vector["value"])
            assert not verify_metadata_commitment(vector["expected"], vector["value"] + "!")

    def test_rejects_wrong_values_salts_and_schemes(self, vectors: dict) -> None:
        vector = vectors["hmacSha256"][0]
        assert not verify_metadata_commitment(vector["expected"], vector["value"] + " ", vector["salt"])
        assert not verify_metadata_commitment(vector["expected"], vector["value"], generate_commitment_salt())
        assert not verify_metadata_commitment(vector["expected"], vector["value"])
        assert not verify_metadata_commitment(vector["expected"], vector["value"], "abcd")
        assert not verify_metadata_commitment(
            vector["expected"].replace("hmac-sha256", "sha512"), vector["value"], vector["salt"]
        )
        assert not verify_metadata_commitment(vector["expected"], "", vector["salt"])

    def test_salt_generation_and_validation(self) -> None:
        salts = {generate_commitment_salt() for _ in range(50)}
        assert len(salts) == 50
        assert all(re.fullmatch(r"[0-9a-f]{64}", salt) for salt in salts)
        with pytest.raises(ValueError, match="64 hex characters"):
            create_metadata_commitment("value", "zz" * 32)
        with pytest.raises(ValueError, match="64 hex characters"):
            create_metadata_commitment("value", "ab" * 16)
        with pytest.raises(ValueError, match="cannot be empty"):
            create_metadata_commitment("", generate_commitment_salt())


class TestAgentMetadataCommitments:
    async def test_create_commits_with_salted_hmacs_and_returns_salts(self, identity: AgentIdentity) -> None:
        result = await identity.create(_params())
        metadata = result.document.agent_metadata
        salts = result.metadata_commitment_salts
        assert salts is not None

        assert _COMMITMENT_RE.match(metadata.system_prompt_hash)
        assert _COMMITMENT_RE.match(metadata.core_model_hash)
        assert salts.core_model != salts.system_prompt
        assert verify_metadata_commitment(metadata.system_prompt_hash, _PROMPT, salts.system_prompt)
        assert verify_metadata_commitment(metadata.core_model_hash, _MODEL, salts.core_model)
        assert salts.system_prompt not in result.document.model_dump_json(by_alias=True)
        assert result.model_dump(by_alias=True)["metadataCommitmentSalts"] == {
            "coreModel": salts.core_model,
            "systemPrompt": salts.system_prompt,
        }

    async def test_guessed_prompt_cannot_be_confirmed_without_salt(self, identity: AgentIdentity) -> None:
        result = await identity.create(_params())
        commitment = result.document.agent_metadata.system_prompt_hash
        assert not verify_metadata_commitment(commitment, _PROMPT)
        assert hashlib.sha256(_PROMPT.encode("utf-8")).hexdigest() not in commitment

    async def test_same_prompt_yields_different_commitments(self, identity: AgentIdentity) -> None:
        first = await identity.create(_params())
        second = await identity.create(_params())
        assert first.document.agent_metadata.system_prompt_hash != second.document.agent_metadata.system_prompt_hash

    async def test_uses_caller_supplied_salts(self, identity: AgentIdentity) -> None:
        prompt_salt = generate_commitment_salt()
        model_salt = generate_commitment_salt()
        result = await identity.create(_params(system_prompt_salt=prompt_salt, core_model_salt=model_salt))
        assert result.metadata_commitment_salts is not None
        assert result.metadata_commitment_salts.system_prompt == prompt_salt
        assert result.metadata_commitment_salts.core_model == model_salt
        assert verify_metadata_commitment(result.document.agent_metadata.system_prompt_hash, _PROMPT, prompt_salt)

    async def test_rejects_malformed_caller_salt(self, identity: AgentIdentity) -> None:
        with pytest.raises(ValueError, match="64 hex characters"):
            await identity.create(_params(system_prompt_salt="not-hex"))

    async def test_update_requires_salt_for_prompt_or_model(self, identity: AgentIdentity) -> None:
        created = await identity.create(_params())
        did = created.document.id

        with pytest.raises(ValueError, match="system_prompt_salt is required"):
            await AgentIdentity.update_did_document(did, UpdateAgentDocumentParams(system_prompt="new prompt"))
        with pytest.raises(ValueError, match="core_model_salt is required"):
            await AgentIdentity.update_did_document(did, UpdateAgentDocumentParams(core_model="gpt-4.1"))

        salt = generate_commitment_salt()
        updated = await AgentIdentity.update_did_document(
            did, UpdateAgentDocumentParams(system_prompt="new prompt", system_prompt_salt=salt)
        )
        assert verify_metadata_commitment(updated.agent_metadata.system_prompt_hash, "new prompt", salt)
        assert updated.agent_metadata.core_model_hash == created.document.agent_metadata.core_model_hash
