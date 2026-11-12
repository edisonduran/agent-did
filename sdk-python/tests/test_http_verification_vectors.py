"""HTTP verification vectors of RFC-001 §6.5: the accepted and rejected requests of
``fixtures/http-verification-vectors.json``. The TypeScript SDK runs the same file
(``sdk/tests/HttpVerificationVectors.test.ts``)."""

from __future__ import annotations

import json
import pathlib
from datetime import datetime, timezone
from typing import Any

import pytest

from agent_did_sdk.core.client import AgentDidClient, AgentDidClientOptions
from agent_did_sdk.core.nonce_store import InMemoryNonceStore
from agent_did_sdk.core.types import (
    AgentDIDDocument,
    VerifyHttpRequestSignatureParams,
    VerifyHttpRequestSignatureResult,
)
from agent_did_sdk.registry.in_memory import InMemoryAgentRegistry
from agent_did_sdk.resolver.in_memory import InMemoryDIDResolver

FIXTURE: dict[str, Any] = json.loads(
    (pathlib.Path(__file__).resolve().parents[2] / "fixtures" / "http-verification-vectors.json").read_text(
        encoding="utf-8"
    )
)
CONTEXT = ["https://www.w3.org/ns/did/v1", "https://agent-did.org/v1"]


def _meta(name: str) -> dict[str, str]:
    return {
        "name": name,
        "version": "1.0.0",
        "coreModelHash": "hash://sha256/model",
        "systemPromptHash": "hash://sha256/prompt",
    }


def _ids_for(relationship: str) -> list[str]:
    return [key["id"] for key in FIXTURE["keys"].values() if relationship in key["relationships"]]


def _agent_document() -> AgentDIDDocument:
    return AgentDIDDocument(
        **{
            "@context": CONTEXT,
            "id": FIXTURE["did"],
            # Self-controlled: the vectors test the HTTP rules, and a document-only resolver cannot prove a binding
            "controller": FIXTURE["did"],
            "created": "2024-01-01T00:00:00.000Z",
            "updated": "2024-01-01T00:00:00.000Z",
            "agentMetadata": _meta("HttpVerificationFixtureBot"),
            "verificationMethod": [
                {
                    "id": key["id"],
                    "type": "Ed25519VerificationKey2020",
                    "controller": FIXTURE["controller"],
                    "publicKeyMultibase": key["publicKeyMultibase"],
                }
                for key in FIXTURE["keys"].values()
            ],
            "authentication": _ids_for("authentication"),
            "assertionMethod": _ids_for("assertionMethod"),
            "keyAgreement": _ids_for("keyAgreement"),
        }
    )


def _controller_document() -> AgentDIDDocument:
    key = FIXTURE["keys"]["key-1"]
    controller = FIXTURE["controller"]
    return AgentDIDDocument(
        **{
            "@context": CONTEXT,
            "id": controller,
            "controller": controller,
            "created": "2024-01-01T00:00:00.000Z",
            "updated": "2024-01-01T00:00:00.000Z",
            "agentMetadata": _meta("HttpVerificationFixtureController"),
            "verificationMethod": [
                {
                    "id": f"{controller}#key-1",
                    "type": "Ed25519VerificationKey2020",
                    "controller": controller,
                    "publicKeyMultibase": key["publicKeyMultibase"],
                }
            ],
            "authentication": [f"{controller}#key-1"],
            "assertionMethod": [f"{controller}#key-1"],
        }
    )


async def _client_at(now: int) -> tuple[AgentDidClient, InMemoryNonceStore]:
    document = _agent_document()
    resolver = InMemoryDIDResolver()
    resolver.register_document(document)
    resolver.register_document(_controller_document())
    registry = InMemoryAgentRegistry()
    await registry.register(document.id, document.controller, "hash://sha256/http-verification-fixture")
    # The store's own clock must match the vector clock, or its entries expire at once.
    nonce_store = InMemoryNonceStore(now=lambda: now)
    client = AgentDidClient(
        AgentDidClientOptions(
            resolver=resolver,
            registry=registry,
            nonce_store=nonce_store,
            clock=lambda: datetime.fromtimestamp(now, tz=timezone.utc),
        )
    )
    return client, nonce_store


def _params(vector: dict[str, Any], nonce_store: InMemoryNonceStore) -> VerifyHttpRequestSignatureParams:
    request = vector["request"]
    return VerifyHttpRequestSignatureParams(
        method=request["method"],
        url=request["url"],
        body=request["body"],
        headers=vector["headers"],
        max_created_skew_seconds=vector.get("maxCreatedSkewSeconds"),
        max_signature_lifetime_seconds=vector.get("maxSignatureLifetimeSeconds"),
        nonce_store=nonce_store,
    )


def test_fixture_format() -> None:
    assert FIXTURE["formatVersion"] == 1
    ids = [vector["id"] for vector in FIXTURE["vectors"]]
    assert ids
    assert len(set(ids)) == len(ids)


@pytest.mark.parametrize("vector", FIXTURE["vectors"], ids=[vector["id"] for vector in FIXTURE["vectors"]])
async def test_http_verification_vector(vector: dict[str, Any]) -> None:
    now = vector.get("now", FIXTURE["clock"])
    client, nonce_store = await _client_at(now)

    async def verify() -> VerifyHttpRequestSignatureResult:
        return await client.verify_http_request_signature_detailed(_params(vector, nonce_store))

    if "expectedSequence" in vector:
        results = [await verify() for _ in vector["expectedSequence"]]
        assert [result.ok for result in results] == vector["expectedSequence"]
        assert [result.reason for result in results] == vector["expectedReasons"]
        return

    result = await verify()
    assert result.ok is vector["expected"]
    assert result.reason == vector.get("reason")

    # The boolean method gives the same verdict (fresh client: its nonce store is not shared).
    fresh, fresh_store = await _client_at(now)
    assert await fresh.verify_http_request_signature(_params(vector, fresh_store)) is vector["expected"]
