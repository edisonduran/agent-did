"""did:wba DID -> document URL vectors (fixtures/did-wba-url-vectors.json).

Parity: sdk/tests/DidWbaUrlVectors.test.ts.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from agent_did_sdk import InMemoryAgentRegistry, UniversalResolverClient
from agent_did_sdk.core.types import AgentDIDDocument
from agent_did_sdk.resolver.types import UniversalResolverConfig

_FIXTURE = json.loads(
    (Path(__file__).resolve().parents[2] / "fixtures" / "did-wba-url-vectors.json").read_text(encoding="utf-8")
)
_VECTORS: list[dict[str, Any]] = _FIXTURE["vectors"]


def _document(did: str) -> AgentDIDDocument:
    return AgentDIDDocument.model_validate({
        "@context": ["https://www.w3.org/ns/did/v1"],
        "id": did,
        "controller": did,
        "created": "2026-01-01T00:00:00Z",
        "updated": "2026-01-01T00:00:00Z",
        "agentMetadata": {"name": "bot", "version": "1", "coreModelHash": "h", "systemPromptHash": "h"},
        "verificationMethod": [],
        "authentication": [],
    })


class _RecordingSource:
    def __init__(self, did: str) -> None:
        self.did = did
        self.urls: list[str] = []

    async def get_by_reference(self, ref: str) -> AgentDIDDocument:
        self.urls.append(ref)
        return _document(self.did)


class _NoDocuments:
    async def get_by_reference(self, ref: str) -> None:
        return None


def _resolver(source: _RecordingSource) -> UniversalResolverClient:
    return UniversalResolverClient(UniversalResolverConfig(
        registry=InMemoryAgentRegistry(),
        document_source=_NoDocuments(),  # type: ignore[arg-type]
        wba_document_source=source,  # type: ignore[arg-type]
    ))


def test_fixture_has_positive_and_negative_vectors() -> None:
    assert any("url" in v for v in _VECTORS)
    assert sum(1 for v in _VECTORS if v.get("invalid")) >= 20


@pytest.mark.parametrize("vector", [v for v in _VECTORS if "url" in v], ids=lambda v: v["did"])
async def test_derives_the_document_url(vector: dict[str, Any]) -> None:
    source = _RecordingSource(vector["did"])
    resolved = await _resolver(source).resolve(vector["did"])
    assert resolved.id == vector["did"]
    assert source.urls == [vector["url"]]


@pytest.mark.parametrize("vector", [v for v in _VECTORS if v.get("invalid")], ids=lambda v: v["did"])
async def test_rejects_the_did_before_any_fetch(vector: dict[str, Any]) -> None:
    source = _RecordingSource(vector["did"])
    with pytest.raises(ValueError, match="Invalid did:wba"):
        await _resolver(source).resolve(vector["did"])
    assert source.urls == []
