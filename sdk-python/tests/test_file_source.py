"""Tests for FilesystemDIDDocumentSource."""

from __future__ import annotations

import json

from agent_did_sdk.resolver.file_source import (
    FilesystemDIDDocumentSource,
    FilesystemDIDDocumentSourceConfig,
)


def _make_document() -> dict[str, object]:
    did = "did:webvh:QmFilesystemScid:example.com:agents:file-bot"
    return {
        "@context": ["https://www.w3.org/ns/did/v1", "https://agent-did.org/v1"],
        "id": did,
        "controller": "did:webvh:QmFilesystemScid:example.com:organizations:ops-root",
        "created": "2026-05-06T00:00:00.000Z",
        "updated": "2026-05-06T00:00:00.000Z",
        "agentMetadata": {
            "name": "FilesystemResolverBot",
            "version": "1.0.0",
            "coreModelHash": "hash://sha256/model",
            "systemPromptHash": "hash://sha256/prompt",
        },
        "verificationMethod": [
            {
                "id": f"{did}#key-1",
                "type": "Ed25519VerificationKey2020",
                "controller": "did:webvh:QmFilesystemScid:example.com:organizations:ops-root",
                "publicKeyMultibase": "zabc",
            }
        ],
        "authentication": [f"{did}#key-1"],
        "assertionMethod": [f"{did}#key-1"],
    }


class TestFilesystemDIDDocumentSource:
    async def test_store_and_load_document(self, tmp_path) -> None:
        source = FilesystemDIDDocumentSource(FilesystemDIDDocumentSourceConfig(
            reference_to_path=lambda document_ref: tmp_path / f"{document_ref.replace(':', '_')}.json",
        ))

        from agent_did_sdk.core.types import AgentDIDDocument

        await source.store_by_reference(
            "hash://sha256/fs-doc",
            AgentDIDDocument.model_validate(_make_document()),
        )
        loaded = await source.get_by_reference("hash://sha256/fs-doc")

        assert loaded is not None
        assert loaded.id == _make_document()["id"]

    async def test_missing_document_returns_none(self, tmp_path) -> None:
        source = FilesystemDIDDocumentSource(FilesystemDIDDocumentSourceConfig(
            reference_to_path=lambda document_ref: tmp_path / f"{document_ref.replace(':', '_')}.json",
        ))

        loaded = await source.get_by_reference("hash://sha256/missing")
        assert loaded is None

    async def test_store_and_load_did_log(self, tmp_path) -> None:
        source = FilesystemDIDDocumentSource(FilesystemDIDDocumentSourceConfig(
            reference_to_path=lambda document_ref: tmp_path / f"{document_ref.replace(':', '_')}.jsonl",
        ))
        did_log = json.dumps({"versionId": "1-QmFilesystemScid", "state": _make_document()})

        await source.store_did_log_by_reference("history://fs-log", did_log)
        loaded = await source.get_did_log_by_reference("history://fs-log")

        assert loaded == did_log

    async def test_fail_over_across_candidate_paths(self, tmp_path) -> None:
        candidate_paths = [tmp_path / "missing.json", tmp_path / "valid.json"]
        candidate_paths[1].write_text(json.dumps(_make_document()), encoding="utf-8")

        source = FilesystemDIDDocumentSource(FilesystemDIDDocumentSourceConfig(
            reference_to_paths=lambda _document_ref: candidate_paths,
        ))
        loaded = await source.get_by_reference("hash://sha256/fs-failover")

        assert loaded is not None
        assert loaded.id == _make_document()["id"]
