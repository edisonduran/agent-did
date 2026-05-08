"""Interoperability vector tests — MUST match the TypeScript SDK byte-for-byte."""

from __future__ import annotations

from nacl.signing import VerifyKey

from agent_did_sdk.core.identity import AgentIdentity
from agent_did_sdk.core.types import (
    AgentDIDDocument,
    VerifyHttpRequestSignatureParams,
)
from agent_did_sdk.crypto.hash import generate_canonical_document_hash
from agent_did_sdk.crypto.multibase import decode_public_key_multibase


def _build_interop_document(vector: dict) -> AgentDIDDocument:
    vm_data = vector["verificationMethod"]
    return AgentDIDDocument(
        **{
            "@context": ["https://www.w3.org/ns/did/v1", "https://agent-did.org/v1"],
            "id": vector["did"],
            "controller": vector["controller"],
            "created": "2024-01-01T00:00:00Z",
            "updated": "2024-01-01T00:00:00Z",
            "agentMetadata": {
                "name": "InteropFixture",
                "version": "1.0.0",
                "coreModelHash": "hash://sha256/interop",
                "systemPromptHash": "hash://sha256/interop",
            },
            "verificationMethod": [vm_data],
            "authentication": [vm_data["id"]],
            "assertionMethod": [vm_data["id"]],
        }
    )


def _build_interop_controller_document(vector: dict) -> AgentDIDDocument:
    return AgentDIDDocument(
        **{
            "@context": ["https://www.w3.org/ns/did/v1", "https://agent-did.org/v1"],
            "id": vector["controller"],
            "controller": vector["controller"],
            "created": "2024-01-01T00:00:00Z",
            "updated": "2024-01-01T00:00:00Z",
            "agentMetadata": {
                "name": "InteropFixtureController",
                "version": "1.0.0",
                "coreModelHash": "hash://sha256/controller",
                "systemPromptHash": "hash://sha256/controller",
            },
            "verificationMethod": [
                {
                    "id": f"{vector['controller']}#key-1",
                    "type": "Ed25519VerificationKey2020",
                    "controller": vector["controller"],
                    "publicKeyMultibase": vector["verificationMethod"]["publicKeyMultibase"],
                }
            ],
            "authentication": [f"{vector['controller']}#key-1"],
            "assertionMethod": [f"{vector['controller']}#key-1"],
        }
    )


class TestInteropMessageVector:
    async def test_verify_message_signature(self, interop_vectors: dict) -> None:
        for vector in interop_vectors["vectors"].values():
            vm_data = vector["verificationMethod"]
            public_key_bytes = decode_public_key_multibase(vm_data["publicKeyMultibase"])
            payload = vector["messageVector"]["payload"]
            signature_hex = vector["messageVector"]["signatureHex"]

            vk = VerifyKey(public_key_bytes)
            # PyNaCl raises on invalid; no exception → valid
            vk.verify(payload.encode("utf-8"), bytes.fromhex(signature_hex))


class TestInteropHttpVector:
    async def test_verify_http_signature(self, interop_vectors: dict) -> None:
        for vector in interop_vectors["vectors"].values():
            http = vector["httpVector"]

            # Register the fixture DID document so verify can resolve it
            AgentIdentity._resolver.register_document(_build_interop_document(vector))
            AgentIdentity._resolver.register_document(_build_interop_controller_document(vector))

            is_valid = await AgentIdentity.verify_http_request_signature(
                VerifyHttpRequestSignatureParams(
                    method=http["method"],
                    url=http["url"],
                    body=http["body"],
                    headers=http["headers"],
                    max_created_skew_seconds=http.get("maxCreatedSkewSeconds", 999999999),
                )
            )
            assert is_valid is True


class TestCanonicalDocumentReferenceVector:
    def test_canonical_document_ref_matches_shared_fixture(self, canonical_document_fixture: dict) -> None:
        assert generate_canonical_document_hash(
            canonical_document_fixture["document"]
        ) == canonical_document_fixture["expectedDocumentRef"]
