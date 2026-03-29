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


class TestInteropMessageVector:
    async def test_verify_message_signature(self, interop_vectors: dict) -> None:
        vm_data = interop_vectors["verificationMethod"]
        public_key_bytes = decode_public_key_multibase(vm_data["publicKeyMultibase"])
        payload = interop_vectors["messageVector"]["payload"]
        signature_hex = interop_vectors["messageVector"]["signatureHex"]

        vk = VerifyKey(public_key_bytes)
        # PyNaCl raises on invalid; no exception → valid
        vk.verify(payload.encode("utf-8"), bytes.fromhex(signature_hex))


class TestInteropHttpVector:
    async def test_verify_http_signature(self, interop_vectors: dict) -> None:
        did = interop_vectors["did"]
        vm_data = interop_vectors["verificationMethod"]
        http = interop_vectors["httpVector"]

        # Register the fixture DID document so verify can resolve it
        doc = AgentDIDDocument(
            **{
                "@context": ["https://www.w3.org/ns/did/v1", "https://agent-did.org/v1"],
                "id": did,
                "controller": interop_vectors["controller"],
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
            }
        )
        AgentIdentity._resolver.register_document(doc)

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
