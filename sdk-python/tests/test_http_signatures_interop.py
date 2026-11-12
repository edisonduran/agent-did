"""Cross-checks the Agent-DID RFC 9421 profile against an independent implementation
(``http-message-signatures``, dev dependency). Parity: sdk/tests/HttpSignaturesInterop.test.ts."""

from __future__ import annotations

import base64
import datetime
import hashlib
import os

import pytest
import requests
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from http_message_signatures import HTTPMessageSigner, HTTPMessageVerifier, HTTPSignatureKeyResolver, algorithms

from agent_did_sdk import (
    AGENT_DID_HTTP_SIGNATURE_COMPONENTS,
    AgentIdentity,
    AgentIdentityConfig,
    CreateAgentParams,
    InMemoryNonceStore,
    LocalKeySigner,
    SignHttpRequestParams,
    VerifyHttpRequestSignatureParams,
    decode_public_key_multibase,
)

URL = "https://api.example.com/v1/orders?id=42"
BODY = '{"qty":1}'


class _Keys(HTTPSignatureKeyResolver):  # type: ignore[misc]
    def __init__(self, key_id: str, private_key_hex: str | None = None, public_key: bytes | None = None) -> None:
        self._key_id = key_id
        self._private = (
            Ed25519PrivateKey.from_private_bytes(bytes.fromhex(private_key_hex)) if private_key_hex else None
        )
        self._public = Ed25519PublicKey.from_public_bytes(public_key) if public_key else None

    def resolve_public_key(self, key_id: str) -> Ed25519PublicKey | None:
        return self._public if key_id == self._key_id else None

    def resolve_private_key(self, key_id: str) -> Ed25519PrivateKey:
        if key_id != self._key_id or self._private is None:
            raise KeyError(key_id)
        return self._private


@pytest.fixture()
def identity() -> AgentIdentity:
    return AgentIdentity(AgentIdentityConfig(controller_signer=LocalKeySigner.generate()[0]))


class TestRfc9421Interop:
    async def test_sdk_signatures_verify_with_the_independent_implementation(self, identity: AgentIdentity) -> None:
        result = await identity.create(CreateAgentParams(name="InteropOut", core_model="m", system_prompt="p"))
        headers = await identity.sign_http_request(
            SignHttpRequestParams(
                method="POST", url=URL, body=BODY,
                agent_private_key=result.agent_private_key, agent_did=result.document.id,
                    verification_method_id=f"{result.document.id}#key-1",
            )
        )
        key_id = f"{result.document.id}#key-1"
        public_key = decode_public_key_multibase(result.document.verification_method[0].public_key_multibase or "")

        prepared = requests.Request("POST", URL, data=BODY, headers=headers).prepare()
        verifier = HTTPMessageVerifier(
            signature_algorithm=algorithms.ED25519, key_resolver=_Keys(key_id, public_key=public_key)
        )
        results = verifier.verify(
            prepared, expect_tag="agent-did", require_components=list(AGENT_DID_HTTP_SIGNATURE_COMPONENTS)
        )

        assert len(results) == 1
        assert results[0].parameters["keyid"] == key_id

    async def test_independent_signatures_verify_with_the_sdk(self, identity: AgentIdentity) -> None:
        result = await identity.create(CreateAgentParams(name="InteropIn", core_model="m", system_prompt="p"))
        key_id = f"{result.document.id}#key-1"
        created = datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0)
        headers = {
            "Signature-Agent": result.document.id,
            "Date": created.strftime("%a, %d %b %Y %H:%M:%S GMT"),
            "Content-Digest": f"sha-256=:{base64.b64encode(hashlib.sha256(BODY.encode()).digest()).decode()}:",
        }
        prepared = requests.Request("POST", URL, data=BODY, headers=headers).prepare()

        signer = HTTPMessageSigner(
            signature_algorithm=algorithms.ED25519,
            key_resolver=_Keys(key_id, private_key_hex=result.agent_private_key),
        )
        signer.sign(
            prepared,
            key_id=key_id,
            created=created,
            expires=created + datetime.timedelta(seconds=30),
            nonce=os.urandom(16).hex(),
            label="sig1",
            tag="agent-did",
            covered_component_ids=list(AGENT_DID_HTTP_SIGNATURE_COMPONENTS),
            use_existing_digest=True,
        )
        signed_headers = dict(prepared.headers)

        assert await AgentIdentity.verify_http_request_signature(
            VerifyHttpRequestSignatureParams(
                method="POST", url=URL, body=BODY, headers=signed_headers, nonce_store=InMemoryNonceStore()
            )
        ) is True
        assert await AgentIdentity.verify_http_request_signature(
            VerifyHttpRequestSignatureParams(
                method="POST", url=URL, body='{"qty":9}', headers=signed_headers, nonce_store=InMemoryNonceStore()
            )
        ) is False
