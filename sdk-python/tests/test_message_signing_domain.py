"""Payload signatures cover a domain prefix (RFC-001 §7); parity: sdk/tests/MessageSigningDomain.test.ts."""

from __future__ import annotations

import base64
import time

from nacl.signing import SigningKey

from agent_did_sdk import AGENT_DID_MESSAGE_SIGNING_PREFIX, AgentDidClient, message_signing_input
from agent_did_sdk.core.http_signatures import (
    HttpRequestLike,
    SignatureInput,
    build_signature_base,
    serialize_signature_input,
)
from agent_did_sdk.core.identity import (
    AGENT_DID_HTTP_SIGNATURE_COMPONENTS,
    AGENT_DID_HTTP_SIGNATURE_TAG,
    AgentIdentity,
    AgentIdentityConfig,
)
from agent_did_sdk.core.signer import LocalKeySigner
from agent_did_sdk.core.types import CreateAgentParams, SignHttpRequestParams, VerifyHttpRequestSignatureParams

PARAMS = CreateAgentParams(name="DomainBot", core_model="gpt-4o-mini", system_prompt="You are a test assistant.")


def _setup() -> tuple[AgentDidClient, AgentIdentity]:
    client = AgentDidClient()
    identity = AgentIdentity(AgentIdentityConfig(controller_signer=LocalKeySigner.generate()[0], client=client))
    return client, identity


async def test_signs_the_domain_prefix_followed_by_the_payload() -> None:
    _, identity = _setup()
    result = await identity.create(PARAMS)
    signature = await identity.sign_message("hello", result.agent_private_key)
    signing_key = SigningKey(bytes.fromhex(result.agent_private_key))

    assert AGENT_DID_MESSAGE_SIGNING_PREFIX == "agent-did/v1/message\n"
    assert signing_key.sign(message_signing_input("hello")).signature.hex() == signature
    assert signing_key.sign(b"hello").signature.hex() != signature


async def test_verifies_payload_signatures_and_rejects_a_raw_signature_over_the_same_payload() -> None:
    client, identity = _setup()
    result = await identity.create(PARAMS)
    signature = await identity.sign_message("approve", result.agent_private_key)
    raw = SigningKey(bytes.fromhex(result.agent_private_key)).sign(b"approve").signature.hex()

    assert await client.verify_signature(result.document.id, "approve", signature) is True
    assert await client.verify_signature(result.document.id, "approve", raw) is False


async def test_a_payload_signature_does_not_stand_in_for_the_signature_of_an_http_request() -> None:
    client, identity = _setup()
    result = await identity.create(PARAMS)
    document = result.document
    key_id = document.authentication[0]
    url = "https://api.example.com/v1/transfer"
    body = '{"amount":1}'
    signed = await identity.sign_http_request(
        SignHttpRequestParams(
            method="POST",
            url=url,
            body=body,
            agent_private_key=result.agent_private_key,
            agent_did=document.id,
            verification_method_id=key_id,
        )
    )

    created = int(time.time())
    headers = {
        "Signature-Agent": document.id,
        "Date": signed["Date"],
        "Content-Digest": signed["Content-Digest"],
    }
    signature_input = SignatureInput(
        components=list(AGENT_DID_HTTP_SIGNATURE_COMPONENTS),
        params=[
            ("created", created),
            ("expires", created + 30),
            ("nonce", "a" * 32),
            ("keyid", key_id),
            ("alg", "ed25519"),
            ("tag", AGENT_DID_HTTP_SIGNATURE_TAG),
        ],
    )
    base = build_signature_base(HttpRequestLike(method="POST", url=url, headers=headers), signature_input)
    via_sign_message = await identity.sign_message(base, result.agent_private_key)
    encoded = base64.b64encode(bytes.fromhex(via_sign_message)).decode()
    forged = {
        **headers,
        "Signature-Input": f"sig1={serialize_signature_input(signature_input)}",
        "Signature": f"sig1=:{encoded}:",
    }

    forged_result = await client.verify_http_request_signature_detailed(
        VerifyHttpRequestSignatureParams(method="POST", url=url, body=body, headers=forged)
    )
    assert forged_result.ok is False

    genuine = await client.verify_http_request_signature_detailed(
        VerifyHttpRequestSignatureParams(method="POST", url=url, body=body, headers=signed)
    )
    assert genuine.ok is True
