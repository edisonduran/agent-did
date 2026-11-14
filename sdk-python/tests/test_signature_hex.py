"""Payload signatures written as hex (parity: sdk/tests/SignatureHex.test.ts)."""

from __future__ import annotations

import re

import pytest

from agent_did_sdk.core.client import AgentDidClient
from agent_did_sdk.core.identity import AgentIdentity, AgentIdentityConfig
from agent_did_sdk.core.signer import LocalKeySigner
from agent_did_sdk.core.types import CreateAgentParams
from agent_did_sdk.crypto.ed25519 import decode_signature_hex


async def test_accepts_exactly_128_hex_digits_in_either_case_and_nothing_else() -> None:
    client = AgentDidClient()
    identity = AgentIdentity(AgentIdentityConfig(controller_signer=LocalKeySigner.generate()[0], client=client))
    result = await identity.create(CreateAgentParams(name="HexBot", core_model="test", system_prompt="test"))
    signature = await identity.sign_message("hello", result.agent_private_key)
    did = result.document.id
    key_id = f"{did}#key-1"

    assert await client.verify_signature(did, "hello", signature, key_id) is True
    assert await client.verify_signature(did, "hello", signature.upper(), key_id) is True
    spaced = re.sub(r"(..)", r"\1 ", signature).strip()
    for variant in (spaced, f"0x{signature}", f" {signature}", f"{signature}\n", signature[2:]):
        assert await client.verify_signature(did, "hello", variant, key_id) is False


def test_decodes_only_the_strict_form() -> None:
    assert len(decode_signature_hex("ab" * 64)) == 64
    with pytest.raises(ValueError):
        decode_signature_hex("ab " * 64)
    with pytest.raises(ValueError):
        decode_signature_hex("ab" * 63)
