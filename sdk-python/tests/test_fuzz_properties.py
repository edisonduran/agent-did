"""Property tests / fuzzing of the SDK's input parsers (M-14).

Structured Fields (Signature-Input / Signature), did.jsonl and publicKeyMultibase.
The default profile is small so the normal suite stays fast; the nightly workflow
``ci-fuzz.yml`` selects the ``nightly`` profile through HYPOTHESIS_PROFILE.
TypeScript parity: sdk/tests/Fuzz.property.test.ts.
"""

from __future__ import annotations

import asyncio
import base64
import json
import os
from typing import Any

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from agent_did_sdk.core.http_signatures import (
    HttpSignatureError,
    parse_signature_header,
    parse_signature_input_header,
)
from agent_did_sdk.core.signer import LocalKeySigner
from agent_did_sdk.crypto.multibase import decode_public_key_multibase, encode_public_key_multibase
from agent_did_sdk.webvh.adapter import (
    DID_WEBVH_PLACEHOLDER,
    DidWebvhError,
    create_did_webvh_log,
    resolve_did_webvh_log,
)

settings.register_profile("default", max_examples=100, deadline=None, suppress_health_check=[HealthCheck.too_slow])
settings.register_profile("nightly", max_examples=5000, deadline=None, suppress_health_check=[HealthCheck.too_slow])
settings.load_profile(os.environ.get("HYPOTHESIS_PROFILE", "default"))

SF_ALPHABET = 'abcdefghijklmnopqrstuvwxyz0123456789=:;,()" *@._-/+'
sf_like = st.one_of(
    st.text(max_size=120),
    st.text(alphabet=SF_ALPHABET, max_size=120),
)
label = st.from_regex(r"[a-z][a-z0-9_\-]{0,10}", fullmatch=True)


json_value = st.recursive(
    st.none() | st.booleans() | st.integers() | st.text(max_size=10),
    lambda children: st.lists(children, max_size=3) | st.dictionaries(st.text(max_size=5), children, max_size=3),
    max_leaves=8,
)
json_lines = st.lists(json_value, min_size=1, max_size=3)


class TestStructuredFieldParsers:
    @given(sf_like)
    def test_signature_input_only_raises_http_signature_error(self, value: str) -> None:
        try:
            parse_signature_input_header(value)
        except HttpSignatureError:
            pass

    @given(sf_like)
    def test_signature_only_raises_http_signature_error(self, value: str) -> None:
        try:
            parse_signature_header(value)
        except HttpSignatureError:
            pass

    @given(
        st.dictionaries(label, st.binary(max_size=80), min_size=1, max_size=4),
    )
    def test_signature_round_trips_byte_sequences(self, members: dict[str, bytes]) -> None:
        header = ", ".join(f"{name}=:{base64.b64encode(data).decode()}:" for name, data in members.items())
        assert parse_signature_header(header) == members

    @given(
        label,
        st.lists(
            st.sampled_from(["@method", "@authority", "@path", "@query", "content-digest", "date"]),
            min_size=1,
            max_size=6,
        ),
        st.integers(min_value=0, max_value=2**31),
        st.from_regex(r"[A-Za-z0-9_\-]{1,20}", fullmatch=True),
    )
    def test_signature_input_round_trips_inner_lists(
        self, name: str, components: list[str], created: int, nonce: str
    ) -> None:
        header = f'{name}=({" ".join(chr(34) + c + chr(34) for c in components)});created={created};nonce="{nonce}"'
        member = parse_signature_input_header(header)[name]
        assert member.components == components
        assert dict(member.params) == {"created": created, "nonce": nonce}


class TestPublicKeyMultibase:
    @given(st.binary(min_size=32, max_size=32))
    def test_round_trips_any_32_byte_key(self, key: bytes) -> None:
        encoded = encode_public_key_multibase(key)
        assert encoded.startswith("z")
        assert decode_public_key_multibase(encoded) == key

    @given(st.binary(max_size=64).filter(lambda key: len(key) != 32))
    def test_rejects_any_key_that_is_not_32_bytes(self, key: bytes) -> None:
        with pytest.raises(ValueError):
            encode_public_key_multibase(key)

    @given(
        st.one_of(
            st.text(max_size=80),
            st.from_regex(r"z?[1-9A-HJ-NP-Za-km-z0-9]{0,60}", fullmatch=True),
        )
    )
    def test_decode_only_raises_value_error_and_returns_32_bytes(self, value: str) -> None:
        try:
            result = decode_public_key_multibase(value)
        except ValueError:
            return
        assert len(result) == 32

    @given(st.binary(min_size=32, max_size=32))
    def test_legacy_hex_keys_are_always_rejected(self, key: bytes) -> None:
        with pytest.raises(ValueError, match="Unable to decode publicKeyMultibase"):
            decode_public_key_multibase(f"z{key.hex()}")


def _run(coro: Any) -> Any:
    return asyncio.run(coro)


@pytest.fixture(scope="module")
def valid_log() -> tuple[str, Any]:
    created = _run(
        create_did_webvh_log(
            domain="agents.example.com",
            document={
                "@context": ["https://www.w3.org/ns/did/v1"],
                "id": DID_WEBVH_PLACEHOLDER,
                "controller": "did:webvh:controller.example.com",
            },
            signer=LocalKeySigner("1" * 64),
            created="2026-01-01T00:00:00Z",
        )
    )
    return created.log, _run(resolve_did_webvh_log(created.log)).document


def _outcome(text: str, expected_document: Any) -> str:
    """Either rejected with DidWebvhError, or resolved to exactly the original document."""
    try:
        result = _run(resolve_did_webvh_log(text))
    except DidWebvhError:
        return "rejected"
    assert result.document == expected_document
    return "ok"


class TestDidJsonlResolution:
    @given(st.one_of(st.text(max_size=200), st.text(alphabet='{}[]":,0123456789 \nabcdef', max_size=200)))
    def test_arbitrary_text_only_fails_with_did_webvh_error(self, valid_log: tuple[str, Any], text: str) -> None:
        assert _outcome(text, valid_log[1]) == "rejected"

    @given(json_lines)
    def test_arbitrary_json_lines_only_fail_with_did_webvh_error(
        self, valid_log: tuple[str, Any], values: list[Any]
    ) -> None:
        text = "\n".join(json.dumps(value) for value in values)
        assert _outcome(text, valid_log[1]) == "rejected"

    @settings(max_examples=50)
    @given(st.data())
    def test_mutated_valid_log_is_rejected_or_resolves_identically(
        self, valid_log: tuple[str, Any], data: st.DataObject
    ) -> None:
        log, document = valid_log
        index = data.draw(st.integers(min_value=0, max_value=len(log) - 1))
        replacement = data.draw(st.text(min_size=1, max_size=3))
        _outcome(log[:index] + replacement + log[index + 1 :], document)

    @settings(max_examples=50)
    @given(st.data())
    def test_truncated_valid_log_is_rejected_or_resolves_identically(
        self, valid_log: tuple[str, Any], data: st.DataObject
    ) -> None:
        log, document = valid_log
        end = data.draw(st.integers(min_value=0, max_value=len(log)))
        _outcome(log[:end], document)
