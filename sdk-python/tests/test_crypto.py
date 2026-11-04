"""Tests for the crypto/hash module."""

import pytest
import rfc8785

from agent_did_sdk.crypto.hash import (
    canonicalize_json,
    format_hash_uri,
    generate_agent_metadata_hash,
    generate_canonical_document_hash,
    hash_payload,
)
from agent_did_sdk.crypto.multibase import decode_public_key_multibase


class TestHashPayload:
    def test_deterministic(self) -> None:
        assert hash_payload("hello") == hash_payload("hello")

    def test_empty_raises(self) -> None:
        with pytest.raises(ValueError, match="empty"):
            hash_payload("")

    def test_starts_with_0x(self) -> None:
        result = hash_payload("test")
        assert result.startswith("0x")
        assert len(result) == 66  # 0x + 64 hex chars

    def test_different_inputs(self) -> None:
        assert hash_payload("a") != hash_payload("b")


class TestDecodeEmptyMultibase:
    def test_empty_string_raises_value_error(self) -> None:
        # Found by fuzzing (M-14): used to raise IndexError instead of ValueError.
        with pytest.raises(ValueError, match="Unsupported multibase prefix: ''"):
            decode_public_key_multibase("")


class TestFormatHashUri:
    def test_strips_0x(self) -> None:
        assert format_hash_uri("0xabc123") == "hash://sha256/abc123"

    def test_no_prefix(self) -> None:
        assert format_hash_uri("abc123") == "hash://sha256/abc123"


class TestGenerateAgentMetadataHash:
    def test_returns_hash_uri(self) -> None:
        result = generate_agent_metadata_hash("my-model-v1")
        assert result.startswith("hash://sha256/")

    def test_deterministic(self) -> None:
        assert generate_agent_metadata_hash("x") == generate_agent_metadata_hash("x")


class TestCanonicalDocumentHash:
    def test_key_order_does_not_change_the_hash(self) -> None:
        left = {
            "updated": "2024-01-01T00:00:00.000Z",
            "agentMetadata": {"systemPromptHash": "hash://sha256/prompt", "name": "Fixture"},
            "created": "2024-01-01T00:00:00.000Z",
        }
        right = {
            "created": "2024-01-01T00:00:00.000Z",
            "agentMetadata": {"name": "Fixture", "systemPromptHash": "hash://sha256/prompt"},
            "updated": "2024-01-01T00:00:00.000Z",
        }

        assert canonicalize_json(left) == canonicalize_json(right)
        assert generate_canonical_document_hash(left) == generate_canonical_document_hash(right)

    def test_timestamps_are_hashed_as_given(self) -> None:
        # JCS does not rewrite values: equivalent instants with different spellings differ.
        assert canonicalize_json({"created": "2024-01-01T00:00:00Z"}) == '{"created":"2024-01-01T00:00:00Z"}'
        assert generate_canonical_document_hash({"created": "2024-01-01T00:00:00Z"}) != (
            generate_canonical_document_hash({"created": "2024-01-01T00:00:00.000Z"})
        )

    def test_sorts_by_utf16_code_units_not_locale(self) -> None:
        assert canonicalize_json({"a": 1, "B": 2, "é": 3, "😂": 4, "דּ": 5}) == (
            '{"B":2,"a":1,"é":3,"😂":4,"דּ":5}'
        )

    def test_null_members_are_kept(self) -> None:
        assert canonicalize_json({"b": None, "a": [None]}) == '{"a":[null],"b":null}'

    def test_rejects_values_outside_jcs(self) -> None:
        with pytest.raises(rfc8785.CanonicalizationError):
            canonicalize_json(float("nan"))
        with pytest.raises(rfc8785.CanonicalizationError):
            canonicalize_json(2**60)
