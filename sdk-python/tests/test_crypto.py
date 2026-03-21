"""Tests for the crypto/hash module."""

import pytest

from agent_did_sdk.crypto.hash import format_hash_uri, generate_agent_metadata_hash, hash_payload


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
