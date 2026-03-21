"""Tests for core/time_utils module."""

import pytest

from agent_did_sdk.core.time_utils import (
    is_unix_timestamp_string,
    iso_to_unix_string,
    normalize_timestamp_to_iso,
    unix_string_to_iso,
)


class TestIsUnixTimestampString:
    def test_positive(self) -> None:
        assert is_unix_timestamp_string("1704067200") is True

    def test_negative_iso(self) -> None:
        assert is_unix_timestamp_string("2024-01-01T00:00:00Z") is False

    def test_negative_empty(self) -> None:
        assert is_unix_timestamp_string("") is False

    def test_with_whitespace(self) -> None:
        assert is_unix_timestamp_string("  123  ") is True


class TestUnixStringToIso:
    def test_known_value(self) -> None:
        result = unix_string_to_iso("1704067200")
        assert result.startswith("2024-01-01T00:00:00")

    def test_invalid_raises(self) -> None:
        with pytest.raises(ValueError, match="Invalid unix"):
            unix_string_to_iso("not-a-number")


class TestIsoToUnixString:
    def test_known_value(self) -> None:
        result = iso_to_unix_string("2024-01-01T00:00:00.000Z")
        assert result == "1704067200"

    def test_invalid_raises(self) -> None:
        with pytest.raises(ValueError, match="Invalid ISO"):
            iso_to_unix_string("garbage")


class TestNormalizeTimestampToIso:
    def test_unix_to_iso(self) -> None:
        result = normalize_timestamp_to_iso("1704067200")
        assert result is not None
        assert result.startswith("2024-01-01")

    def test_iso_passthrough(self) -> None:
        iso = "2024-06-15T12:00:00Z"
        assert normalize_timestamp_to_iso(iso) == "2024-06-15T12:00:00.000Z"

    def test_iso_offset_canonicalization(self) -> None:
        iso = "2024-06-15T12:00:00+00:00"
        assert normalize_timestamp_to_iso(iso) == "2024-06-15T12:00:00.000Z"

    def test_none_returns_none(self) -> None:
        assert normalize_timestamp_to_iso(None) is None

    def test_empty_returns_none(self) -> None:
        assert normalize_timestamp_to_iso("") is None
