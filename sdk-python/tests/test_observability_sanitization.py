"""Observability sanitization (parity: sdk/tests/ObservabilitySanitization.test.ts)."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest
from pydantic import BaseModel

from agent_did_sdk import (
    is_redacted_marker,
    is_sensitive_field_name,
    sanitize_headers,
    sanitize_observability_attributes,
    sanitize_url,
)

_VECTORS: list[dict[str, Any]] = json.loads(
    (Path(__file__).resolve().parents[2] / "fixtures" / "observability-sanitization-vectors.json").read_text(
        encoding="utf-8"
    )
)["vectors"]


@pytest.mark.parametrize("vector", _VECTORS, ids=lambda v: v["id"])
def test_shared_vectors(vector: dict[str, Any]) -> None:
    assert sanitize_observability_attributes(vector["input"]) == vector["expected"]


class _Output(BaseModel):
    raw: str
    payload: str


@dataclass
class _Step:
    signature: str
    note: str


class _Opaque:
    def __repr__(self) -> str:
        return "secret 4111 1111 1111 1111"


def test_models_dataclasses_and_opaque_objects_are_walked_or_hidden() -> None:
    result = sanitize_observability_attributes({
        "model": _Output(raw="r", payload="p"),
        "step": _Step(signature="s", note="n"),
        "opaque": _Opaque(),
        "data": b"\x00\x01",
        "set": {1},
    })
    assert result == {
        "model": {"raw": "r", "payload": {"redacted": True, "length": 1}},
        "step": {"signature": {"redacted": True, "length": 1}, "note": "n"},
        "opaque": "<_Opaque>",
        "data": {"redacted": True, "length": 2},
        "set": [1],
    }
    json.dumps(result)


def test_cycles_and_depth_are_bounded() -> None:
    loop: dict[str, Any] = {}
    loop["self"] = loop
    assert sanitize_observability_attributes(loop) == {"self": "<cycle>"}
    deep: dict[str, Any] = {}
    node = deep
    for _ in range(40):
        node["next"] = {}
        node = node["next"]
    assert "<max depth>" in json.dumps(sanitize_observability_attributes(deep))


def test_helpers() -> None:
    assert is_sensitive_field_name("agentPrivateKey") and is_sensitive_field_name("API_KEY")
    assert not is_sensitive_field_name("did")
    assert sanitize_url("not a url") == "<invalid url>"
    assert sanitize_url("https://[::1]:8443/x?y#z") == "https://[::1]:8443/x"
    expected = {"Cookie": {"redacted": True, "length": 1}, "Accept": "a"}
    assert sanitize_headers({"Cookie": "c", "Accept": "a"}) == expected
    assert is_redacted_marker({"redacted": True, "length": 1})
    assert not is_redacted_marker({"redacted": True, "length": 1, "x": 1})
