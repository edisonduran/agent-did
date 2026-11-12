"""Ed25519 verification rule of RFC-001 §7 (parity: sdk/tests/Ed25519VerificationVectors.test.ts)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from agent_did_sdk.crypto.ed25519 import verify_ed25519

_FIXTURE = Path(__file__).resolve().parents[2] / "fixtures" / "ed25519-verification-vectors.json"
VECTORS: list[dict[str, Any]] = json.loads(_FIXTURE.read_text(encoding="utf-8"))["vectors"]


def test_loads_the_shared_vectors() -> None:
    assert len(VECTORS) >= 16
    assert any(v["valid"] for v in VECTORS)
    assert any(not v["valid"] for v in VECTORS)


@pytest.mark.parametrize("vector", VECTORS, ids=[v["name"] for v in VECTORS])
def test_vector(vector: dict[str, Any]) -> None:
    verified = verify_ed25519(
        bytes.fromhex(vector["signature"]), bytes.fromhex(vector["message"]), bytes.fromhex(vector["publicKey"])
    )
    assert verified is vector["valid"]
