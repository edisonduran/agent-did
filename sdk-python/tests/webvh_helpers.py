"""Helpers that build real did:webvh v1.0 logs holding Agent-DID documents (parity: sdk/tests/helpers)."""

from __future__ import annotations

import json
from collections.abc import Callable
from typing import Any

from agent_did_sdk.core.signer import LocalKeySigner
from agent_did_sdk.webvh.adapter import DID_WEBVH_PLACEHOLDER, DidWebvhLogResult, create_did_webvh_log

TEST_CONTROLLER_KEY = "5a" * 32


def agent_document_template(name: str = "WebvhResolverBot") -> dict[str, Any]:
    return {
        "@context": ["https://www.w3.org/ns/did/v1", "https://agent-did.org/v1"],
        "id": DID_WEBVH_PLACEHOLDER,
        "controller": "did:webvh:QmControllerScid:example.com:organizations:acme-support",
        "created": "2026-01-01T00:00:00Z",
        "updated": "2026-01-01T00:00:00Z",
        "agentMetadata": {
            "name": name,
            "version": "1.0.0",
            "coreModelHash": "hash://hmac-sha256/model",
            "systemPromptHash": "hash://hmac-sha256/prompt",
        },
        "verificationMethod": [
            {
                "id": f"{DID_WEBVH_PLACEHOLDER}#key-1",
                "type": "Ed25519VerificationKey2020",
                "controller": DID_WEBVH_PLACEHOLDER,
                "publicKeyMultibase": "z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
            }
        ],
        "authentication": [f"{DID_WEBVH_PLACEHOLDER}#key-1"],
        "assertionMethod": [f"{DID_WEBVH_PLACEHOLDER}#key-1"],
    }


async def create_agent_webvh_log(domain: str, path_segments: list[str] | None = None) -> DidWebvhLogResult:
    """A controller-signed did:webvh v1.0 log holding an Agent-DID document."""
    return await create_did_webvh_log(
        domain=domain,
        path_segments=path_segments or [],
        document=agent_document_template(),
        signer=LocalKeySigner(TEST_CONTROLLER_KEY),
        created="2026-01-01T00:00:00Z",
    )


def tamper_last_state(log: str, mutate: Callable[[dict[str, Any]], None]) -> str:
    """Rewrite the ``state`` of the last entry without re-signing it."""
    lines = log.rstrip("\n").split("\n")
    entry = json.loads(lines[-1])
    mutate(entry["state"])
    lines[-1] = json.dumps(entry, separators=(",", ":"))
    return "\n".join(lines) + "\n"
