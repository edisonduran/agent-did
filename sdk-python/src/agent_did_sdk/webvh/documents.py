"""Pure helpers that build the documents and history derived from did:webvh logs.

No state and no I/O: ``AgentDidClient`` owns the stores and calls these.
TypeScript parity: ``sdk/src/webvh/documents.ts``.
"""

from __future__ import annotations

import json
import re
from typing import Any

from ..core.types import AgentDIDDocument, AgentDocumentHistoryAction, AgentDocumentHistoryEntry
from ..crypto.hash import generate_agent_metadata_hash, generate_canonical_document_hash
from ..crypto.multibase import encode_public_key_multibase
from .adapter import DID_WEBVH_PLACEHOLDER

_AGENT_DID_CONTEXT = ["https://www.w3.org/ns/did/v1", "https://agent-did.org/v1"]


def compute_document_reference(document: AgentDIDDocument) -> str:
    return generate_canonical_document_hash(document.model_dump_jsonld())


def normalize_did_path_segment(value: str) -> str:
    normalized = re.sub(r"[^a-z0-9]+", "-", value.strip().lower()).strip("-")
    return normalized or "agent"


def build_agent_document_template(
    *,
    controller_did: str,
    timestamp: str,
    agent_metadata: dict[str, Any],
    public_key_bytes: bytes,
) -> dict[str, Any]:
    """Genesis document of an agent, with the did:webvh placeholder in place of the DID."""
    verification_method_id = f"{DID_WEBVH_PLACEHOLDER}#key-1"
    return {
        "@context": list(_AGENT_DID_CONTEXT),
        "id": DID_WEBVH_PLACEHOLDER,
        "controller": controller_did,
        "created": timestamp,
        "updated": timestamp,
        "agentMetadata": {k: v for k, v in agent_metadata.items() if v is not None},
        "verificationMethod": [
            {
                "id": verification_method_id,
                "type": "Ed25519VerificationKey2020",
                "controller": controller_did,
                "publicKeyMultibase": encode_public_key_multibase(public_key_bytes),
            }
        ],
        "authentication": [verification_method_id],
        "assertionMethod": [verification_method_id],
    }


def build_bootstrap_controller_template(
    *, creator_key_did: str, timestamp: str, public_key_bytes: bytes
) -> dict[str, Any]:
    """Genesis document of a self-controlled local bootstrap controller."""
    key_id = creator_key_did.removeprefix("did:key:")
    verification_method_id = f"{DID_WEBVH_PLACEHOLDER}#key-1"
    return {
        "@context": list(_AGENT_DID_CONTEXT),
        "id": DID_WEBVH_PLACEHOLDER,
        "controller": DID_WEBVH_PLACEHOLDER,
        "created": timestamp,
        "updated": timestamp,
        "agentMetadata": {
            "name": f"controller-{normalize_did_path_segment(key_id)}",
            "description": "Local bootstrap controller root for canonical did:webvh flows.",
            "version": "1.0.0",
            "coreModelHash": generate_agent_metadata_hash(f"controller:{creator_key_did}"),
            "systemPromptHash": generate_agent_metadata_hash("controller-bootstrap-root"),
        },
        "verificationMethod": [
            {
                "id": verification_method_id,
                "type": "Ed25519VerificationKey2020",
                "controller": DID_WEBVH_PLACEHOLDER,
                "publicKeyMultibase": encode_public_key_multibase(public_key_bytes),
            }
        ],
        "authentication": [verification_method_id],
        "assertionMethod": [verification_method_id],
    }


def history_from_did_webvh_log(log: str) -> list[AgentDocumentHistoryEntry]:
    """History entries for a verified did:webvh log, one per log entry."""
    entries: list[AgentDocumentHistoryEntry] = []
    previous: AgentDIDDocument | None = None
    for index, line in enumerate((line for line in log.splitlines() if line.strip()), start=1):
        entry = json.loads(line)
        document = AgentDIDDocument.model_validate(entry["state"])
        action: AgentDocumentHistoryAction = "updated"
        if index == 1 or previous is None:
            action = "created"
        elif (entry.get("parameters") or {}).get("deactivated") is True:
            action = "revoked"
        elif len(document.verification_method) != len(previous.verification_method):
            action = "rotated-key"
        entries.append(
            AgentDocumentHistoryEntry(
                did=document.id,
                revision=index,
                action=action,
                timestamp=entry["versionTime"],
                version=document.agent_metadata.version,
                documentRef=compute_document_reference(document),
            )
        )
        previous = document
    return entries
