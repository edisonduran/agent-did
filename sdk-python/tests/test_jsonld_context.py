"""M-19: every term an Agent-DID document uses is defined by the published JSON-LD context.

The authoritative check (full JSON-LD expansion in safe mode) is ``npm run check:jsonld-context``.
This test keeps the Python SDK honest on its own: documents it builds may only use terms that
``contexts/v1.jsonld`` or the W3C DID v1 context define, and the context file is the pinned one.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

REPO = Path(__file__).resolve().parents[2]
CONTEXT_PATH = REPO / "contexts" / "v1.jsonld"
DID_V1_TERMS = {
    "id", "type", "alsoKnownAs", "assertionMethod", "authentication", "capabilityDelegation",
    "capabilityInvocation", "controller", "keyAgreement", "service", "serviceEndpoint",
    "verificationMethod",
}


def _defined_terms(context: dict[str, Any]) -> set[str]:
    return {key for key in context if not key.startswith("@")}


def test_context_matches_pinned_hash() -> None:
    pinned = (REPO / "contexts" / "v1.jsonld.sha256").read_text(encoding="utf-8").split()[0]
    assert hashlib.sha256(CONTEXT_PATH.read_bytes()).hexdigest() == pinned


def test_sdk_documents_only_use_defined_terms() -> None:
    from agent_did_sdk.webvh.documents import build_agent_document_template

    context = json.loads(CONTEXT_PATH.read_text(encoding="utf-8"))["@context"]
    top = _defined_terms(context) | DID_V1_TERMS
    nested = _defined_terms(context["agentMetadata"]["@context"])
    nested_cc = _defined_terms(context["complianceCertifications"]["@context"]) | {"type"}

    document = build_agent_document_template(
        controller_did="did:webvh:QmControllerScid:controller.example.com",
        timestamp="2026-02-22T14:00:00Z",
        agent_metadata={
            "name": "a", "version": "1.0.0", "coreModelHash": "x", "systemPromptHash": "y",
            "capabilities": [], "memberOf": "did:example:fleet",
        },
        public_key_bytes=bytes(32),
    )
    assert set(document) - {"@context"} <= top
    assert set(document["agentMetadata"]) <= nested
    for method in document["verificationMethod"]:
        assert set(method) <= top | {"type", "publicKeyMultibase"}
        assert method["type"] in top
    assert nested_cc >= {"issuer", "credentialSubject", "proofHash"}
