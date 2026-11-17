"""Edge cases of the signature checks that the protocol tests do not reach (C-QA-2).

TypeScript parity: sdk/tests/HttpSignatureEdgeCases.test.ts ("signature checks with a malformed key or signature").
"""

from __future__ import annotations

from agent_did_sdk.core.types import AgentDIDDocument, KeyAtTimeResult
from agent_did_sdk.verification.key_at_time import signature_result_for_key
from agent_did_sdk.verification.signature import verify_with_active_keys

_KEY_ID = "did:example:a#key-1"


def test_a_key_that_does_not_decode_does_not_verify() -> None:
    document = AgentDIDDocument.model_validate(
        {
            "@context": ["https://www.w3.org/ns/did/v1", "https://agent-did.org/v1"],
            "id": "did:example:a",
            "controller": "did:example:a",
            "created": "2026-01-01T00:00:00Z",
            "updated": "2026-01-01T00:00:00Z",
            "agentMetadata": {"name": "Edge", "version": "1.0.0"},
            "verificationMethod": [
                {"id": _KEY_ID, "type": "Multikey", "controller": "did:example:a", "publicKeyMultibase": "z-not-base58"}
            ],
            "authentication": [_KEY_ID],
            "assertionMethod": [_KEY_ID],
        }
    )
    assert verify_with_active_keys(document, "payload", "00" * 64, _KEY_ID, "assertionMethod") is False


def test_history_unavailable_is_indeterminate_and_a_bad_signature_is_invalid() -> None:
    unavailable = KeyAtTimeResult(status="indeterminate", key_id=_KEY_ID, reason="history_unavailable")
    result = signature_result_for_key(unavailable, "payload", "00")
    assert result.status == "indeterminate"
    assert result.key is unavailable

    authorized = KeyAtTimeResult(status="authorized", key_id=_KEY_ID, public_key_multibase="z-not-base58")
    result = signature_result_for_key(authorized, "payload", "not hex")
    assert (result.status, result.reason) == ("invalid", "signature_invalid")
