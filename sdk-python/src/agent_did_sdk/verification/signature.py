"""Signature verification against an already resolved, active DID document.

Resolution, revocation and controller-chain checks stay in ``AgentDidClient``.
TypeScript parity: ``sdk/src/verification/signature.ts``.
"""

from __future__ import annotations

from nacl.signing import VerifyKey

from ..core.identity_composition import assert_key_purpose, assert_signing_purpose, get_relationship_key_ids
from ..core.types import AgentDIDDocument, VerificationRelationship
from ..crypto.multibase import decode_public_key_multibase


def verify_with_active_keys(
    doc: AgentDIDDocument,
    payload: str,
    signature: str,
    key_id: str | None,
    required_purpose: VerificationRelationship,
) -> bool:
    """Verify against active keys listed under *required_purpose* (and *key_id*, when given)."""
    assert_signing_purpose(required_purpose, doc, key_id or "")
    if key_id is not None:
        assert_key_purpose(key_id, doc, required_purpose)

    message_bytes = payload.encode("utf-8")
    sig_bytes = bytes.fromhex(signature)

    active_ids = set(get_relationship_key_ids(doc, required_purpose))
    candidates = [
        m
        for m in doc.verification_method
        if m.public_key_multibase
        and not m.deactivated
        and (m.id == key_id and m.id in active_ids if key_id else m.id in active_ids)
    ]

    for vm in candidates:
        pk_raw = vm.public_key_multibase
        if not pk_raw:
            continue
        try:
            VerifyKey(decode_public_key_multibase(pk_raw)).verify(message_bytes, sig_bytes)
            return True
        except Exception:
            continue
    return False


def verify_with_historical_key(
    doc: AgentDIDDocument,
    payload: str,
    signature: str,
    key_id: str,
    required_purpose: VerificationRelationship,
) -> bool:
    """Verify against *key_id* even if it was rotated out (audit-trail verification)."""
    assert_signing_purpose(required_purpose, doc, key_id)
    assert_key_purpose(key_id, doc, required_purpose)

    message_bytes = payload.encode("utf-8")
    sig_bytes = bytes.fromhex(signature)

    candidate = next((m for m in doc.verification_method if m.id == key_id and m.public_key_multibase), None)
    if candidate is None or not candidate.public_key_multibase:
        return False

    try:
        VerifyKey(decode_public_key_multibase(candidate.public_key_multibase)).verify(message_bytes, sig_bytes)
        return True
    except Exception:
        return False
