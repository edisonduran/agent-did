"""Signature verification against an already resolved, active DID document.

Resolution, revocation and controller-chain checks stay in ``AgentDidClient``.
TypeScript parity: ``sdk/src/verification/signature.ts``.
"""

from __future__ import annotations

from ..core.identity_composition import assert_key_purpose, assert_signing_purpose, get_relationship_key_ids
from ..core.types import AgentDIDDocument, VerificationRelationship
from ..crypto.ed25519 import verify_ed25519
from ..crypto.multibase import decode_public_key_multibase


def verify_with_active_keys(
    doc: AgentDIDDocument,
    payload: str | bytes,
    signature: str,
    key_id: str | None,
    required_purpose: VerificationRelationship,
) -> bool:
    """Verify against active keys listed under *required_purpose* (and *key_id*, when given).

    Returns ``False`` for a signature that is not valid hex, an empty *key_id* and a *key_id* of a retired key
    (one with a ``deactivated`` time: a rotated-out key is no longer listed in any relationship). Ed25519 edge
    cases follow the single rule of :func:`verify_ed25519`.
    """
    assert_signing_purpose(required_purpose, doc, key_id or "")
    if key_id is not None:
        if key_id == "" or any(m.id == key_id and m.deactivated for m in doc.verification_method):
            return False
        assert_key_purpose(key_id, doc, required_purpose)

    message_bytes = payload.encode("utf-8") if isinstance(payload, str) else payload
    try:
        sig_bytes = bytes.fromhex(signature)
    except ValueError:
        return False

    active_ids = set(get_relationship_key_ids(doc, required_purpose))
    candidates = [
        m
        for m in doc.verification_method
        if m.public_key_multibase
        and not m.deactivated
        and (m.id == key_id and m.id in active_ids if key_id is not None else m.id in active_ids)
    ]

    for vm in candidates:
        pk_raw = vm.public_key_multibase
        if not pk_raw:
            continue
        try:
            if verify_ed25519(sig_bytes, message_bytes, decode_public_key_multibase(pk_raw)):
                return True
        except Exception:
            continue
    return False

