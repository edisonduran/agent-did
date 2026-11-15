"""Verification method types for Ed25519 keys (ADR-006 D-8b).

Documents are written with ``Multikey``; documents and did:webvh logs written before rc.5 use
``Ed25519VerificationKey2020`` with the same ``publicKeyMultibase`` encoding and stay valid. A
method of any other type is never used to verify a signature.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from typing import Any

VERIFICATION_METHOD_TYPE = "Multikey"

_ED25519_VERIFICATION_METHOD_TYPES = frozenset({"Multikey", "Ed25519VerificationKey2020"})


def is_ed25519_verification_method_type(value: object) -> bool:
    """Whether ``value`` names an Ed25519 verification method this SDK reads."""
    return isinstance(value, str) and value in _ED25519_VERIFICATION_METHOD_TYPES


REVOKED_CONTEXT_TERM: dict[str, Any] = {
    "revoked": {
        "@id": "https://w3id.org/security#revoked",
        "@type": "http://www.w3.org/2001/XMLSchema#dateTime",
    }
}
"""Inline JSON-LD context term a document adds after its context URLs when one of its keys carries ``revoked``: the
published ``https://agent-did.org/v1`` context is immutable and does not define it. Treat it as read-only."""


def is_revoked_context_term(entry: object) -> bool:
    """Whether *entry* is the inline ``revoked`` context term, member for member."""
    if not isinstance(entry, dict) or list(entry) != ["revoked"]:
        return False
    term = entry["revoked"]
    expected = REVOKED_CONTEXT_TERM["revoked"]
    return (
        isinstance(term, dict)
        and len(term) == 2
        and term.get("@id") == expected["@id"]
        and term.get("@type") == expected["@type"]
    )


def context_for_methods(context: Sequence[object], revoked_flags: Iterable[bool]) -> list[Any]:
    """*context* with the inline ``revoked`` term last when a key is revoked (*revoked_flags*, one per verification
    method), and without it otherwise. The context URLs keep their order."""
    urls: list[Any] = [entry for entry in context if not is_revoked_context_term(entry)]
    if any(revoked_flags):
        return [*urls, {"revoked": dict(REVOKED_CONTEXT_TERM["revoked"])}]
    return urls
