"""Verification method types for Ed25519 keys (ADR-006 D-8b).

Documents are written with ``Multikey``; documents and did:webvh logs written before rc.5 use
``Ed25519VerificationKey2020`` with the same ``publicKeyMultibase`` encoding and stay valid. A
method of any other type is never used to verify a signature.
"""

from __future__ import annotations

VERIFICATION_METHOD_TYPE = "Multikey"

_ED25519_VERIFICATION_METHOD_TYPES = frozenset({"Multikey", "Ed25519VerificationKey2020"})


def is_ed25519_verification_method_type(value: object) -> bool:
    """Whether ``value`` names an Ed25519 verification method this SDK reads."""
    return isinstance(value, str) and value in _ED25519_VERIFICATION_METHOD_TYPES
