"""Core Agent-DID SDK helpers."""

from .identity_composition import (
    DID_VERIFICATION_RELATIONSHIPS,
    SIGNING_VERIFICATION_PURPOSES,
    IdentityCompositionError,
    assert_key_purpose,
    assert_signing_purpose,
    get_key_relationships,
    get_relationship_key_ids,
)

__all__ = [
    "IdentityCompositionError",
    "DID_VERIFICATION_RELATIONSHIPS",
    "SIGNING_VERIFICATION_PURPOSES",
    "assert_key_purpose",
    "assert_signing_purpose",
    "get_key_relationships",
    "get_relationship_key_ids",
]
