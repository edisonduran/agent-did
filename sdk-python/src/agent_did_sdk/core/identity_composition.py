"""Identity-composition helpers for DID verification relationships."""

from __future__ import annotations

from collections.abc import Sequence

from .types import (
    AgentDIDDocument,
    IdentityCompositionErrorReason,
    SigningVerificationPurpose,
    VerificationRelationship,
)

DID_VERIFICATION_RELATIONSHIPS: tuple[VerificationRelationship, ...] = (
    "authentication",
    "assertionMethod",
    "capabilityDelegation",
    "capabilityInvocation",
    "keyAgreement",
)

SIGNING_VERIFICATION_PURPOSES: tuple[SigningVerificationPurpose, ...] = (
    "authentication",
    "assertionMethod",
    "capabilityDelegation",
    "capabilityInvocation",
)


class IdentityCompositionError(ValueError):
    """Raised when a key is not authorized for the requested DID relationship."""

    def __init__(
        self,
        reason: IdentityCompositionErrorReason,
        *,
        key_id: str,
        required_purpose: VerificationRelationship,
        found_in: Sequence[VerificationRelationship],
        did: str | None = None,
    ) -> None:
        self.reason = reason
        self.did = did
        self.key_id = key_id
        self.required_purpose = required_purpose
        self.found_in = list(found_in)
        super().__init__(
            f"Verification method {key_id or '<unspecified>'} is not authorized for {required_purpose}"
        )


def get_relationship_key_ids(
    did_doc: AgentDIDDocument,
    relationship: VerificationRelationship,
) -> list[str]:
    if relationship == "authentication":
        return did_doc.authentication or []
    if relationship == "assertionMethod":
        return did_doc.assertion_method or []
    if relationship == "capabilityDelegation":
        return did_doc.capability_delegation or []
    if relationship == "capabilityInvocation":
        return did_doc.capability_invocation or []
    return did_doc.key_agreement or []


def get_key_relationships(key_id: str, did_doc: AgentDIDDocument) -> list[VerificationRelationship]:
    return [
        relationship
        for relationship in DID_VERIFICATION_RELATIONSHIPS
        if key_id in get_relationship_key_ids(did_doc, relationship)
    ]


def assert_key_purpose(
    key_id: str,
    did_doc: AgentDIDDocument,
    required_purpose: VerificationRelationship,
) -> None:
    found_in = get_key_relationships(key_id, did_doc)
    key_ids_for_purpose = get_relationship_key_ids(did_doc, required_purpose)

    # Membership-only predicate per RFC-001 §6.2.1; signing-purpose policy lives in assert_signing_purpose.
    if key_id not in key_ids_for_purpose:
        raise IdentityCompositionError(
            "key_purpose_violation",
            did=did_doc.id,
            key_id=key_id,
            required_purpose=required_purpose,
            found_in=found_in,
        )


def assert_signing_purpose(
    required_purpose: VerificationRelationship,
    did_doc: AgentDIDDocument,
    key_id: str = "",
) -> None:
    if required_purpose == "keyAgreement":
        raise IdentityCompositionError(
            "key_purpose_violation",
            did=did_doc.id,
            key_id=key_id,
            required_purpose=required_purpose,
            found_in=get_key_relationships(key_id, did_doc) if key_id else [],
        )
