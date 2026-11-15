"""The ``AgentMetadataCredential`` profile (RFC-001 §4.4, ADR-006 D-8d): form checks and the unsigned credential.

The signing and the resolution checks are in ``AgentDidClient.issue_agent_metadata_credential`` /
``verify_agent_metadata_credential``. TypeScript parity: ``sdk/src/core/agent-metadata-credential.ts``.
"""

from __future__ import annotations

import copy
import re
from dataclasses import dataclass
from typing import Any

from ..crypto.data_integrity import DATA_INTEGRITY_PROOF_TYPE, EDDSA_JCS_2022_CRYPTOSUITE, decode_eddsa_proof_value
from ..crypto.hash import canonicalize_json
from ..verification.key_at_time import parse_rfc3339_millis
from .types import AgentMetadataCredentialRejection

VC_V2_CONTEXT = "https://www.w3.org/ns/credentials/v2"
AGENT_METADATA_CREDENTIAL_TYPE = "AgentMetadataCredential"

AGENT_METADATA_CREDENTIAL_CONTEXT: tuple[Any, ...] = (
    VC_V2_CONTEXT,
    "https://agent-did.org/v1",
    {AGENT_METADATA_CREDENTIAL_TYPE: f"https://agent-did.org/vocab#{AGENT_METADATA_CREDENTIAL_TYPE}"},
)
"""The ``@context`` of every ``AgentMetadataCredential``: VC 2.0, the Agent-DID context (it defines ``agentMetadata``
and its members) and the credential type, which the published Agent-DID context v1 does not define."""

_CREDENTIAL_TYPES = ["VerifiableCredential", AGENT_METADATA_CREDENTIAL_TYPE]
_CREDENTIAL_MEMBERS = frozenset(
    {"@context", "id", "type", "issuer", "validFrom", "validUntil", "credentialSubject", "proof"}
)
_STRING_METADATA_MEMBERS = frozenset(
    {"name", "description", "version", "coreModelHash", "systemPromptHash", "memberOf"}
)
# A DID without path, query or fragment (DID Core §3.1 characters).
_DID_PATTERN = re.compile(r"did:[a-z0-9]+:[A-Za-z0-9._%:-]+")


def _is_did(value: object) -> bool:
    return isinstance(value, str) and _DID_PATTERN.fullmatch(value) is not None


def agent_metadata_problem(metadata: object) -> str | None:
    """``None`` when *metadata* is a non-empty dict of known ``agentMetadata`` members (JSON names), valid values."""
    if not isinstance(metadata, dict):
        return "agentMetadata must be an object"
    if not metadata:
        return "agentMetadata must state at least one member"
    for member, value in metadata.items():
        if member in _STRING_METADATA_MEMBERS:
            if not isinstance(value, str):
                return f"agentMetadata.{member} must be a string"
        elif member == "capabilities":
            if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
                return "agentMetadata.capabilities must be an array of strings"
        else:
            return f"agentMetadata.{member} is not an agentMetadata member"
    return None


def build_unsigned_agent_metadata_credential(
    *,
    issuer: str,
    agent_did: str,
    agent_metadata: dict[str, Any],
    valid_from: str,
    valid_until: str | None = None,
    credential_id: str | None = None,
) -> dict[str, Any]:
    """The credential without its proof, as ``issue_agent_metadata_credential`` signs it."""
    credential: dict[str, Any] = {"@context": copy.deepcopy(list(AGENT_METADATA_CREDENTIAL_CONTEXT))}
    if credential_id is not None:
        credential["id"] = credential_id
    credential["type"] = list(_CREDENTIAL_TYPES)
    credential["issuer"] = issuer
    credential["validFrom"] = valid_from
    if valid_until is not None:
        credential["validUntil"] = valid_until
    credential["credentialSubject"] = {"id": agent_did, "agentMetadata": copy.deepcopy(agent_metadata)}
    return credential


@dataclass(frozen=True)
class CheckedAgentMetadataCredential:
    """A credential that passed the form checks."""

    issuer: str
    agent_did: str
    verification_method: str
    agent_metadata: dict[str, Any]


def check_agent_metadata_credential_form(
    credential: object, now_millis: int
) -> CheckedAgentMetadataCredential | AgentMetadataCredentialRejection:
    """The checks that need no resolution, in order: form, proof form, validity period at *now_millis*.

    Returns the rejection reason, or the checked credential.
    """
    if not isinstance(credential, dict):
        return "malformed_credential"
    if any(member not in _CREDENTIAL_MEMBERS for member in credential):
        return "malformed_credential"
    if canonicalize_json(credential.get("@context")) != canonicalize_json(list(AGENT_METADATA_CREDENTIAL_CONTEXT)):
        return "malformed_credential"
    if canonicalize_json(credential.get("type")) != canonicalize_json(_CREDENTIAL_TYPES):
        return "malformed_credential"
    if "id" in credential and (not isinstance(credential["id"], str) or not credential["id"]):
        return "malformed_credential"
    issuer = credential.get("issuer")
    if not _is_did(issuer):
        return "malformed_credential"
    subject = credential.get("credentialSubject")
    if not isinstance(subject, dict) or any(member not in ("id", "agentMetadata") for member in subject):
        return "malformed_credential"
    if not _is_did(subject.get("id")) or agent_metadata_problem(subject.get("agentMetadata")) is not None:
        return "malformed_credential"
    valid_from = parse_rfc3339_millis(credential.get("validFrom"))
    valid_until = parse_rfc3339_millis(credential["validUntil"]) if "validUntil" in credential else None
    if valid_from is None or ("validUntil" in credential and valid_until is None):
        return "malformed_credential"
    if valid_until is not None and valid_until < valid_from:
        return "malformed_credential"
    assert isinstance(issuer, str)

    proof = credential.get("proof")
    if not isinstance(proof, dict):
        return "unsupported_proof"
    verification_method = proof.get("verificationMethod")
    if (
        proof.get("type") != DATA_INTEGRITY_PROOF_TYPE
        or proof.get("cryptosuite") != EDDSA_JCS_2022_CRYPTOSUITE
        or proof.get("proofPurpose") != "assertionMethod"
        or not isinstance(verification_method, str)
        or not verification_method.startswith(f"{issuer}#")
        or len(verification_method) == len(issuer) + 1
        or decode_eddsa_proof_value(proof.get("proofValue")) is None
    ):
        return "unsupported_proof"
    if "created" in proof and parse_rfc3339_millis(proof["created"]) is None:
        return "unsupported_proof"
    proof_expires = parse_rfc3339_millis(proof["expires"]) if "expires" in proof else None
    if "expires" in proof and proof_expires is None:
        return "unsupported_proof"

    if now_millis < valid_from:
        return "not_yet_valid"
    if (valid_until is not None and now_millis > valid_until) or (
        proof_expires is not None and now_millis > proof_expires
    ):
        return "expired"
    return CheckedAgentMetadataCredential(
        issuer=issuer,
        agent_did=subject["id"],
        verification_method=verification_method,
        agent_metadata=copy.deepcopy(subject["agentMetadata"]),
    )
