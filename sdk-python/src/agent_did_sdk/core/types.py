"""Pydantic models for the Agent-DID Specification (RFC-001)."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

# ---------------------------------------------------------------------------
# Agent metadata
# ---------------------------------------------------------------------------

class AgentMetadata(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    name: str
    description: str | None = None
    version: str
    core_model_hash: str = Field(alias="coreModelHash")
    system_prompt_hash: str = Field(alias="systemPromptHash")
    capabilities: list[str] | None = None
    member_of: str | None = Field(default=None, alias="memberOf")


class VerifiableCredentialLink(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    type: str
    issuer: str
    credential_subject: str = Field(alias="credentialSubject")
    proof_hash: str = Field(alias="proofHash")


class VerificationMethod(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    id: str
    type: str
    controller: str
    public_key_multibase: str | None = Field(default=None, alias="publicKeyMultibase")
    blockchain_account_id: str | None = Field(default=None, alias="blockchainAccountId")
    deactivated: str | None = None


class CreateDidWebvhOptions(BaseModel):
    """Explicit did:webvh profile.

    ``controller_signer`` is the controller's key: the did:webvh log's only ``updateKeys``
    entry, which signs every log entry (create, update, rotate, revoke). Use a KMS/HSM-backed
    ``AgentSigner`` in production. ``controller_did="{DID}"`` makes the DID self-controlled.
    did:webvh v1.0 derives the SCID from the genesis entry, so it cannot be chosen.
    """

    model_config = ConfigDict(arbitrary_types_allowed=True, extra="forbid")

    domain: str
    controller_did: str
    controller_signer: Any  # AgentSigner (controller key, did:webvh updateKeys)
    path_segments: list[str] | None = None
    next_update_keys: list[str] | None = None
    """Pre-rotation: public keys (Ed25519 multikeys) that will sign the DID's NEXT log entry. Only their hashes
    go into the log (``nextKeyHashes``). From then on the key in ``controller_signer`` can no longer sign log
    entries: a compromised controller key cannot rotate or deactivate the DID, and the holder of one of these
    keys can. Keep their private keys offline. Rotate with ``AgentDidClient.rotate_controller_key``."""


@dataclass(frozen=True)
class DidWebvhControllerKeys:
    """The controller keys of a did:webvh DID, from its verified log."""

    update_keys: list[str]
    """Keys that may sign the next entry (when ``next_key_hashes`` is empty) or that signed the last one."""
    next_key_hashes: list[str]
    """Pre-rotation commitments in force. While non-empty, only a key with one of these hashes can sign."""


# ---------------------------------------------------------------------------
# DID Document (top-level JSON-LD)
# ---------------------------------------------------------------------------

class AgentDIDDocument(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    context: list[str] = Field(alias="@context")
    id: str
    controller: str
    created: str
    updated: str
    agent_metadata: AgentMetadata = Field(alias="agentMetadata")
    compliance_certifications: list[VerifiableCredentialLink] | None = Field(
        default=None, alias="complianceCertifications"
    )
    verification_method: list[VerificationMethod] = Field(alias="verificationMethod")
    authentication: list[str]
    assertion_method: list[str] | None = Field(default=None, alias="assertionMethod")
    capability_delegation: list[str] | None = Field(default=None, alias="capabilityDelegation")
    capability_invocation: list[str] | None = Field(default=None, alias="capabilityInvocation")
    key_agreement: list[str] | None = Field(default=None, alias="keyAgreement")

    def model_dump_jsonld(self) -> dict[str, object]:
        """Serialize using JSON-LD aliases, dropping ``None`` values."""
        return self.model_dump(by_alias=True, exclude_none=True)


# ---------------------------------------------------------------------------
# Params / Results
# ---------------------------------------------------------------------------

class CreateAgentParams(BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=True)

    name: str
    description: str | None = None
    version: str | None = None
    core_model: str
    system_prompt: str
    core_model_salt: str | None = None
    """32-byte hex salt for the ``coreModelHash`` commitment. Generated randomly when omitted."""
    system_prompt_salt: str | None = None
    """32-byte hex salt for the ``systemPromptHash`` commitment. Generated randomly when omitted."""
    capabilities: list[str] | None = None
    member_of: str | None = None
    signer: Any | None = None  # AgentSigner — optional external signer for production mode
    did_method: Literal["agent", "webvh"] = "webvh"
    webvh: CreateDidWebvhOptions | None = None


class MetadataCommitmentSalts(BaseModel):
    """Salts (32-byte hex) of an agent's metadata commitments."""

    model_config = ConfigDict(populate_by_name=True)

    core_model: str = Field(alias="coreModel")
    system_prompt: str = Field(alias="systemPrompt")


class CreateAgentResult(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    document: AgentDIDDocument
    agent_private_key: str = Field(alias="agentPrivateKey")
    controller_private_key: str | None = Field(default=None, alias="controllerPrivateKey")
    """Ed25519 private key (hex) of the local bootstrap controller.

    Present only when this call created the bootstrap controller document (implicit ``did:webvh``
    profile, controller not yet registered). Randomly generated and returned only once.
    """
    metadata_commitment_salts: MetadataCommitmentSalts | None = Field(default=None, alias="metadataCommitmentSalts")
    """Salts of the ``coreModelHash`` and ``systemPromptHash`` commitments (``hash://hmac-sha256/``).

    Always set by ``AgentIdentity.create()``; ``None`` only when a result is built by hand.

    Keep them private; reveal a salt together with its value only to a party that should be able to
    verify it (see ``verify_metadata_commitment``). They are not stored anywhere else.
    """


class UpdateAgentDocumentParams(BaseModel):
    description: str | None = None
    version: str | None = None
    core_model: str | None = None
    core_model_salt: str | None = None
    """Required when ``core_model`` is set: 32-byte hex salt for the new commitment."""
    system_prompt: str | None = None
    system_prompt_salt: str | None = None
    """Required when ``system_prompt`` is set: 32-byte hex salt for the new commitment."""
    capabilities: list[str] | None = None
    member_of: str | None = None
    compliance_certifications: list[VerifiableCredentialLink] | None = None


class RotateVerificationMethodResult(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    document: AgentDIDDocument
    verification_method_id: str = Field(alias="verificationMethodId")
    agent_private_key: str = Field(alias="agentPrivateKey")


# ---------------------------------------------------------------------------
# HTTP Signature types
# ---------------------------------------------------------------------------

class SignHttpRequestParams(BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=True)

    method: str
    url: str
    body: str | None = None
    agent_private_key: str | None = None
    signer: Any | None = None  # AgentSigner — preferred over agent_private_key
    agent_did: str
    verification_method_id: str | None = None
    expires_in_seconds: int | None = None
    http_security: Any | None = None  # HttpTargetValidationOptions


class VerifyHttpRequestSignatureParams(BaseModel):
    method: str
    url: str
    body: str | None = None
    model_config = ConfigDict(arbitrary_types_allowed=True)

    headers: dict[str, str]
    max_created_skew_seconds: int | None = None
    """Maximum distance between ``created`` and now, in seconds (default: 300)."""
    max_signature_lifetime_seconds: int | None = None
    """Maximum lifetime of a signature (``expires - created``), in seconds (default: 300)."""
    nonce_store: Any | None = None
    """Replay store (``NonceStore``). Defaults to a process-wide ``InMemoryNonceStore``."""


HttpSignatureRejection = Literal[
    "missing_headers",
    "malformed_headers",
    "digest_mismatch",
    "tag_mismatch",
    "alg_unsupported",
    "params_missing",
    "keyid_not_bound",
    "components_missing",
    "components_order",
    "created_skew",
    "expires_before_created",
    "lifetime_exceeded",
    "expired",
    "signed_component_missing",
    "did_resolution_failed",
    "keyid_not_authorized",
    "signature_invalid",
    "nonce_replayed",
]
"""Why ``verify_http_request_signature_detailed`` rejected a request. When the request carries several
signatures, the reason is the one of the first signature that has ``tag="agent-did"`` (else the first).

* ``missing_headers``: ``Signature``, ``Signature-Input`` or ``Signature-Agent`` is absent.
* ``malformed_headers``: ``Signature`` / ``Signature-Input`` do not parse, or no signature has a matching label.
* ``digest_mismatch``: ``Content-Digest`` is absent or is not exactly the SHA-256 of the body.
* ``tag_mismatch``: the ``tag`` parameter is not ``agent-did`` (for example another profile's signature).
* ``alg_unsupported``: the ``alg`` parameter is not ``ed25519``.
* ``params_missing``: ``created``, ``expires``, ``nonce`` or ``keyid`` is absent or has the wrong type.
* ``keyid_not_bound``: ``keyid`` is not a key of the ``Signature-Agent`` DID.
* ``components_missing``: a required covered component is absent.
* ``components_order``: the required components are all covered but not first and in order.
* ``created_skew``: ``created`` is further from now than ``max_created_skew_seconds``.
* ``expires_before_created``: ``expires`` is earlier than ``created``.
* ``lifetime_exceeded``: ``expires - created`` is greater than ``max_signature_lifetime_seconds``.
* ``expired``: now is after ``expires``.
* ``signed_component_missing``: a covered component has no value in the request (for example no ``Date``).
* ``did_resolution_failed``: the ``Signature-Agent`` DID has no active verification chain: unknown, revoked,
  deactivated, inactive controller, or the resolver failed. The SDK does not tell a resolver outage from a
  revocation; treat this reason as "could not establish the key".
* ``keyid_not_authorized``: ``keyid`` is not an ``assertionMethod`` key of the DID document.
* ``signature_invalid``: the signature does not verify, or the key is no longer active.
* ``nonce_replayed``: the ``(keyid, nonce)`` pair was already seen.
"""


@dataclass(frozen=True)
class VerifyHttpRequestSignatureResult:
    """Result of ``verify_http_request_signature_detailed``. Always test ``result.ok``: the object itself
    is truthy for a rejection too, which is why ``verify_http_request_signature`` keeps returning a bool."""

    ok: bool
    reason: HttpSignatureRejection | None = None


# ---------------------------------------------------------------------------
# Document history
# ---------------------------------------------------------------------------

AgentDocumentHistoryAction = Literal["created", "updated", "rotated-key", "revoked"]
VerificationRelationship = Literal[
    "authentication",
    "assertionMethod",
    "capabilityDelegation",
    "capabilityInvocation",
    "keyAgreement",
]
SigningVerificationPurpose = Literal[
    "authentication",
    "assertionMethod",
    "capabilityDelegation",
    "capabilityInvocation",
]
# Kinds of signed artifact whose required verification relationship RFC-001 §6.2.1.3 fixes:
# "assertion" (signed payloads, receipts, attestations and other claims), "http_request" (HTTP message
# signatures), "delegation" (issuing a delegation of authority), "invocation" (exercising a delegated
# capability) and "authentication" (proving control of the DID, e.g. in a challenge).
SignedArtifactKind = Literal["assertion", "http_request", "delegation", "invocation", "authentication"]
IdentityCompositionErrorReason = Literal[
    "key_purpose_violation",
    "rotation_window_closed",
    "emergency_revoked",
    "tampered",
]


class AgentDocumentHistoryEntry(BaseModel):
    did: str
    revision: int
    action: AgentDocumentHistoryAction
    timestamp: str
    version: str | None = None
    document_ref: str | None = Field(default=None, alias="documentRef")
