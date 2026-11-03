"""Pydantic models for the Agent-DID Specification (RFC-001)."""

from __future__ import annotations

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
    nonce_store: Any | None = None
    """Replay store (``NonceStore``). Defaults to a process-wide ``InMemoryNonceStore``."""


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
