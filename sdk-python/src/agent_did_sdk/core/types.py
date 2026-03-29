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
    capabilities: list[str] | None = None
    member_of: str | None = None
    signer: Any | None = None  # AgentSigner — optional external signer for production mode


class CreateAgentResult(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    document: AgentDIDDocument
    agent_private_key: str = Field(alias="agentPrivateKey")


class UpdateAgentDocumentParams(BaseModel):
    description: str | None = None
    version: str | None = None
    core_model: str | None = None
    system_prompt: str | None = None
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
    headers: dict[str, str]
    max_created_skew_seconds: int | None = None


# ---------------------------------------------------------------------------
# Document history
# ---------------------------------------------------------------------------

AgentDocumentHistoryAction = Literal["created", "updated", "rotated-key", "revoked"]


class AgentDocumentHistoryEntry(BaseModel):
    did: str
    revision: int
    action: AgentDocumentHistoryAction
    timestamp: str
    version: str | None = None
    document_ref: str | None = Field(default=None, alias="documentRef")
