"""Pydantic models for the Agent-DID Specification (RFC-001)."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from .verification_method import is_ed25519_verification_method_type, is_revoked_context_term

# ---------------------------------------------------------------------------
# Agent metadata
# ---------------------------------------------------------------------------

class AgentMetadata(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    name: str
    description: str | None = None
    version: str
    core_model_hash: str | None = Field(default=None, alias="coreModelHash")
    """Optional commitment to the base model (RFC-001 §4.3): an assertion by the controller."""
    system_prompt_hash: str | None = Field(default=None, alias="systemPromptHash")
    """Optional commitment to the system prompt (RFC-001 §4.3): an assertion by the controller."""
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
    revoked: str | None = None
    """ISO 8601 time of an emergency revocation (``https://w3id.org/security#revoked``). A revoked key also has
    ``deactivated`` and is never authorized, whatever time a signature states (composition contract scenario 3d)."""

    @model_validator(mode="after")
    def _revoked_is_retired(self) -> VerificationMethod:
        # A revoked key is a retired key: revoked without deactivated is malformed.
        if self.revoked is not None and self.deactivated is None:
            raise ValueError("revoked requires deactivated")
        return self

    @model_validator(mode="after")
    def _ed25519_key_type(self) -> VerificationMethod:
        # A publicKeyMultibase key is an Ed25519 key here, so its method must have one of the Ed25519 types.
        if self.public_key_multibase is not None and not is_ed25519_verification_method_type(self.type):
            raise ValueError("type must be Multikey or Ed25519VerificationKey2020 for a publicKeyMultibase key")
        return self


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
    witness: Any = None  # DidWebvhWitnessConfig
    """Witnesses (ADR-007), a ``DidWebvhWitnessConfig``: ``threshold`` of these ``did:key`` DIDs must approve the
    genesis entry and every later entry before it is published. The client obtains the approvals with
    ``AgentDidClientOptions.collect_witness_proofs``."""


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

class DidCoreVerificationMethod(BaseModel):
    """A verification method as a DID Core document (a controller) may write it: the members the SDK reads must have
    the right type, and the key type is not restricted (a method that is not Ed25519 is never used to verify)."""

    model_config = ConfigDict(populate_by_name=True, extra="allow")

    id: str
    type: str
    controller: str
    public_key_multibase: str | None = Field(default=None, alias="publicKeyMultibase")
    deactivated: str | None = None
    revoked: str | None = None


VerificationRelationshipEntry = str | DidCoreVerificationMethod
"""A relationship entry: a reference to a ``verificationMethod`` (absolute DID URL, or relative such as ``#key-1``,
read against the document ``id``) or a method embedded in the relationship."""


class DidDocument(BaseModel):
    """A DID Core document as this SDK reads a controller (RFC-001 §4.2.1): a did:webvh controller does not need the
    Agent-DID members (``agentMetadata``, ``created``, ``updated``). Only the members the SDK uses are checked; a
    document may carry others. An agent's document is an :class:`AgentDIDDocument` (the agent profile)."""

    model_config = ConfigDict(populate_by_name=True, extra="allow")

    context: Any = Field(default=None, alias="@context")
    id: str
    controller: str | list[str] | None = None
    verification_method: list[DidCoreVerificationMethod] | None = Field(default=None, alias="verificationMethod")
    authentication: list[VerificationRelationshipEntry] | None = None
    assertion_method: list[VerificationRelationshipEntry] | None = Field(default=None, alias="assertionMethod")
    capability_delegation: list[VerificationRelationshipEntry] | None = Field(
        default=None, alias="capabilityDelegation"
    )
    capability_invocation: list[VerificationRelationshipEntry] | None = Field(
        default=None, alias="capabilityInvocation"
    )
    key_agreement: list[VerificationRelationshipEntry] | None = Field(default=None, alias="keyAgreement")

    def model_dump_jsonld(self) -> dict[str, object]:
        """Serialize using JSON-LD aliases, dropping ``None`` values."""
        return self.model_dump(by_alias=True, exclude_none=True)


class AgentDIDDocument(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    context: list[str | dict[str, Any]] = Field(alias="@context")
    """Context URLs, then the inline ``revoked`` term (``REVOKED_CONTEXT_TERM``) as the last entry when a key
    carries ``revoked``, and only then."""
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

    @model_validator(mode="after")
    def _context_entries(self) -> AgentDIDDocument:
        for index, entry in enumerate(self.context):
            if not isinstance(entry, str) and (not is_revoked_context_term(entry) or index != len(self.context) - 1):
                raise ValueError(f"@context[{index}] must be a string (or the inline revoked term, last)")
        has_term = bool(self.context) and not isinstance(self.context[-1], str)
        has_revoked = any(method.revoked is not None for method in self.verification_method)
        if has_revoked and not has_term:
            raise ValueError("@context must end with the inline revoked term when a key is revoked")
        if has_term and not has_revoked:
            raise ValueError("@context has the inline revoked term but no key is revoked")
        return self

    def model_dump_jsonld(self) -> dict[str, object]:
        """Serialize using JSON-LD aliases, dropping ``None`` values."""
        return self.model_dump(by_alias=True, exclude_none=True)


AnyDidDocument = DidDocument | AgentDIDDocument
"""A resolved document: an :class:`AgentDIDDocument` for an agent, a :class:`DidDocument` for a controller that is
not one (RFC-001 §4.2.1)."""


def parse_did_document(value: object) -> AnyDidDocument:
    """*value* (a did:webvh state) as an :class:`AgentDIDDocument` when it is one, otherwise as a
    :class:`DidDocument`. Raises ``ValueError`` when it is not even a DID Core document."""
    document = DidDocument.model_validate(value)
    try:
        return AgentDIDDocument.model_validate(value)
    except ValueError:
        return document


# ---------------------------------------------------------------------------
# Params / Results
# ---------------------------------------------------------------------------

# Relationships a document created by the SDK can list the agent key under, besides ``authentication`` and
# ``assertionMethod`` (see ``CreateAgentParams.additional_verification_relationships``, RFC-001 §6.2.1.3).
AdditionalVerificationRelationship = Literal["capabilityDelegation", "capabilityInvocation"]


class CreateAgentParams(BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=True)

    name: str
    description: str | None = None
    version: str | None = None
    core_model: str | None = None
    """The raw model name, committed to as ``coreModelHash``. Optional: omitted, no coreModelHash."""
    system_prompt: str | None = None
    """The raw system prompt, committed to as ``systemPromptHash``. Optional, like ``core_model``."""
    core_model_salt: str | None = None
    """32-byte hex salt for the ``coreModelHash`` commitment. Generated when omitted; only valid with ``core_model``."""
    system_prompt_salt: str | None = None
    """32-byte hex salt for the ``systemPromptHash`` commitment. Only valid with ``system_prompt``."""
    capabilities: list[str] | None = None
    member_of: str | None = None
    signer: Any | None = None  # AgentSigner — optional external signer for production mode
    webvh: CreateDidWebvhOptions | None = None
    additional_verification_relationships: list[AdditionalVerificationRelationship] | None = None
    """Relationships to list the agent key under besides ``authentication`` and ``assertionMethod``.

    RFC-001 §6.2.1.3: ``capabilityDelegation`` for an agent that issues delegations of authority,
    ``capabilityInvocation`` for one that exercises capabilities delegated to it. Duplicates are ignored and
    any other value raises ``ValueError``. Omitted or empty, the document is the same as in earlier releases.
    Key rotation carries these relationships over to the new key.
    """


class MetadataCommitmentSalts(BaseModel):
    """Salts (32-byte hex) of an agent's metadata commitments."""

    model_config = ConfigDict(populate_by_name=True)

    core_model: str | None = Field(default=None, alias="coreModel")
    system_prompt: str | None = Field(default=None, alias="systemPrompt")


class CreateAgentResult(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    document: AgentDIDDocument
    agent_private_key: str = Field(alias="agentPrivateKey")
    signer: Any | None = Field(default=None, exclude=True, repr=False)
    """The external signer (``AgentSigner``) given for the agent key, when one was: the private key never left it and
    ``agent_private_key`` is empty. Integrations sign with it. It lives only in this process and is not serialized."""
    controller_private_key: str | None = Field(default=None, alias="controllerPrivateKey")
    """Ed25519 private key (hex) of the local bootstrap controller.

    Present only when this call created the bootstrap controller document (implicit ``did:webvh``
    profile, controller not yet registered). Randomly generated and returned only once.
    """
    metadata_commitment_salts: MetadataCommitmentSalts | None = Field(default=None, alias="metadataCommitmentSalts")
    """Salts of the ``coreModelHash`` and ``systemPromptHash`` commitments (``hash://hmac-sha256/``).

    Set by ``AgentIdentity.create()``; each salt is present only for the value (``core_model``,
    ``system_prompt``) that was given.

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


class AddVerificationMethodResult(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    document: AgentDIDDocument
    verification_method_id: str = Field(alias="verificationMethodId")
    agent_private_key: str = Field(alias="agentPrivateKey")
    """Empty when a ``signer`` was given."""
    signer: Any | None = Field(default=None, exclude=True, repr=False)
    """The external signer (``AgentSigner``) given for the agent key, when one was: the private key never left it and
    ``agent_private_key`` is empty. Integrations sign with it. It lives only in this process and is not serialized."""


class RotateVerificationMethodResult(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    document: AgentDIDDocument
    verification_method_id: str = Field(alias="verificationMethodId")
    agent_private_key: str = Field(alias="agentPrivateKey")
    """Empty when a ``signer`` was given."""
    signer: Any | None = Field(default=None, exclude=True, repr=False)
    """The external signer (``AgentSigner``) given for the agent key, when one was: the private key never left it and
    ``agent_private_key`` is empty. Integrations sign with it. It lives only in this process and is not serialized."""


# ---------------------------------------------------------------------------
# HTTP Signature types
# ---------------------------------------------------------------------------

class SignHttpRequestParams(BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=True)

    method: str
    url: str
    body: str | bytes | None = None
    """Request body; bytes are hashed as they are, a string as UTF-8."""
    agent_private_key: str | None = None
    signer: Any | None = None  # AgentSigner — preferred over agent_private_key
    agent_did: str
    verification_method_id: str
    """The verification method (``keyid``) that matches the signing key, e.g. ``document.authentication[0]`` or the
    ``verification_method_id`` that ``rotate_verification_method`` returned. Required: there is no default, because
    a fixed guess names the wrong key once the agent has rotated."""
    expires_in_seconds: int | None = None
    http_security: Any | None = None  # HttpTargetValidationOptions


class VerifyHttpRequestSignatureParams(BaseModel):
    method: str
    url: str
    body: str | bytes | None = None
    """Request body; bytes are hashed as they are, a string as UTF-8."""
    model_config = ConfigDict(arbitrary_types_allowed=True)

    headers: dict[str, str]
    max_created_skew_seconds: int | None = None
    """Maximum distance between ``created`` and now, in seconds (default: 300)."""
    max_signature_lifetime_seconds: int | None = None
    """Maximum lifetime of a signature (``expires - created``), in seconds (default: 300)."""
    nonce_store: Any | None = None
    """Replay store (``NonceStore``). Defaults to a process-wide ``InMemoryNonceStore``."""
    allowed_dids: list[str] | None = None
    """Accept only these agent DIDs (the ``Agent-DID`` member; exact match). Checked before any resolution, so a
    request from any other DID costs no network call. A valid signature only proves which DID signed: without
    ``allowed_dids`` or ``allowed_controllers``, any DID with a valid key passes, and authorization is the caller's
    job (read ``result.did`` / ``result.controllers``)."""
    allowed_controllers: list[str] | None = None
    """Accept only agents whose controller chain (``result.controllers``) includes one of these DIDs, for example the
    organization that operates them. Checked after the signature verifies. When both lists are set, both apply."""


HttpSignatureRejection = Literal[
    "missing_headers",
    "url_not_normalized",
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
    "controller_not_bound",
    "keyid_not_authorized",
    "signature_invalid",
    "nonce_replayed",
    "did_not_allowed",
    "controller_not_allowed",
]
"""Why ``verify_http_request_signature_detailed`` rejected a request. When the request carries several
signatures, the reason is the one of the first signature that has ``tag="agent-did"`` (else the first).

* ``missing_headers``: ``Signature``, ``Signature-Input`` or ``Agent-DID`` is absent.
* ``url_not_normalized``: the request URL is not in the normalized form of RFC-001 §6.5 item 4 (see
  ``request_url_form_problem``); the SDK refuses to sign such a URL too.
* ``malformed_headers``: ``Signature`` / ``Signature-Input`` / ``Agent-DID`` do not parse, no signature has a matching
  label, or the ``Agent-DID`` member of the signature's label is not a String without parameters.
* ``digest_mismatch``: ``Content-Digest`` is absent or is not exactly the SHA-256 of the body.
* ``tag_mismatch``: the ``tag`` parameter is not ``agent-did`` (for example another profile's signature).
* ``alg_unsupported``: the ``alg`` parameter is not ``ed25519``.
* ``params_missing``: ``created``, ``expires``, ``nonce`` or ``keyid`` is absent or has the wrong type, or ``nonce``
  is not 1 to 256 characters of ``A-Z a-z 0-9 . _ ~ + / = -`` (RFC-001 §6.5 item 3).
* ``keyid_not_bound``: ``keyid`` is not a key of the agent DID (the ``Agent-DID`` member of the signature's label).
* ``components_missing``: a required covered component is absent.
* ``components_order``: the required components are all covered but not first and in order.
* ``created_skew``: ``created`` is further from now than ``max_created_skew_seconds``.
* ``expires_before_created``: ``expires`` is earlier than ``created``.
* ``lifetime_exceeded``: ``expires - created`` is greater than ``max_signature_lifetime_seconds``.
* ``expired``: now is after ``expires``.
* ``signed_component_missing``: a covered component has no value in the request (for example no ``Date``, or no
  ``Agent-DID`` member for the signature's label).
* ``did_resolution_failed``: the agent DID has no active verification chain: unknown, revoked,
  deactivated, inactive controller, or the resolver failed. The SDK does not tell a resolver outage from a
  revocation; treat this reason as "could not establish the key".
* ``keyid_not_authorized``: ``keyid`` is not an ``assertionMethod`` key of the DID document.
* ``signature_invalid``: the signature does not verify, or the key is no longer active.
* ``nonce_replayed``: the ``(keyid, nonce)`` pair was already seen.
* ``did_not_allowed``: ``allowed_dids`` is set and the agent DID is not in it.
* ``controller_not_allowed``: ``allowed_controllers`` is set and no DID of the controller chain is in it.
"""


@dataclass(frozen=True)
class VerifyHttpRequestSignatureResult:
    """Result of ``verify_http_request_signature_detailed``. Always test ``result.ok``: the object itself
    is truthy for a rejection too, which is why ``verify_http_request_signature`` keeps returning a bool."""

    ok: bool
    reason: HttpSignatureRejection | None = None
    did: str | None = None
    """For an accepted request, the agent DID (the ``Agent-DID`` member of the signature's label): who signed. A
    valid signature does not make it authorized."""
    key_id: str | None = None
    """For an accepted request, the verification method that signed (``keyid``)."""
    controllers: list[str] = field(default_factory=list)
    """For an accepted request, the controller chain of ``did``, nearest first (empty for a DID that controls
    itself)."""


KeyAtTimeStatus = Literal["authorized", "not_authorized", "indeterminate"]
KeyAtTimeRejection = Literal[
    "invalid_stated_time",
    "did_not_yet_created",
    "did_deactivated",
    "key_not_found",
    "key_deactivated",
    "key_purpose_violation",
    "key_revoked",
]
"""Why a key was not authorized at the stated time (RFC-001 §6.2.2).

* ``invalid_stated_time``: the stated time is not an RFC 3339 date-time.
* ``did_not_yet_created``: the stated time is before the first entry of the DID log.
* ``did_deactivated``: the DID was already deactivated at the stated time.
* ``key_not_found``: the DID document at the stated time has no such key (or it has no public key).
* ``key_deactivated``: the key was already deactivated at the stated time.
* ``key_purpose_violation``: the key was not listed under the required relationship at the stated time.
* ``key_revoked``: some entry of the log marks the key ``revoked`` (emergency revocation): it is not authorized at
  any stated time, even with trusted time evidence.
"""
KeyAtTimeUncertainty = Literal[
    "key_retired_after_stated_time",
    "did_deactivated_after_stated_time",
    "history_unavailable",
]
"""Why a key check at a stated time could not be decided (RFC-001 §6.2.2).

The stated time is asserted by the signer, so it cannot place a signature on either side of a later change.

* ``key_retired_after_stated_time``: the key was authorized at the stated time, but a later log entry retires
  it (removed, deactivated or moved out of the required relationship) and no trusted time evidence places the
  signature before that entry.
* ``did_deactivated_after_stated_time``: same, for a later deactivation of the DID.
* ``history_unavailable``: no verified did:webvh log is available for the DID, so its state at the stated time
  cannot be established.
"""


@dataclass(frozen=True)
class KeyAtTimeResult:
    """Result of a key check at a stated time. Test ``result.status``; treat ``indeterminate`` as not accepted.

    ``authorized`` means the key was authorized at the stated time and either nothing later retires it
    (``basis == "no_later_change"``) or trusted time evidence places the signature before the first entry that
    does (``basis == "time_evidence"``).
    """

    status: KeyAtTimeStatus
    key_id: str
    reason: KeyAtTimeRejection | KeyAtTimeUncertainty | None = None
    public_key_multibase: str | None = None
    """The key at the stated time (``authorized``, and ``indeterminate`` when it was authorized then)."""
    version_id: str | None = None
    """``authorized``: the log version in effect at the stated time."""
    basis: Literal["no_later_change", "time_evidence"] | None = None
    found_in: tuple[VerificationRelationship, ...] = ()
    """``not_authorized``: relationships listing the key at the stated time (empty when it was not there)."""
    boundary_version_id: str | None = None
    """``indeterminate``: the first log entry that retires the key or deactivates the DID, when there is one."""
    boundary_time: str | None = None
    """``indeterminate``: when the key stopped being authorized (log ``versionTime`` or the key's ``deactivated``)."""


VerifySignatureAtTimeRejection = Literal[
    "did_resolution_failed", "key_not_authorized", "controller_not_bound", "signature_invalid", "timestamp_invalid"
]


@dataclass(frozen=True)
class VerifySignatureAtTimeResult:
    """Result of ``verify_signature_at_time``. ``valid`` only when the signature verifies and the key was
    authorized at the stated time. Treat ``indeterminate`` as not accepted.

    ``reason`` (for ``invalid``): ``did_resolution_failed`` (the did:webvh log, or a controller's, could not be
    fetched or failed verification),
    ``key_not_authorized`` (see ``key.reason``), ``controller_not_bound`` (the agent is not bound to its controller
    now, RFC-001 §6.6 item 7), ``signature_invalid`` or ``timestamp_invalid`` (the RFC 3161 ``timestamp_token`` does
    not verify; see ``timestamp_rejection``, ADR-007).
    """

    status: Literal["valid", "invalid", "indeterminate"]
    reason: VerifySignatureAtTimeRejection | None = None
    key: KeyAtTimeResult | None = None
    timestamp_rejection: str | None = None
    """Set with ``reason="timestamp_invalid"``: a ``TimestampRejection``."""


# ---------------------------------------------------------------------------
# AgentMetadataCredential (RFC-001 §4.4)
# ---------------------------------------------------------------------------


class IssueAgentMetadataCredentialParams(BaseModel):
    """Parameters of ``AgentDidClient.issue_agent_metadata_credential``."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    agent_did: str
    """The agent the credential is about (``credentialSubject.id``). Must resolve and not be deactivated."""
    signer: Any
    """``AgentSigner`` that holds the controller key named by ``verification_method_id`` (for example a KMS or HSM
    key)."""
    verification_method_id: str
    """An active ``assertionMethod`` key of the agent's controller (the issuer), e.g.
    ``controller_document.assertion_method[0]``."""
    agent_metadata: dict[str, Any] | None = None
    """The metadata to state, with its JSON member names (``coreModelHash``, ``memberOf``...). Defaults to the agent
    document's ``agentMetadata``; pass a subset to share only some members. The values are the controller's assertion:
    they are not compared with the document."""
    credential_id: str | None = None
    """Optional credential ``id`` (a URL, URN or DID URL)."""
    valid_from: str | None = None
    """RFC 3339 date-time from which the credential is valid. Defaults to now."""
    valid_until: str | None = None
    """RFC 3339 date-time after which the credential is no longer valid."""


AgentMetadataCredentialRejection = Literal[
    "malformed_credential",
    "unsupported_proof",
    "subject_mismatch",
    "not_yet_valid",
    "expired",
    "did_deactivated",
    "did_resolution_failed",
    "controller_not_bound",
    "issuer_not_controller",
    "key_not_authorized",
    "signature_invalid",
]
"""Why ``verify_agent_metadata_credential`` rejected a credential (RFC-001 §4.4).

* ``malformed_credential``: not a VC 2.0 ``AgentMetadataCredential`` of the Agent-DID profile (``@context``,
  ``type``, ``issuer``, ``credentialSubject.id``, ``credentialSubject.agentMetadata``, ``validFrom`` /
  ``validUntil`` dates).
* ``unsupported_proof``: the proof is absent, is a proof set, is not ``DataIntegrityProof`` / ``eddsa-jcs-2022`` /
  ``assertionMethod``, its ``verificationMethod`` is not a key of ``issuer``, or its ``proofValue`` is malformed.
* ``subject_mismatch``: ``expected_agent_did`` is set and ``credentialSubject.id`` differs.
* ``not_yet_valid``: now is before ``validFrom``.
* ``expired``: now is after ``validUntil`` (or after the proof's ``expires``).
* ``did_deactivated``: the agent DID is deactivated.
* ``did_resolution_failed``: the agent DID, or its controller, could not be resolved and verified.
* ``controller_not_bound``: the agent is not bound to its controller now (RFC-001 §6.6 item 7).
* ``issuer_not_controller``: ``issuer`` is not the agent document's ``controller``.
* ``key_not_authorized``: ``proof.verificationMethod`` is not an active Ed25519 ``assertionMethod`` key of the
  issuer.
* ``signature_invalid``: the proof does not verify.
"""


@dataclass(frozen=True)
class VerifyAgentMetadataCredentialResult:
    """Result of ``verify_agent_metadata_credential``. Test ``result.ok``: the object is truthy for a rejection
    too."""

    ok: bool
    reason: AgentMetadataCredentialRejection | None = None
    agent_did: str | None = None
    """For an accepted credential, the agent DID (``credentialSubject.id``)."""
    issuer: str | None = None
    """For an accepted credential, the controller that issued it."""
    verification_method: str | None = None
    """For an accepted credential, the key of the issuer that made the proof."""
    agent_metadata: dict[str, Any] | None = None
    """For an accepted credential, the metadata the controller states (JSON member names). An assertion of the
    controller, not evidence of what the agent runs."""
    controllers: list[str] = field(default_factory=list)
    """For an accepted credential, the controller chain of the agent, nearest first (empty for an agent that
    controls itself)."""


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
IdentityCompositionRejection = Literal[
    "key_purpose_violation",
    "rotation_window_closed",
    "emergency_revoked",
    "tampered",
    "card_keyid_mismatch",
    "format_drift",
    "did_document_unresolvable",
    "request_rejected",
]
"""Why a signed Agent Card or a request checked against one was rejected (composition contract §5). The first four
are the cross-stack floor (§5.1); the others are verifier-side reasons (§5.2) plus ``request_rejected``:

* ``rotation_window_closed``: the key was retired by its controller (planned retirement); the overlap is over.
* ``emergency_revoked``: the key carries ``revoked``.
* ``key_purpose_violation``: the key is a key of the DID, active, but not an ``assertionMethod`` key.
* ``tampered``: the signature does not verify under the key, or the key is not a key of the DID.
* ``card_keyid_mismatch``: the request was signed by a DID or key the card does not publish.
* ``format_drift``: the card is not a JSON object with Agent-DID JWS signatures (see ``parse_signed_agent_card``).
* ``did_document_unresolvable``: the agent DID has no active verification chain (unknown, deactivated, unbound
  controller or the resolver failed).
* ``request_rejected``: the HTTP signature failed a check the contract does not name; ``http_reason`` says which.
"""


@dataclass(frozen=True)
class VerifyAgentCardResult:
    """Result of ``verify_agent_card``. Test ``result.ok``."""

    ok: bool
    reason: IdentityCompositionRejection | None = None
    did: str | None = None
    """For an accepted card, its agent DID."""
    published_key_ids: tuple[str, ...] = ()
    """For an accepted card, the keys it publishes: signature ``kid`` values, then the extension ``keyIds``."""
    key_id: str | None = None
    """For a rejected card, the signature ``kid`` that failed, when one did."""


class VerifyIdentityCompositionParams(VerifyHttpRequestSignatureParams):
    agent_card: Any
    """The Agent Card of the agent that signed the request, as fetched (a parsed JSON value)."""


@dataclass(frozen=True)
class VerifyIdentityCompositionResult:
    """Result of ``verify_identity_composition``. Test ``result.ok``."""

    ok: bool
    reason: IdentityCompositionRejection | None = None
    stage: Literal["agent_card", "request"] | None = None
    """For a rejection, which check failed: the card's own signatures, or the request against the card."""
    http_reason: HttpSignatureRejection | None = None
    """For a rejection in the HTTP verifier, its reason."""
    did: str | None = None
    key_id: str | None = None
    controllers: tuple[str, ...] = ()
    published_key_ids: tuple[str, ...] = ()


class AgentDocumentHistoryEntry(BaseModel):
    did: str
    revision: int
    action: AgentDocumentHistoryAction
    timestamp: str
    version: str | None = None
    document_ref: str | None = Field(default=None, alias="documentRef")
