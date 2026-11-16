"""AgentIdentity — main class for creating, signing, resolving and revoking Agent-DIDs."""

from __future__ import annotations

import asyncio
import functools
import uuid
from collections.abc import Awaitable, Callable, Sequence
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Concatenate, Literal, ParamSpec, TypeVar

import httpx
from nacl.signing import SigningKey

from ..crypto.data_integrity import (
    DATA_INTEGRITY_PROOF_TYPE,
    EDDSA_JCS_2022_CRYPTOSUITE,
    create_eddsa_jcs_2022_proof,
    eddsa_jcs_2022_hash_data,
    encode_eddsa_proof_value,
    verify_eddsa_jcs_2022_proof,
)
from ..crypto.ed25519 import decode_signature_hex
from ..crypto.hash import create_metadata_commitment, generate_commitment_salt
from ..crypto.multibase import did_key_from_public_key
from ..crypto.timestamp import verify_timestamp_token
from ..http_signatures.verify_request import (
    ExtensionRejection,
    SignatureCheck,
    SignatureCheckOutcome,
    verify_agent_did_http_request,
    verify_agent_did_http_request_with,
)
from ..lifecycle.documents import (
    assert_update_patch,
    build_added_key_document,
    build_retired_key_document,
    build_rotated_document,
    build_updated_document,
    next_document_timestamp,
)
from ..registry.in_memory import InMemoryAgentRegistry
from ..registry.types import AgentRegistry
from ..resolver.http_source import HttpDIDDocumentSource, HttpDIDDocumentSourceConfig
from ..resolver.in_memory import InMemoryDIDResolver
from ..resolver.jsonrpc_source import JsonRpcDIDDocumentSource, JsonRpcDIDDocumentSourceConfig
from ..resolver.types import (
    DEFAULT_RESOLVER_MAX_CACHE_ENTRIES,
    DIDDocumentSource,
    DIDResolver,
    DidWebvhResolution,
    DidWebvhState,
    ResolutionLimits,
    ResolverResolutionEvent,
    UniversalResolverConfig,
)
from ..resolver.universal import UniversalResolverClient
from ..resolver.webvh_source import WebvhDIDDocumentSource, WebvhDIDDocumentSourceConfig
from ..verification.key_at_time import check_did_webvh_key_at_time, parse_rfc3339_millis, signature_result_for_key
from ..verification.signature import verify_with_active_keys
from ..webvh.adapter import (
    REMOVE_WITNESSES,
    DidWebvhError,
    DidWebvhLogResult,
    DidWebvhWitnessCollector,
    DidWebvhWitnessConfig,
    compare_did_webvh_logs,
    create_did_webvh_log,
    deactivate_did_webvh_log,
    did_webvh_last_entry_signers,
    did_webvh_update_key_for,
    resolve_did_webvh_log,
    update_did_webvh_log,
)
from ..webvh.documents import (
    additional_relationship_entries,
    build_agent_document_template,
    build_bootstrap_controller_template,
    compute_document_reference,
    history_from_did_webvh_log,
    normalize_did_path_segment,
)
from .agent_card import did_of_key_id, parse_signed_agent_card
from .agent_metadata_credential import (
    agent_metadata_problem,
    build_unsigned_agent_metadata_credential,
    check_agent_metadata_credential_form,
)
from .capability import (
    AGENT_DID_CAPABILITY_HTTP_HEADER,
    CAPABILITY_DELEGATION_PURPOSE,
    CAPABILITY_HEADER_MISSING,
    DEFAULT_MAX_CAPABILITY_CHAIN_LENGTH,
    MAX_CAPABILITY_HEADER_BYTES,
    CapabilityChainRejection,
    action_allowed,
    build_unsigned_capability,
    capability_form_problem,
    check_capability_chain,
    child_capability_chain,
    invocation_target_problem,
    parse_capability_header,
    root_capability_id,
    target_within,
)
from .controller_binding import ControllerBindingError, assert_bound_to_controller
from .http_security import HttpTargetValidationOptions
from .http_signatures import KeyedComponent, SignatureInput
from .identity_composition import (
    DID_VERIFICATION_RELATIONSHIPS,
    REQUIRED_RELATIONSHIP_BY_ARTIFACT,
    IdentityCompositionError,
    composition_reason_for_key,
)
from .message_signing import message_signing_input
from .nonce_store import InMemoryNonceStore, NonceStore
from .oauth_client import parse_client_assertion
from .signer import AgentSigner, LocalKeySigner
from .time_utils import normalize_timestamp_to_iso
from .types import (
    AddVerificationMethodResult,
    AgentDIDDocument,
    AgentDocumentHistoryAction,
    AgentDocumentHistoryEntry,
    AnyDidDocument,
    CapabilityRejection,
    ClientAssertionRejection,
    CreateAgentParams,
    CreateAgentResult,
    CreateDidWebvhOptions,
    DidWebvhControllerKeys,
    IdentityCompositionRejection,
    IssueAgentMetadataCredentialParams,
    KeyAtTimeResult,
    MetadataCommitmentSalts,
    RotateVerificationMethodResult,
    SigningVerificationPurpose,
    UpdateAgentDocumentParams,
    VerificationRelationship,
    VerifyAgentCardResult,
    VerifyAgentMetadataCredentialResult,
    VerifyCapabilityChainResult,
    VerifyClientAssertionResult,
    VerifyHttpCapabilityInvocationParams,
    VerifyHttpCapabilityInvocationResult,
    VerifyHttpRequestSignatureParams,
    VerifyHttpRequestSignatureResult,
    VerifyIdentityCompositionParams,
    VerifyIdentityCompositionResult,
    VerifySignatureAtTimeResult,
    parse_did_document,
)
from .verification_method import active_ed25519_public_key, relationship_methods

_P = ParamSpec("_P")
_R = TypeVar("_R")


def _metadata_commitment(field: str, value: str | None, salt: str | None) -> tuple[str, str] | None:
    """Salted commitment and salt for an optional metadata value (RFC-001 §4.3), or ``None`` without a value.

    A salt without its value is a caller mistake and raises ``ValueError``.
    """
    if value is None:
        if salt is not None:
            raise ValueError(f"{field}_salt was given without {field}")
        return None
    used_salt = salt if salt is not None else generate_commitment_salt()
    return create_metadata_commitment(value, used_salt), used_salt


def _one_operation_per_did(
    method: Callable[Concatenate[AgentDidClient, str, _P], Awaitable[_R]],
) -> Callable[Concatenate[AgentDidClient, str, _P], Awaitable[_R]]:
    """Run a lifecycle operation of a DID only after every earlier one of the same DID in this client has finished."""

    @functools.wraps(method)
    async def serialized(self: AgentDidClient, did: str, /, *args: _P.args, **kwargs: _P.kwargs) -> _R:
        async with self._did_locks.setdefault(did, asyncio.Lock()):
            return await method(self, did, *args, **kwargs)

    return serialized

@dataclass
class ProductionResolverProfileConfig:
    registry: AgentRegistry
    document_source: DIDDocumentSource
    wba_document_source: DIDDocumentSource | None = None
    webvh_document_source: DIDDocumentSource | None = None
    cache_ttl_ms: int | None = None
    max_cache_entries: int | None = None
    on_resolution_event: object | None = None
    unverified_document_ref_schemes: list[str] | None = None
    resolution_limits: ResolutionLimits | None = None


@dataclass
class ProductionHttpResolverProfileConfig:
    registry: AgentRegistry
    cache_ttl_ms: int | None = None
    max_cache_entries: int | None = None
    reference_to_url: Callable[[str], str] | None = None
    reference_to_urls: Callable[[str], list[str]] | None = None
    http_client: httpx.AsyncClient | None = None
    ipfs_gateways: list[str] | None = None
    on_resolution_event: Callable[[ResolverResolutionEvent], None] | None = None
    http_security: HttpTargetValidationOptions | None = None
    unverified_document_ref_schemes: list[str] | None = None
    resolution_limits: ResolutionLimits | None = None


@dataclass
class ProductionJsonRpcResolverProfileConfig:
    registry: AgentRegistry
    cache_ttl_ms: int | None = None
    max_cache_entries: int | None = None
    endpoint: str | None = None
    endpoints: list[str] | None = None
    method: str | None = None
    build_params: Callable[[str], list[Any]] | None = None
    headers: dict[str, str] | None = None
    http_client: httpx.AsyncClient | None = None
    on_resolution_event: Callable[[ResolverResolutionEvent], None] | None = None
    http_security: HttpTargetValidationOptions | None = None
    resolution_limits: ResolutionLimits | None = None


@dataclass
class AgentDidClientOptions:
    """Options of :class:`AgentDidClient`."""

    resolver: DIDResolver | None = None
    """DID resolver. Defaults to a fresh in-memory resolver."""
    registry: AgentRegistry | None = None
    """Agent registry. Defaults to a fresh in-memory registry."""
    nonce_store: NonceStore | None = None
    """Replay store for ``verify_http_request_signature``. Defaults to a fresh in-memory store."""
    clock: Callable[[], datetime] | None = None
    """Time source (timezone-aware ``datetime``). Defaults to ``datetime.now(timezone.utc)``."""
    webvh_domain: str = "agents.local"
    """Domain of the implicit local did:webvh profile."""
    collect_witness_proofs: DidWebvhWitnessCollector | None = None
    """Obtains witness approvals for did:webvh entries governed by a witness rule (ADR-007): when the DID was created
    with ``webvh.witness`` or ``set_did_webvh_witnesses``. Without it, changing such a DID fails before anything is
    stored."""


class AgentDidClient:
    """Owns all mutable identity state (resolver, registry, replay store, document history,
    did:webvh logs and controller signers). Each client is an isolated instance: two clients
    never share state. ``AgentIdentity``'s static API is a facade over a default client."""

    def __init__(self, options: AgentDidClientOptions | None = None) -> None:
        opts = options or AgentDidClientOptions()
        self._resolver: DIDResolver = opts.resolver or InMemoryDIDResolver()
        self._registry: AgentRegistry = opts.registry or InMemoryAgentRegistry()
        # The default store reads the client's clock, like the signature window it protects
        self._nonce_store: NonceStore = opts.nonce_store or InMemoryNonceStore(
            now=lambda: int(self._clock().timestamp())
        )
        self._clock: Callable[[], datetime] = opts.clock or (lambda: datetime.now(timezone.utc))
        self._webvh_domain: str = opts.webvh_domain
        self._history_store: dict[str, list[AgentDocumentHistoryEntry]] = {}
        # did:webvh v1.0 logs (did.jsonl) of the DIDs created or imported in this process.
        self._did_webvh_log_store: dict[str, str] = {}
        # did-witness.json of the stored logs that have witnessed entries (ADR-007), keyed by DID.
        self._did_webvh_witness_store: dict[str, str] = {}
        self._collect_witness_proofs: DidWebvhWitnessCollector | None = opts.collect_witness_proofs
        # Deactivation state derived from the verified log, keyed by DID and tied to the exact
        # log text it was computed from. It is recomputed whenever the stored log changes.
        self._did_webvh_state_cache: dict[str, tuple[str, str | None, bool, AnyDidDocument]] = {}
        # Controller signers (did:webvh updateKeys) retained for DIDs created in this process.
        self._did_webvh_signer_store: dict[str, AgentSigner] = {}
        # Local bootstrap controllers, keyed by lowercase controller wallet address.
        self._bootstrap_controllers: dict[str, tuple[str, AgentSigner]] = {}
        self._bootstrap_controller_locks: dict[str, asyncio.Lock] = {}
        # One lifecycle operation (update, rotation, revocation, import) at a time per DID, so none is lost.
        self._did_locks: dict[str, asyncio.Lock] = {}

    def _store_did_webvh_log(self, did: str, result: DidWebvhLogResult) -> None:
        """Store a verified log and its witness file (or drop the stale one when the log has none)."""
        self._did_webvh_log_store[did] = result.log
        if result.witness_file is not None:
            self._did_webvh_witness_store[did] = result.witness_file
        else:
            self._did_webvh_witness_store.pop(did, None)

    def _now_iso_timestamp(self) -> str:
        return normalize_timestamp_to_iso(self._clock().isoformat())  # type: ignore[return-value]

    async def create_agent(self, controller_signer: AgentSigner, params: CreateAgentParams) -> CreateAgentResult:
        """Create a new Agent-DID document (passport) in this client's state."""
        # Reject an unsupported relationship before generating keys or touching any store
        additional_relationship_entries(params.additional_verification_relationships, "")
        timestamp = self._now_iso_timestamp()
        # The creator is identified by its Ed25519 key, never by an EVM address
        controller_key_did = did_key_from_public_key(await controller_signer.get_public_key())

        # Commit to the sensitive metadata with salted HMACs so it cannot be guessed by dictionary. Both
        # commitments are optional controller assertions (RFC-001 §4.3): no value, no commitment and no salt.
        core_model = _metadata_commitment("core_model", params.core_model, params.core_model_salt)
        system_prompt = _metadata_commitment("system_prompt", params.system_prompt, params.system_prompt_salt)
        metadata_commitment_salts = MetadataCommitmentSalts(
            core_model=core_model[1] if core_model else None,
            system_prompt=system_prompt[1] if system_prompt else None,
        )
        agent_metadata: dict[str, Any] = {
            "name": params.name,
            "description": params.description,
            "version": params.version or "1.0.0",
            "capabilities": params.capabilities or [],
            "memberOf": params.member_of,
        }
        if core_model:
            agent_metadata["coreModelHash"] = core_model[0]
        if system_prompt:
            agent_metadata["systemPromptHash"] = system_prompt[0]

        # The agent's own Ed25519 key (RFC-001 assertion/authentication key)
        private_key_hex = ""
        if params.signer is not None:
            public_key_bytes = await params.signer.get_public_key()
        else:
            signing_key = SigningKey.generate()
            private_key_hex = signing_key.encode().hex()
            public_key_bytes = bytes(signing_key.verify_key)

        return await self._create_did_webvh_agent(
            params,
            controller_key_did=controller_key_did,
            timestamp=timestamp,
            agent_metadata=agent_metadata,
            public_key_bytes=public_key_bytes,
            private_key_hex=private_key_hex,
            metadata_commitment_salts=metadata_commitment_salts,
        )

    async def _create_did_webvh_agent(
        self,
        params: CreateAgentParams,
        *,
        controller_key_did: str,
        timestamp: str,
        agent_metadata: dict[str, Any],
        public_key_bytes: bytes,
        private_key_hex: str,
        metadata_commitment_salts: MetadataCommitmentSalts,
    ) -> CreateAgentResult:
        """Canonical did:webvh v1.0 profile.

        The agent document is the genesis entry of a ``did.jsonl`` log signed by the
        controller key (the log's only ``updateKeys`` entry).
        """
        controller_private_key: str | None = None
        next_update_keys: list[str] | None = None
        witness: DidWebvhWitnessConfig | None = None
        if params.webvh is not None and params.webvh.domain.strip():
            options = self._require_webvh_create_options(params)
            domain = options.domain.strip()
            path_segments = list(options.path_segments or [])
            controller_did = options.controller_did.strip()
            controller_signer = options.controller_signer
            next_update_keys = options.next_update_keys
            witness = options.witness
        else:
            # Only the implicit local profile bootstraps a controller. An explicitly supplied
            # controller DID must be published by its owner; the SDK never fabricates it.
            controller_did, controller_signer, controller_private_key = await self._ensure_bootstrap_controller(
                controller_key_did
            )
            domain = self._webvh_domain
            path_segments = ["agents", normalize_did_path_segment(params.name)]

        template = build_agent_document_template(
            controller_did=controller_did,
            timestamp=timestamp,
            agent_metadata=agent_metadata,
            public_key_bytes=public_key_bytes,
            additional_verification_relationships=params.additional_verification_relationships,
        )

        created = await create_did_webvh_log(
            domain=domain,
            path_segments=path_segments,
            document=template,
            signer=controller_signer,
            next_update_keys=next_update_keys,
            witness=witness,
            collect_witness_proofs=self._collect_witness_proofs,
        )
        document = AgentDIDDocument.model_validate(created.state)
        self._store_did_webvh_log(document.id, created)
        self._did_webvh_signer_store[document.id] = controller_signer

        self._resolver.register_document(document)
        await self._registry.register(document.id, document.controller, compute_document_reference(document))
        self._append_history(document, "created")

        return CreateAgentResult(
            document=document,
            agent_private_key=private_key_hex,
            signer=params.signer,
            controller_private_key=controller_private_key,
            metadata_commitment_salts=metadata_commitment_salts,
        )

    @staticmethod
    def _require_webvh_create_options(params: CreateAgentParams) -> CreateDidWebvhOptions:
        if params.webvh is None or not params.webvh.domain.strip():
            raise ValueError("webvh.domain is required")

        if not params.webvh.controller_did.strip():
            raise ValueError("webvh.controller_did is required")

        return params.webvh

    async def _ensure_bootstrap_controller(self, controller_key_did: str) -> tuple[str, AgentSigner, str | None]:
        """Return the local bootstrap controller for a creator's did:key, creating it on first use.

        Its did:webvh log is signed by a controller key generated with a CSPRNG; the key is
        returned to the caller exactly once (third element) and never derived from public data.
        Concurrent creates for the same creator share one bootstrap controller (a lock per creator key).
        """
        address = controller_key_did.strip()
        lock = self._bootstrap_controller_locks.setdefault(address, asyncio.Lock())
        async with lock:
            return await self._create_or_reuse_bootstrap_controller(address)

    async def _create_or_reuse_bootstrap_controller(self, address: str) -> tuple[str, AgentSigner, str | None]:
        key_id = address.removeprefix("did:key:")
        existing = self._bootstrap_controllers.get(address)
        if existing is not None and await self._registry.get_record(existing[0]) is not None:
            return existing[0], existing[1], None

        signer, private_key = LocalKeySigner.generate()
        template = build_bootstrap_controller_template(
            creator_key_did=address,
            timestamp=self._now_iso_timestamp(),
            public_key_bytes=await signer.get_public_key(),
        )

        created = await create_did_webvh_log(
            domain=self._webvh_domain,
            path_segments=["controllers", normalize_did_path_segment(key_id)],
            document=template,
            signer=signer,
        )
        document = AgentDIDDocument.model_validate(created.state)
        self._store_did_webvh_log(document.id, created)
        self._did_webvh_signer_store[document.id] = signer
        self._bootstrap_controllers[address] = (document.id, signer)

        self._resolver.register_document(document)
        await self._registry.register(document.id, document.controller, compute_document_reference(document))
        self._append_history(document, "created")
        return document.id, signer, private_key

    def _require_did_webvh_lifecycle(self, did: str, controller_signer: AgentSigner | None) -> tuple[str, AgentSigner]:
        log = self._did_webvh_log_store.get(did)
        if log is None:
            raise ValueError(
                f"No did:webvh log for {did} in this process; import it with import_did_webvh_history first"
            )
        signer = controller_signer or self._did_webvh_signer_store.get(did)
        if signer is None:
            raise ValueError(f"A controller signer is required to change {did}: pass controller_signer")
        return log, signer

    async def _append_did_webvh_entry(
        self, did: str, document: AgentDIDDocument, controller_signer: AgentSigner | None
    ) -> AgentDIDDocument:
        """Append a controller-signed entry with *document* to the DID's log; return the signed state."""
        log, signer = self._require_did_webvh_lifecycle(did, controller_signer)
        updated = await update_did_webvh_log(
            log=log,
            signer=signer,
            document=document.model_dump(by_alias=True, exclude_none=True),
            witness_file=self._did_webvh_witness_store.get(did),
            collect_witness_proofs=self._collect_witness_proofs,
        )
        self._store_did_webvh_log(did, updated)
        # With pre-rotation active the signer was a committed key and is now the active controller key.
        if await did_webvh_update_key_for(signer) in updated.metadata.update_keys:
            self._did_webvh_signer_store[did] = signer
        return AgentDIDDocument.model_validate(updated.state)

    @_one_operation_per_did
    async def rotate_controller_key(
        self,
        did: str,
        new_controller_signer: AgentSigner,
        *,
        next_update_keys: list[str] | None = None,
        controller_signer: AgentSigner | None = None,
    ) -> DidWebvhControllerKeys:
        """Rotate the controller key of a did:webvh DID: append a log entry whose ``updateKeys`` is
        *new_controller_signer*'s key.

        This is the recovery path after a compromise of the controller key, and it only works if the DID
        committed to a successor (pre-rotation: ``CreateDidWebvhOptions.next_update_keys`` at creation, or a
        previous rotation that set ``next_update_keys``).

        * Pre-rotation active: *new_controller_signer* must be a committed key and signs the entry; the key
          that was active can no longer sign.
        * Not active: the current controller signer (*controller_signer*, or the one retained in this process)
          signs, and *next_update_keys* may start pre-rotation.

        Commit to the following key in *next_update_keys*, or the key you rotate to stays the only valid next key.
        An empty list ends pre-rotation.
        """
        if not did.startswith("did:webvh:"):
            raise ValueError(f"did:webvh DID is required to rotate the controller key: {did}")
        log = self._did_webvh_log_store.get(did)
        if log is None:
            raise ValueError(
                f"No did:webvh log for {did} in this process; import it with import_did_webvh_history first"
            )
        current = await resolve_did_webvh_log(log, did=did, witness_file=self._did_webvh_witness_store.get(did))
        signer = (
            new_controller_signer
            if current.metadata.next_key_hashes
            else controller_signer or self._did_webvh_signer_store.get(did)
        )
        if signer is None:
            raise ValueError(f"A controller signer is required to change {did}: pass controller_signer")
        new_key = await did_webvh_update_key_for(new_controller_signer)
        updated = await update_did_webvh_log(
            log=log,
            signer=signer,
            update_keys=[new_key],
            next_update_keys=next_update_keys,
            witness_file=self._did_webvh_witness_store.get(did),
            collect_witness_proofs=self._collect_witness_proofs,
        )
        self._store_did_webvh_log(did, updated)
        self._did_webvh_signer_store[did] = new_controller_signer
        return DidWebvhControllerKeys(
            update_keys=list(updated.metadata.update_keys), next_key_hashes=list(updated.metadata.next_key_hashes)
        )

    async def get_did_webvh_controller_keys(self, did: str) -> DidWebvhControllerKeys:
        """The controller keys of a did:webvh DID, from its verified log (including pre-rotation commitments)."""
        log = self._did_webvh_log_store.get(did)
        if not did.startswith("did:webvh:") or log is None:
            raise ValueError(
                f"No did:webvh log for {did} in this process; import it with import_did_webvh_history first"
            )
        resolved = await resolve_did_webvh_log(log, did=did, witness_file=self._did_webvh_witness_store.get(did))
        return DidWebvhControllerKeys(
            update_keys=list(resolved.metadata.update_keys),
            next_key_hashes=list(resolved.metadata.next_key_hashes),
        )

    @_one_operation_per_did
    async def set_did_webvh_witnesses(
        self,
        did: str,
        witness: DidWebvhWitnessConfig | None,
        *,
        controller_signer: AgentSigner | None = None,
    ) -> DidWebvhWitnessConfig:
        """Set, change or (with ``None``) remove the witnesses of a did:webvh DID (ADR-007) by appending a log entry.

        The witnesses in force approve that entry (through ``AgentDidClientOptions.collect_witness_proofs``); the new
        rule governs the entries after it. Returns the witness configuration now in force (``threshold`` 0 and no
        witnesses when removed).
        """
        if not did.startswith("did:webvh:"):
            raise ValueError(f"did:webvh DID is required to set witnesses: {did}")
        log, signer = self._require_did_webvh_lifecycle(did, controller_signer)
        updated = await update_did_webvh_log(
            log=log,
            signer=signer,
            witness=witness if witness is not None else REMOVE_WITNESSES,
            witness_file=self._did_webvh_witness_store.get(did),
            collect_witness_proofs=self._collect_witness_proofs,
        )
        self._store_did_webvh_log(did, updated)
        return DidWebvhWitnessConfig(
            threshold=int(updated.metadata.witness_threshold), witnesses=list(updated.metadata.witnesses)
        )

    def export_did_webvh_witness_file(self, did: str) -> str | None:
        """The ``did-witness.json`` of a did:webvh DID created, changed or imported in this process, or ``None`` when
        its log has no witnessed entries. Publish it next to ``did.jsonl``, and before it."""
        if not did.startswith("did:webvh:") or did not in self._did_webvh_log_store:
            raise ValueError(
                f"No did:webvh log for {did} in this process; import it with import_did_webvh_history first"
            )
        return self._did_webvh_witness_store.get(did)

    async def _resolve_active_verification_chain(self, did: str) -> tuple[AgentDIDDocument, list[AnyDidDocument]]:
        """The agent's document and its controller chain, every link active and (did:webvh) bound. The agent's
        document must be an Agent-DID document; the controllers may be any DID Core documents (RFC-001 §4.2.1)."""
        if did.startswith("did:webvh:"):
            first, *controllers = await self.resolve_controller_chain(did)
            agent = _agent_document(first, did)
        else:
            agent, controllers = await self.resolve(did), []
        chain: list[AnyDidDocument] = [agent, *controllers]
        if any(not self._has_active_verification_method(document) for document in chain):
            raise ValueError(f"DID is not active: {did}")
        if did.startswith("did:webvh:"):
            await self._assert_controller_chain_bound(chain)
        return agent, controllers

    async def _assert_controller_chain_bound(self, chain: list[AnyDidDocument]) -> None:
        """Every link of a controller chain (agent -> controller -> its controller ...) must be bound: the last entry
        of the agent's did:webvh log was signed by a key that is active now under ``capabilityInvocation`` of the
        controller (RFC-001 §6.6 item 7). Fails closed with :class:`ControllerBindingError`, also when no log is
        available to check."""
        for index, (agent, controller) in enumerate(zip(chain, chain[1:], strict=False)):
            state = await self.resolve_did_webvh_state(agent.id) if agent.id.startswith("did:webvh:") else None
            if state is None:
                raise ControllerBindingError(
                    agent.id, controller.id, "no did:webvh log is available to check the binding"
                )
            if state.deactivated and index > 0:
                raise ControllerBindingError(agent.id, controller.id, "the controller DID is deactivated")
            assert_bound_to_controller(agent, state.last_entry_signer_keys, controller)

    async def resolve_did_webvh_state(self, did: str) -> DidWebvhState | None:
        """The verified did:webvh log behind *did* and what it says: the document in force, ``version_id``, the
        ``update_keys`` in force, the keys that signed the last entry and the provenance of the log.

        A DID created or changed in this client is answered from its local log; any other is answered by the resolver
        (``resolve_did_webvh_log``), which raises when the log cannot be fetched or verified, and otherwise from the
        log imported in this client. Returns ``None`` for a DID that is not did:webvh or has no log available (a
        resolver that holds only documents)."""
        if not did.startswith("did:webvh:"):
            return None
        local = self._did_webvh_log_store.get(did)
        if local is not None and did in self._did_webvh_signer_store:
            return await self._did_webvh_state_from_log(did, local, "local")
        resolve_log = getattr(self._resolver, "resolve_did_webvh_log", None)
        fetched: DidWebvhResolution | None = await resolve_log(did) if callable(resolve_log) else None
        if fetched is not None:
            return DidWebvhState(
                document=fetched.document,
                log=fetched.log,
                version_id=fetched.version_id,
                update_keys=fetched.update_keys,
                last_entry_signer_keys=fetched.last_entry_signer_keys,
                deactivated=fetched.deactivated,
                witness_file=fetched.witness_file,
                provenance="fetched",
            )
        return await self._did_webvh_state_from_log(did, local, "imported") if local is not None else None

    async def _did_webvh_state_from_log(
        self, did: str, log: str, provenance: Literal["local", "imported"]
    ) -> DidWebvhState:
        resolved = await resolve_did_webvh_log(log, did=did, witness_file=self._did_webvh_witness_store.get(did))
        return DidWebvhState(
            document=parse_did_document(resolved.state),
            log=resolved.log,
            version_id=resolved.metadata.version_id,
            update_keys=list(resolved.metadata.update_keys),
            last_entry_signer_keys=did_webvh_last_entry_signers(resolved.log),
            deactivated=bool(resolved.metadata.deactivated),
            witness_file=resolved.witness_file,
            provenance=provenance,
        )

    async def _assert_did_webvh_bound_now(self, did: str, state: DidWebvhState) -> None:
        """The binding of *did* (and of its controllers) to its controller chain as it is now."""
        controller = state.document.controller
        if not isinstance(controller, str) or not controller.strip() or controller.strip() == did:
            return
        controller_did = controller.strip()
        try:
            controllers = await self.resolve_controller_chain(controller_did)
        except Exception as exc:
            raise ControllerBindingError(did, controller_did, f"the controller does not resolve ({exc})") from exc
        await self._assert_controller_chain_bound([state.document, *controllers])

    @staticmethod
    def _has_active_verification_method(document: AnyDidDocument) -> bool:
        """Whether *document* has an active ``publicKeyMultibase`` key, declared or embedded in a relationship."""
        listed = [
            method
            for relationship in DID_VERIFICATION_RELATIONSHIPS
            for method in relationship_methods(document, relationship)
        ]
        return any(
            method.public_key_multibase and not method.deactivated
            for method in [*(document.verification_method or []), *listed]
        )

    # ------------------------------------------------------------------
    # Class methods — verification & resolution
    # ------------------------------------------------------------------

    async def verify_http_request_signature(self, params: VerifyHttpRequestSignatureParams) -> bool:
        """Verify an Agent-DID RFC 9421 HTTP Message Signature.

        Requires the Agent-DID profile (covered components, ``tag="agent-did"``, ``alg="ed25519"``,
        ``created``, ``expires``, ``nonce``, a ``keyid`` under the DID of the ``Agent-DID`` member), a matching
        ``Content-Digest``, and a signature by an active ``assertionMethod`` key. The nonce is then
        recorded in ``nonce_store`` (default: this client's :class:`InMemoryNonceStore`), so a
        replayed request is rejected. Returns ``False`` on any failure; use
        :meth:`verify_http_request_signature_detailed` to learn why.
        """
        return (await self.verify_http_request_signature_detailed(params)).ok

    async def verify_http_request_signature_detailed(
        self, params: VerifyHttpRequestSignatureParams
    ) -> VerifyHttpRequestSignatureResult:
        """Same verification as :meth:`verify_http_request_signature`, returning the reason of a rejection
        (see ``HttpSignatureRejection``). Test ``result.ok``: the result object is truthy for a rejection too."""
        return await verify_agent_did_http_request(
            params,
            verify_signature=self._check_signature,
            nonce_store=self._nonce_store,
            now=self._clock(),
        )

    async def verify_agent_card(self, card: object) -> VerifyAgentCardResult:
        """Verify a signed A2A Agent Card (composition contract §1.1, §3.1; A2A 1.0 §8.4): its format
        (``parse_signed_agent_card``), then every signature against an active ``assertionMethod`` key of the card's
        agent DID, resolved as for any other signature. A card without signatures is ``format_drift``: the contract
        needs a signed card."""
        parsed = parse_signed_agent_card(card)
        if parsed is None:
            return VerifyAgentCardResult(ok=False, reason="format_drift")
        for entry in parsed.signatures:
            check = await self._check_signature(
                parsed.did,
                entry.signing_input,
                entry.signature.hex(),
                entry.key_id,
                REQUIRED_RELATIONSHIP_BY_ARTIFACT["assertion"],
            )
            if check.outcome != "valid":
                reason = await self._composition_reason(parsed.did, entry.key_id, check.outcome)
                return VerifyAgentCardResult(ok=False, reason=reason, key_id=entry.key_id)
        return VerifyAgentCardResult(ok=True, did=parsed.did, published_key_ids=parsed.published_key_ids)

    async def verify_identity_composition(
        self, params: VerifyIdentityCompositionParams
    ) -> VerifyIdentityCompositionResult:
        """The identity composition check (composition contract §2, §3): the Agent Card must verify
        (:meth:`verify_agent_card`), the request must verify as :meth:`verify_http_request_signature_detailed` checks
        it, the request's agent DID must be the card's, and its ``keyid`` must be a key the card publishes. The card
        is checked first, so a request against a bad card does not consume its nonce. Contract reasons are derived
        from the current DID document: a retired key is ``rotation_window_closed``, a revoked one
        ``emergency_revoked``."""
        card = await self.verify_agent_card(params.agent_card)
        if not card.ok:
            return VerifyIdentityCompositionResult(ok=False, stage="agent_card", reason=card.reason, key_id=card.key_id)
        request = VerifyHttpRequestSignatureParams.model_validate(
            {name: getattr(params, name) for name in VerifyHttpRequestSignatureParams.model_fields}
        )
        # The HTTP verifier reports a reason; the contract reason needs the key and the outcome of its signature check.
        last_check: list[tuple[str, str, SignatureCheckOutcome]] = []

        async def check_and_record(
            did: str, payload: str, signature: str, key_id: str, purpose: VerificationRelationship
        ) -> SignatureCheck:
            check = await self._check_signature(did, payload, signature, key_id, purpose)
            last_check.append((did, key_id, check.outcome))
            return check

        result = await verify_agent_did_http_request(
            request, verify_signature=check_and_record, nonce_store=self._nonce_store, now=self._clock()
        )
        if not result.ok:
            checked = (
                last_check[-1]
                if last_check
                and last_check[-1][2] != "valid"
                and result.reason
                in ("did_resolution_failed", "controller_not_bound", "keyid_not_authorized", "signature_invalid")
                else None
            )
            if checked is None:
                return VerifyIdentityCompositionResult(
                    ok=False, stage="request", reason="request_rejected", http_reason=result.reason
                )
            return VerifyIdentityCompositionResult(
                ok=False,
                stage="request",
                reason=await self._composition_reason(*checked),
                http_reason=result.reason,
                key_id=checked[1],
            )
        if result.did != card.did or result.key_id not in card.published_key_ids:
            return VerifyIdentityCompositionResult(
                ok=False, stage="request", reason="card_keyid_mismatch", key_id=result.key_id
            )
        return VerifyIdentityCompositionResult(
            ok=True,
            did=result.did,
            key_id=result.key_id,
            controllers=tuple(result.controllers),
            published_key_ids=card.published_key_ids,
        )

    async def _composition_reason(
        self, did: str, key_id: str, outcome: SignatureCheckOutcome
    ) -> IdentityCompositionRejection:
        """Contract reason for a signature check that failed, from the current document of *did*."""
        if outcome in ("did_resolution_failed", "controller_not_bound"):
            return "did_document_unresolvable"
        try:
            document = await self.resolve(did)
        except Exception:
            return "did_document_unresolvable"
        return composition_reason_for_key(document, key_id)

    async def _check_signature(
        self,
        did: str,
        payload: str,
        signature: str,
        key_id: str,
        required_purpose: VerificationRelationship,
    ) -> SignatureCheck:
        """``verify_signature`` that tells apart the ways a verification can fail, with the controller chain."""
        try:
            agent, controllers = await self._resolve_active_verification_chain(did)
        except ControllerBindingError:
            return SignatureCheck("controller_not_bound")
        except Exception:
            return SignatureCheck("did_resolution_failed")
        try:
            valid = verify_with_active_keys(agent, payload, signature, key_id, required_purpose)
        except IdentityCompositionError:
            return SignatureCheck("key_not_authorized")
        if not valid:
            return SignatureCheck("invalid")
        return SignatureCheck("valid", tuple(document.id for document in controllers))

    async def verify_signature(
        self,
        did: str,
        payload: str,
        signature: str,
        key_id: str | None = None,
        required_purpose: VerificationRelationship = REQUIRED_RELATIONSHIP_BY_ARTIFACT["assertion"],
    ) -> bool:
        """Verify that *signature* (``sign_message``: it covers ``AGENT_DID_MESSAGE_SIGNING_PREFIX + payload``)
        was produced by *did* for *payload*. HTTP request signatures use ``verify_http_request_signature``."""
        try:
            agent, controllers = await self._resolve_active_verification_chain(did)
        except Exception:
            return False

        return verify_with_active_keys(
            agent, message_signing_input(payload), signature, key_id, required_purpose
        )

    async def verify_signature_at_time(
        self,
        did: str,
        payload: str,
        signature: str,
        key_id: str,
        *,
        stated_time: str,
        required_purpose: VerificationRelationship = REQUIRED_RELATIONSHIP_BY_ARTIFACT["assertion"],
        trusted_time_not_after: str | None = None,
        timestamp_token: bytes | None = None,
        tsa_trust_anchors: Sequence[bytes | str] | None = None,
    ) -> VerifySignatureAtTimeResult:
        """Verify a signature made with *key_id* at the time the signed artifact states (RFC-001 §6.2.2).

        Checks against the DID's verified did:webvh log as :meth:`resolve_did_webvh_state` gives it: the local log
        for a DID created or changed in this client, otherwise the log the resolver fetches (the longer of it and a
        log imported with ``import_did_webvh_history``), and the imported log only when the resolver does not fetch
        logs. A key retired by a later entry of the log host is therefore seen even when an older log was imported.

        * ``valid``: the signature verifies and the key was authorized for *required_purpose* at *stated_time*,
          with no later change that retires it, or with *trusted_time_not_after* earlier than that change.
        * ``invalid``: the signature does not verify, the key was not authorized at *stated_time*, the log cannot
          be fetched or fails verification (``did_resolution_failed``), or the controller binding does not hold now.
        * ``indeterminate``: the key was retired or the DID deactivated after *stated_time* and there is no
          trusted time evidence, or no did:webvh log is available for the DID. Do not accept it.

        The stated time is asserted by the signer, so a retired key is never accepted on the signer's word alone.
        With *timestamp_token* (an RFC 3161 token over the raw signature bytes) and *tsa_trust_anchors*, the SDK
        verifies the token and uses its ``genTime + accuracy`` as the trusted time evidence (ADR-007; needs the
        ``timestamps`` extra); a token that does not verify gives ``invalid`` / ``timestamp_invalid``.
        """
        if timestamp_token is not None:
            if trusted_time_not_after is not None:
                raise TypeError("Pass either timestamp_token or trusted_time_not_after, not both")
            if tsa_trust_anchors is None:
                raise TypeError("timestamp_token needs tsa_trust_anchors")
            try:
                signature_bytes = decode_signature_hex(signature)
            except ValueError:
                return VerifySignatureAtTimeResult(status="invalid", reason="signature_invalid")
            timestamp = verify_timestamp_token(timestamp_token, signature_bytes, trust_anchors=tsa_trust_anchors)
            if timestamp.status == "invalid":
                return VerifySignatureAtTimeResult(
                    status="invalid", reason="timestamp_invalid", timestamp_rejection=timestamp.reason
                )
            trusted_time_not_after = timestamp.trusted_time_not_after
        try:
            state = await self.resolve_did_webvh_state(did)
        except Exception:  # noqa: BLE001 - any resolution failure fails closed
            return VerifySignatureAtTimeResult(status="invalid", reason="did_resolution_failed")
        if state is None:
            return VerifySignatureAtTimeResult(
                status="indeterminate",
                key=KeyAtTimeResult(status="indeterminate", key_id=key_id, reason="history_unavailable"),
            )
        if not isinstance(state.document, AgentDIDDocument):
            try:
                AgentDIDDocument.model_validate(state.document.model_dump(by_alias=True, exclude_none=True))
            except ValueError:
                # Signatures are verified for agents; a plain DID Core document (a controller) is not one
                return VerifySignatureAtTimeResult(status="invalid", reason="did_resolution_failed")
        try:
            key = await check_did_webvh_key_at_time(
                state.log,
                key_id=key_id,
                stated_time=stated_time,
                required_purpose=required_purpose,
                did=did,
                trusted_time_not_after=trusted_time_not_after,
                witness_file=state.witness_file,
            )
        except DidWebvhError:
            return VerifySignatureAtTimeResult(status="invalid", reason="did_resolution_failed")
        result = signature_result_for_key(key, message_signing_input(payload), signature)
        if result.status == "valid":
            # The binding is evaluated against the controller as it is now, never at the stated time
            try:
                await self._assert_did_webvh_bound_now(did, state)
            except ControllerBindingError:
                return VerifySignatureAtTimeResult(status="invalid", reason="controller_not_bound", key=result.key)
            except Exception:  # noqa: BLE001 - a controller that cannot be resolved fails closed
                return VerifySignatureAtTimeResult(status="invalid", reason="did_resolution_failed", key=result.key)
        return result

    async def issue_agent_metadata_credential(self, params: IssueAgentMetadataCredentialParams) -> dict[str, Any]:
        """Issue an ``AgentMetadataCredential`` (RFC-001 §4.4).

        The agent's controller states the agent's metadata in a W3C VC 2.0 credential secured with an
        ``eddsa-jcs-2022`` Data Integrity proof. ``verification_method_id`` must be an active Ed25519
        ``assertionMethod`` key of the controller held by ``signer``. The credential is presented out of band (an A2A
        Agent Card, an MCP exchange, a request body); DID resolution never fetches it.
        """
        agent = await self.resolve(params.agent_did)
        issuer = (agent.controller or "").strip() or agent.id
        if not params.verification_method_id.startswith(f"{issuer}#"):
            raise ValueError(f"verification_method_id must be a key of the agent's controller {issuer}")
        issuer_document: AnyDidDocument = agent if issuer == agent.id else await self.resolve_document(issuer)
        public_key = _active_assertion_key(issuer_document, params.verification_method_id)
        if public_key is None:
            raise ValueError(
                f"{params.verification_method_id} is not an active Ed25519 assertionMethod key of {issuer}"
            )
        if await params.signer.get_public_key() != public_key:
            raise ValueError(f"The signer does not hold {params.verification_method_id}")
        agent_metadata = (
            dict(params.agent_metadata)
            if params.agent_metadata is not None
            else agent.agent_metadata.model_dump(by_alias=True, exclude_none=True)
        )
        problem = agent_metadata_problem(agent_metadata)
        if problem is not None:
            raise TypeError(problem)
        now = self._now_iso_timestamp()
        valid_from = params.valid_from if params.valid_from is not None else now
        valid_from_millis = parse_rfc3339_millis(valid_from)
        if valid_from_millis is None:
            raise TypeError("valid_from must be an RFC 3339 date-time")
        if params.valid_until is not None:
            valid_until_millis = parse_rfc3339_millis(params.valid_until)
            if valid_until_millis is None or valid_until_millis < valid_from_millis:
                raise TypeError("valid_until must be an RFC 3339 date-time not earlier than valid_from")
        if params.credential_id is not None and not params.credential_id:
            raise TypeError("credential_id must be a non-empty string")
        unsigned = build_unsigned_agent_metadata_credential(
            issuer=issuer,
            agent_did=agent.id,
            agent_metadata=agent_metadata,
            valid_from=valid_from,
            valid_until=params.valid_until,
            credential_id=params.credential_id,
        )

        async def sign(hash_data: bytes) -> bytes:
            return bytes.fromhex(await params.signer.sign(hash_data))

        proof = await create_eddsa_jcs_2022_proof(
            unsigned,
            created=now,
            verification_method=params.verification_method_id,
            proof_purpose="assertionMethod",
            sign=sign,
        )
        credential = {**unsigned, "proof": proof}
        if not verify_eddsa_jcs_2022_proof(credential, public_key):
            raise ValueError("The signer produced a signature that does not match its public key")
        return credential

    async def verify_agent_metadata_credential(
        self, credential: object, *, expected_agent_did: str | None = None
    ) -> VerifyAgentMetadataCredentialResult:
        """Verify an ``AgentMetadataCredential`` (RFC-001 §4.4).

        Checks its form and validity period, that the agent DID resolves, is not deactivated and is bound to its
        controller (RFC-001 §6.6 item 7), that ``issuer`` is that controller, and the ``eddsa-jcs-2022`` proof by an
        active ``assertionMethod`` key of the issuer. Never raises for a bad credential: test ``result.ok``. The
        metadata in an accepted credential is the controller's assertion, not evidence of what runs.
        """
        try:
            form = check_agent_metadata_credential_form(credential, int(self._clock().timestamp() * 1000))
        except Exception:  # noqa: BLE001 - a value JCS cannot represent is a malformed credential
            return VerifyAgentMetadataCredentialResult(ok=False, reason="malformed_credential")
        if isinstance(form, str):
            return VerifyAgentMetadataCredentialResult(ok=False, reason=form)
        if expected_agent_did is not None and expected_agent_did != form.agent_did:
            return VerifyAgentMetadataCredentialResult(ok=False, reason="subject_mismatch")
        try:
            state = await self.resolve_did_webvh_state(form.agent_did)
        except Exception:
            return VerifyAgentMetadataCredentialResult(ok=False, reason="did_resolution_failed")
        if state is not None and state.deactivated:
            return VerifyAgentMetadataCredentialResult(ok=False, reason="did_deactivated")
        try:
            agent, controllers = await self._resolve_active_verification_chain(form.agent_did)
        except ControllerBindingError:
            return VerifyAgentMetadataCredentialResult(ok=False, reason="controller_not_bound")
        except Exception:
            return VerifyAgentMetadataCredentialResult(ok=False, reason="did_resolution_failed")
        if form.issuer != ((agent.controller or "").strip() or agent.id):
            return VerifyAgentMetadataCredentialResult(ok=False, reason="issuer_not_controller")
        issuer_document: AnyDidDocument
        if form.issuer == agent.id:
            issuer_document = agent
        elif controllers and controllers[0].id == form.issuer:
            issuer_document = controllers[0]
        else:
            try:
                issuer_document = await self.resolve_document(form.issuer)
            except Exception:
                return VerifyAgentMetadataCredentialResult(ok=False, reason="did_resolution_failed")
        public_key = _active_assertion_key(issuer_document, form.verification_method)
        if public_key is None:
            return VerifyAgentMetadataCredentialResult(ok=False, reason="key_not_authorized")
        if not verify_eddsa_jcs_2022_proof(credential, public_key):
            return VerifyAgentMetadataCredentialResult(ok=False, reason="signature_invalid")
        return VerifyAgentMetadataCredentialResult(
            ok=True,
            agent_did=form.agent_did,
            issuer=form.issuer,
            verification_method=form.verification_method,
            agent_metadata=form.agent_metadata,
            controllers=[document.id for document in controllers],
        )

    async def create_capability(
        self,
        *,
        invocation_target: str,
        controller: str,
        expires: str,
        verification_method_id: str,
        signer: AgentSigner,
        allowed_action: Sequence[str] | None = None,
        parent_capability: dict[str, Any] | None = None,
        root_target: str | None = None,
        capability_id: str | None = None,
    ) -> dict[str, Any]:
        """Delegate a capability (RFC-001 §6.7).

        Grants *controller* the authority to act on *invocation_target* until *expires*, signed with an
        ``eddsa-jcs-2022`` proof by a ``capabilityDelegation`` key of the delegator. Without *parent_capability* the
        delegator is a root controller of *root_target* (whether it is one is the verifier's configuration); with it,
        the delegator must be the parent's ``controller``, and the new capability may only narrow the parent's target,
        actions and expiry.
        """
        delegator = did_of_key_id(verification_method_id)
        if delegator is None:
            raise TypeError(f"verification_method_id must be a DID URL with a fragment: {verification_method_id!r}")
        target_problem = invocation_target_problem(invocation_target)
        if target_problem is not None:
            raise TypeError(target_problem)
        expires_millis = parse_rfc3339_millis(expires)
        if expires_millis is None:
            raise TypeError("expires must be an RFC 3339 date-time")
        if allowed_action is not None:
            actions = list(allowed_action)
            distinct = len(set(actions)) == len(actions)
            if not actions or any(not isinstance(a, str) or not a for a in actions) or not distinct:
                raise TypeError("allowed_action must be a non-empty list of distinct non-empty strings")
        new_id = capability_id if capability_id is not None else f"urn:uuid:{uuid.uuid4()}"
        parent_for_chain: dict[str, Any] | str
        if parent_capability is not None:
            parent = parent_capability
            if parent.get("controller") != delegator:
                raise ValueError(f"Only the parent's controller {parent.get('controller')} can delegate it")
            parent_expires = parse_rfc3339_millis(parent.get("expires"))
            parent_actions = parent.get("allowedAction")
            if (
                not target_within(invocation_target, str(parent.get("invocationTarget")))
                or (
                    parent_actions is not None
                    and allowed_action is not None
                    and not all(action in parent_actions for action in allowed_action)
                )
                or parent_expires is None
                or expires_millis > parent_expires
            ):
                raise ValueError("The capability must not widen the parent's target, actions or expiry")
            parent_id = str(parent["id"])
            parent_for_chain = parent
        else:
            root = root_target if root_target is not None else invocation_target
            root_problem = invocation_target_problem(root)
            if root_problem is not None:
                raise TypeError(root_problem)
            if not target_within(invocation_target, root):
                raise ValueError("invocation_target must be the root target or within it")
            parent_id = root_capability_id(root)
            parent_for_chain = parent_id
        delegator_document = await self.resolve_document(delegator)
        public_key = _active_key_under(delegator_document, verification_method_id, "capabilityDelegation")
        if public_key is None:
            raise ValueError(
                f"{verification_method_id} is not an active Ed25519 capabilityDelegation key of {delegator}"
            )
        if await signer.get_public_key() != public_key:
            raise ValueError(f"The signer does not hold {verification_method_id}")
        unsigned = build_unsigned_capability(
            capability_id=new_id,
            parent_capability=parent_id,
            invocation_target=invocation_target,
            controller=controller,
            expires=expires,
            allowed_action=allowed_action,
        )
        config: dict[str, Any] = {
            "type": DATA_INTEGRITY_PROOF_TYPE,
            "cryptosuite": EDDSA_JCS_2022_CRYPTOSUITE,
            "created": self._now_iso_timestamp(),
            "verificationMethod": verification_method_id,
            "proofPurpose": CAPABILITY_DELEGATION_PURPOSE,
            "capabilityChain": child_capability_chain(parent_for_chain),
            "@context": list(unsigned["@context"]),
        }
        signature = bytes.fromhex(await signer.sign(eddsa_jcs_2022_hash_data(unsigned, config)))
        capability = {**unsigned, "proof": {**config, "proofValue": encode_eddsa_proof_value(signature)}}
        if capability_form_problem(capability) is not None or not verify_eddsa_jcs_2022_proof(capability, public_key):
            raise ValueError("The signer produced a capability that does not verify")
        return capability

    async def verify_capability_chain(
        self,
        capability: object,
        *,
        root_controllers: dict[str, list[str]],
        max_chain_length: int | None = None,
    ) -> VerifyCapabilityChainResult:
        """Verify a delegated capability and its chain (RFC-001 §6.7).

        Form, chain structure, the root controller the verifier configured for the root target, attenuation at every
        link, validity period, and each proof by an active Ed25519 ``capabilityDelegation`` key of its delegator,
        resolved now. Never raises for a bad capability: test ``result.ok``.
        """
        checked = check_capability_chain(
            capability,
            root_controllers,
            int(self._clock().timestamp() * 1000),
            max_chain_length if max_chain_length is not None else DEFAULT_MAX_CAPABILITY_CHAIN_LENGTH,
        )
        if isinstance(checked, CapabilityChainRejection):
            return VerifyCapabilityChainResult(ok=False, reason=checked.reason, capability_id=checked.capability_id)
        delegators: list[str] = []
        for index, item in enumerate(checked.capabilities):
            delegator = did_of_key_id(item["proof"]["verificationMethod"])
            assert delegator is not None
            allowed = (
                delegator in checked.root_controllers
                if index == 0
                else checked.capabilities[index - 1]["controller"] == delegator
            )
            if not allowed:
                return VerifyCapabilityChainResult(ok=False, reason="delegator_mismatch", capability_id=item["id"])
            key_check = await self._delegation_key_check(delegator, item["proof"]["verificationMethod"])
            if isinstance(key_check, str):
                return VerifyCapabilityChainResult(ok=False, reason=key_check, capability_id=item["id"])
            if not verify_eddsa_jcs_2022_proof(item, key_check):
                return VerifyCapabilityChainResult(ok=False, reason="signature_invalid", capability_id=item["id"])
            delegators.append(delegator)
        leaf = checked.capabilities[-1]
        return VerifyCapabilityChainResult(
            ok=True,
            capability=leaf,
            controller=leaf["controller"],
            invocation_target=leaf["invocationTarget"],
            allowed_action=checked.allowed_action,
            root_id=checked.root_id,
            delegators=tuple(delegators),
        )

    async def _delegation_key_check(self, did: str, key_id: str) -> bytes | CapabilityRejection:
        """The delegation key *key_id* of *did*, resolved now, or why it cannot sign a delegation."""
        try:
            if did.startswith("did:webvh:"):
                state = await self.resolve_did_webvh_state(did)
                if state is not None and state.deactivated:
                    return "did_deactivated"
            document = await self.resolve_document(did)
        except Exception:  # noqa: BLE001 - a delegator that cannot be resolved fails closed
            return "did_resolution_failed"
        public_key = _active_key_under(document, key_id, "capabilityDelegation")
        if public_key is not None:
            return public_key
        elsewhere = any(
            relationship != "capabilityDelegation" and _active_key_under(document, key_id, relationship) is not None
            for relationship in DID_VERIFICATION_RELATIONSHIPS
        )
        return "key_purpose_violation" if elsewhere else "key_not_authorized"

    async def verify_http_capability_invocation(
        self, params: VerifyHttpCapabilityInvocationParams
    ) -> VerifyHttpCapabilityInvocationResult:
        """Verify a request that invokes a capability (RFC-001 §6.5, §6.7).

        The request profile of :meth:`verify_http_request_signature_detailed`, with the signing key under
        ``capabilityInvocation`` instead of ``assertionMethod``; the signature must cover
        ``"agent-did-capability";key="<label>"``; the request's agent DID must be the capability's ``controller``, its
        URL within the target and its method allowed; then the capability chain (:meth:`verify_capability_chain`).
        The nonce is recorded only when everything passes.
        """
        request = VerifyHttpRequestSignatureParams.model_validate(
            {name: getattr(params, name) for name in VerifyHttpRequestSignatureParams.model_fields}
        )
        headers = {key.lower(): value for key, value in params.headers.items()}
        field_value = headers.get(AGENT_DID_CAPABILITY_HTTP_HEADER.lower())
        method = params.method.upper()
        request_target = params.url.split("?", 1)[0]
        client = self

        class _Invocation:
            relationship: VerificationRelationship = REQUIRED_RELATIONSHIP_BY_ARTIFACT["invocation"]

            def before_signature(self, label: str, signature_input: SignatureInput, agent_did: str) -> object:
                covered = any(
                    isinstance(component, KeyedComponent)
                    and component.name == "agent-did-capability"
                    and component.key == label
                    for component in signature_input.components
                )
                if not covered or field_value is None:
                    return ExtensionRejection("capability_missing")
                if len(field_value.encode("utf-8")) > MAX_CAPABILITY_HEADER_BYTES:
                    return ExtensionRejection("capability_too_large")
                parsed = parse_capability_header(field_value, label)
                if parsed is CAPABILITY_HEADER_MISSING:
                    return ExtensionRejection("capability_missing")
                if not isinstance(parsed, dict):
                    return ExtensionRejection("malformed_capability")
                cap_id = parsed.get("id") if isinstance(parsed.get("id"), str) else None
                if parsed.get("controller") != agent_did:
                    return ExtensionRejection("invoker_not_controller", cap_id)
                target = parsed.get("invocationTarget")
                if not isinstance(target, str) or not target_within(request_target, target):
                    return ExtensionRejection("target_mismatch", cap_id)
                return parsed

            async def after_signature(self, state: Any) -> object:
                chain = await client.verify_capability_chain(
                    state, root_controllers=params.root_controllers, max_chain_length=params.max_chain_length
                )
                if not chain.ok:
                    return ExtensionRejection(str(chain.reason), chain.capability_id)
                if not action_allowed(method, chain.allowed_action):
                    assert chain.capability is not None
                    return ExtensionRejection("action_not_allowed", chain.capability["id"])
                return chain

        result = await verify_agent_did_http_request_with(
            request,
            verify_signature=self._check_signature,
            nonce_store=self._nonce_store,
            now=self._clock(),
            extension=_Invocation(),
        )
        if isinstance(result, ExtensionRejection):
            return VerifyHttpCapabilityInvocationResult(
                ok=False,
                reason=result.reason,  # type: ignore[arg-type]
                capability_id=result.capability_id,
            )
        chain = result.extra
        assert isinstance(chain, VerifyCapabilityChainResult)
        return VerifyHttpCapabilityInvocationResult(
            ok=True,
            did=result.did,
            key_id=result.key_id,
            controllers=result.controllers,
            capability=chain.capability,
            allowed_action=chain.allowed_action,
            root_id=chain.root_id,
            delegators=chain.delegators,
        )

    async def verify_client_assertion(
        self,
        assertion: str,
        *,
        issuer: str,
        client_id: str,
        did: str,
        max_clock_skew_seconds: int = 30,
        nonce_store: NonceStore | None = None,
    ) -> VerifyClientAssertionResult:
        """Verify a JWT client assertion (``private_key_jwt``) against the agent DID registered for the client
        (RFC-001 §6.8).

        JWS form, ``alg`` (``EdDSA`` or ``Ed25519``), ``typ`` (absent or ``client-authentication+jwt``), ``kid`` a DID
        URL of *did*, ``iss`` = ``sub`` = *client_id*, ``aud`` exactly *issuer*, lifetime at most 300 s and times within
        the clock skew, then the signature by an active Ed25519 ``authentication`` key of the resolved DID, and
        finally ``jti`` in the nonce store. For an authorization server or MCP server that knows Agent-DID. Never
        raises: test ``result.ok``.
        """
        parsed = parse_client_assertion(
            assertion,
            client_id=client_id,
            issuer=issuer,
            did=did,
            now_seconds=int(self._clock().timestamp()),
            max_clock_skew_seconds=max_clock_skew_seconds,
        )
        if isinstance(parsed, str):
            return VerifyClientAssertionResult(ok=False, reason=parsed)
        check = await self._check_signature(
            did,
            parsed.signing_input,
            parsed.signature.hex(),
            parsed.key_id,
            REQUIRED_RELATIONSHIP_BY_ARTIFACT["authentication"],
        )
        if check.outcome != "valid":
            reason: ClientAssertionRejection = (
                "signature_invalid" if check.outcome == "invalid" else check.outcome
            )
            return VerifyClientAssertionResult(ok=False, reason=reason)
        store = nonce_store if nonce_store is not None else self._nonce_store
        if not await store.check_and_store(
            f"client-assertion {client_id} {parsed.jti}", parsed.expires_at + max_clock_skew_seconds
        ):
            return VerifyClientAssertionResult(ok=False, reason="jti_replayed")
        return VerifyClientAssertionResult(
            ok=True,
            did=did,
            key_id=parsed.key_id,
            client_id=client_id,
            jti=parsed.jti,
            expires_at=parsed.expires_at,
            controllers=list(check.controllers),
        )

    def evict_cached_resolution(self, did: str) -> None:
        """Drop the resolver's cached resolution of *did*, so the next verification fetches and verifies it again (for a
        check that must not rely on a cached state, such as an irreversible action). A no-op with a resolver that does
        not cache (no ``evict`` method)."""
        evict = getattr(self._resolver, "evict", None)
        if callable(evict):
            evict(did)

    async def resolve(self, did: str) -> AgentDIDDocument:
        """The Agent-DID document of *did*. Raises when the DID resolves to a DID Core document that is not an
        Agent-DID document (a plain controller: use :meth:`resolve_document`)."""
        if did.startswith("did:webvh:"):
            return _agent_document(await self.resolve_document(did), did)

        is_revoked = await self._registry.is_revoked(did)
        if is_revoked:
            raise ValueError(f"DID is revoked: {did}")
        return await self._resolver.resolve(did)

    async def resolve_document(self, did: str) -> AnyDidDocument:
        """The DID Core document of *did*. A did:webvh DID may resolve to any DID Core document (a controller,
        RFC-001 §4.2.1), with the same log verification and revocation rules as :meth:`resolve`; any other DID is
        answered by :meth:`resolve`, so its document must be an Agent-DID document."""
        if did.startswith("did:webvh:"):
            # For did:webvh the verified log is the only source of revocation state: a DID is
            # revoked only by a controller-signed deactivation entry. The registry record is a
            # derived index and is not consulted.
            #
            # A DID created or changed in this process (its controller signer is retained) is
            # authoritative here: its local log is served without asking the resolver, so it does
            # not stop resolving when a resolver cache entry expires or its host is down. Any other
            # DID is resolved (and its log verified) by the configured resolver, which treats an
            # imported log as a cache and fails closed when it cannot refresh it.
            state = await self._did_webvh_state(did)
            if state is not None and state[0]:
                raise ValueError(f"DID is revoked: {did}")
            if state is not None and did in self._did_webvh_signer_store:
                return state[1].model_copy(deep=True)
            resolve_document = getattr(self._resolver, "resolve_document", None)
            if callable(resolve_document):
                document: AnyDidDocument = await resolve_document(did)
                return document
            return await self._resolver.resolve(did)
        return await self.resolve(did)

    async def _did_webvh_state(self, did: str) -> tuple[bool, AnyDidDocument] | None:
        """State of the locally stored did:webvh log: ``(deactivated, latest document)``.

        The log is verified (SCID, hash chain, controller proofs) before its state is
        trusted; a log that fails verification is an error, never "not revoked". Returns
        None when no log is stored for the DID.
        """
        log = self._did_webvh_log_store.get(did)
        if log is None:
            return None
        witness_file = self._did_webvh_witness_store.get(did)
        cached = self._did_webvh_state_cache.get(did)
        if cached is not None and cached[0] == log and cached[1] == witness_file:
            return cached[2], cached[3]
        resolved = await resolve_did_webvh_log(log, did=did, witness_file=witness_file)
        document = parse_did_document(resolved.state)
        self._did_webvh_state_cache[did] = (log, witness_file, resolved.metadata.deactivated, document)
        return resolved.metadata.deactivated, document

    async def resolve_controller_chain(self, did: str, max_depth: int = 8) -> list[AnyDidDocument]:
        if max_depth < 1:
            raise ValueError("max_depth must be a positive integer")

        chain: list[AnyDidDocument] = []
        visited: set[str] = set()
        current_did = did

        while True:
            if current_did in visited:
                raise ValueError(f"Controller chain cycle detected at DID: {current_did}")

            if len(chain) >= max_depth:
                raise ValueError(f"Controller chain exceeded max depth of {max_depth} starting from DID: {did}")

            visited.add(current_did)
            current = await self.resolve_document(current_did)
            chain.append(current)

            # A list of controllers is not followed in 1.0: the chain fails closed instead of skipping them
            # (RFC-001 §4.2.1)
            if isinstance(current.controller, list):
                raise ValueError(f"Controller chain cannot follow a list of controllers at DID: {current_did}")
            controller_did = current.controller.strip() if current.controller else ""
            if not controller_did or controller_did == current_did or not controller_did.startswith("did:"):
                return chain

            current_did = controller_did

    @_one_operation_per_did
    async def revoke_did(self, did: str, *, controller_signer: AgentSigner | None = None) -> None:
        """Revoke a DID.

        For did:webvh DIDs this appends a controller-signed deactivation entry
        (``deactivated: true``) to the DID's log, which is what makes the DID revoked; the
        registry record is then updated as a derived index. Other DID methods are revoked in
        the registry.
        """
        existing = await self.resolve(did)
        if did.startswith("did:webvh:"):
            log, signer = self._require_did_webvh_lifecycle(did, controller_signer)
            deactivated = await deactivate_did_webvh_log(
                log=log,
                signer=signer,
                witness_file=self._did_webvh_witness_store.get(did),
                collect_witness_proofs=self._collect_witness_proofs,
            )
            self._store_did_webvh_log(did, deactivated)
        await self._registry.revoke(did)
        self._append_history(existing, "revoked")

    @_one_operation_per_did
    async def update_did_document(
        self,
        did: str,
        patch: UpdateAgentDocumentParams,
        *,
        controller_signer: AgentSigner | None = None,
    ) -> AgentDIDDocument:
        assert_update_patch(did, patch)

        existing = await self.resolve(did)
        updated = build_updated_document(existing, patch, self._next_timestamp(existing.updated))

        if did.startswith("did:webvh:"):
            updated = await self._append_did_webvh_entry(did, updated, controller_signer)

        self._resolver.register_document(updated)
        await self._registry.set_document_reference(did, compute_document_reference(updated))
        self._append_history(updated, "updated")
        return updated

    @_one_operation_per_did
    async def retire_verification_method(
        self,
        did: str,
        key_id: str,
        *,
        controller_signer: AgentSigner | None = None,
        emergency: bool = False,
    ) -> AgentDIDDocument:
        """Retire one key of *did* and leave the others as they are (RFC-001 §6.6): the key gets a ``deactivated``
        time and leaves every verification relationship. A planned retirement ends the overlap of a rotation started
        with :meth:`add_verification_method`; signatures under the key are then rejected (``rotation_window_closed`` in
        the composition contract). With *emergency* the key also gets ``revoked`` and is never accepted again,
        whatever time a signature states (``emergency_revoked``); an already retired key can still be revoked this way.

        Refuses an unknown key, a key already retired (without *emergency*) or revoked, and the last
        ``authentication`` or ``assertionMethod`` key: use :meth:`rotate_verification_method` or :meth:`revoke_did`.
        """
        existing = await self.resolve(did)
        was_active = any(vm.id == key_id and not vm.deactivated for vm in existing.verification_method)
        updated = build_retired_key_document(existing, key_id, self._next_timestamp(existing.updated), emergency)

        if did.startswith("did:webvh:"):
            updated = await self._append_did_webvh_entry(did, updated, controller_signer)

        self._resolver.register_document(updated)
        await self._registry.set_document_reference(did, compute_document_reference(updated))
        self._append_history(updated, "rotated-key" if was_active else "updated")
        return updated

    @_one_operation_per_did
    async def add_verification_method(
        self,
        did: str,
        *,
        controller_signer: AgentSigner | None = None,
        signer: AgentSigner | None = None,
        relationships: list[SigningVerificationPurpose] | None = None,
    ) -> AddVerificationMethodResult:
        """Add a key to the document of *did* without retiring any other key, listed under *relationships* (default:
        ``capabilityInvocation``). It is the first step of rotating the key that endorses the agents a DID controls
        without unbinding them: add the new key, give each agent an entry signed by the new key, then retire the old
        one with :meth:`rotate_verification_method` (RFC-001 §6.6 item 7). With *signer* (for example a KMS or HSM
        key) its public key becomes the new verification method and ``agent_private_key`` in the result is empty."""
        existing = await self.resolve(did)
        updated, vm_id, private_key_hex = build_added_key_document(
            did,
            existing,
            self._next_timestamp(existing.updated),
            relationships if relationships is not None else ["capabilityInvocation"],
            await signer.get_public_key() if signer is not None else None,
        )

        if did.startswith("did:webvh:"):
            updated = await self._append_did_webvh_entry(did, updated, controller_signer)

        self._resolver.register_document(updated)
        await self._registry.set_document_reference(did, compute_document_reference(updated))
        self._append_history(updated, "updated")
        return AddVerificationMethodResult(
            document=updated, verification_method_id=vm_id, agent_private_key=private_key_hex, signer=signer
        )

    @_one_operation_per_did
    async def rotate_verification_method(
        self,
        did: str,
        *,
        controller_signer: AgentSigner | None = None,
        signer: AgentSigner | None = None,
        emergency: bool = False,
    ) -> RotateVerificationMethodResult:
        """Rotate the agent key. With *signer* (for example a KMS or HSM key) its public key becomes the new
        verification method and ``agent_private_key`` in the result is empty; otherwise a local key is generated.
        With *emergency* (the old keys may be compromised) every retired key also gets ``revoked``, so no signature
        under it is accepted again, whatever time it states."""
        existing = await self.resolve(did)
        updated, vm_id, private_key_hex = build_rotated_document(
            did,
            existing,
            self._next_timestamp(existing.updated),
            await signer.get_public_key() if signer is not None else None,
            emergency,
        )

        if did.startswith("did:webvh:"):
            updated = await self._append_did_webvh_entry(did, updated, controller_signer)

        self._resolver.register_document(updated)
        await self._registry.set_document_reference(did, compute_document_reference(updated))
        self._append_history(updated, "rotated-key")

        return RotateVerificationMethodResult(
            document=updated, verification_method_id=vm_id, agent_private_key=private_key_hex, signer=signer
        )

    def get_document_history(self, did: str) -> list[AgentDocumentHistoryEntry]:
        entries = self._history_store.get(did, [])
        return [e.model_copy(deep=True) for e in entries]

    def export_did_webvh_history(self, did: str) -> str:
        """Return the DID's did:webvh v1.0 log (``did.jsonl``) as created or imported in this process."""
        if not did.startswith("did:webvh:"):
            raise ValueError(f"did:webvh DID is required for history export: {did}")
        log = self._did_webvh_log_store.get(did)
        if log is None:
            raise ValueError(f"No document history found for DID: {did}")
        return log

    async def import_did_webvh_history(self, did_log: str, witness_file: str | None = None) -> AgentDIDDocument:
        """Verify a did:webvh v1.0 log and load it into this process.

        Checks the SCID, hash chain and controller-signed proofs, then loads the latest
        document, registry record and document history. Changing the DID afterwards requires
        its controller signer (``controller_signer=``).

        The imported log is a copy of what the log host serves. With a resolver that fetches logs, it is not cached
        as the DID's current document: the next resolution fetches the host's log and the longer of the two wins.
        *witness_file* is the log's ``did-witness.json``, required when it has witnessed entries (ADR-007).
        """
        resolved = await resolve_did_webvh_log(did_log, witness_file=witness_file)
        async with self._did_locks.setdefault(resolved.did, asyncio.Lock()):
            return await self._import_resolved_did_webvh_log(resolved)

    async def _import_resolved_did_webvh_log(self, resolved: DidWebvhLogResult) -> AgentDIDDocument:
        did = resolved.did
        latest = AgentDIDDocument.model_validate(resolved.state)
        document_ref = compute_document_reference(latest)

        # A log can only replace the stored one by extending it: an older prefix (it would reinstate
        # a revoked DID or an earlier key set) or a different history is rejected. The same log is a no-op.
        stored = self._did_webvh_log_store.get(did)
        relation = "extends" if stored is None else compare_did_webvh_logs(stored, resolved.log)
        if relation in ("prefix", "diverged"):
            raise DidWebvhError(
                "invalidInput",
                f"did:webvh log for {did} does not extend the log already stored in this client "
                f"({'it is older' if relation == 'prefix' else 'it diverges'})",
            )
        if relation == "extends":
            self._history_store[did] = history_from_did_webvh_log(resolved.log)
            self._store_did_webvh_log(did, resolved)
            # The retained controller signer stays only while its key is still one of the log's updateKeys.
            signer = self._did_webvh_signer_store.get(did)
            if signer is not None and await did_webvh_update_key_for(signer) not in resolved.metadata.update_keys:
                del self._did_webvh_signer_store[did]

        # An imported log is a copy of what the log host serves, not an authority: a resolver that fetches logs must
        # not answer from it as a fresh entry, or an older prefix would be served until the entry expires. Dropping
        # its entry makes the next resolution fetch, and the longer of the fetched and the imported log wins at once.
        # A DID whose controller signer this client retains (created or changed here) is registered as before, and so
        # is any DID when the resolver cannot fetch logs (then the imported log is all there is: see the README).
        evict = getattr(self._resolver, "evict", None)
        fetches_logs = getattr(self._resolver, "resolve_did_webvh_log", None) is not None
        if did not in self._did_webvh_signer_store and fetches_logs and evict is not None:
            evict(did)
        else:
            self._resolver.register_document(latest)
        await self._registry.register(latest.id, latest.controller, document_ref)
        await self._registry.set_document_reference(latest.id, document_ref)
        if resolved.metadata.deactivated:
            await self._registry.revoke(did)

        return latest

    def save_did_webvh_history_to_file(
        self, did: str, file_path: str | Path, witness_file_path: str | Path | None = None
    ) -> Path:
        """Write the DID's ``did.jsonl`` to *file_path*. A DID with witnessed entries also needs *witness_file_path* for
        its ``did-witness.json`` (written first, as when publishing)."""
        path = Path(file_path)
        log = self.export_did_webvh_history(did)
        witness_file = self._did_webvh_witness_store.get(did)
        if witness_file is not None:
            if witness_file_path is None:
                raise ValueError(f"{did} has witnessed entries: pass witness_file_path for its did-witness.json")
            Path(witness_file_path).write_text(witness_file, encoding="utf-8")
        path.write_text(log, encoding="utf-8")
        return path

    async def load_did_webvh_history_from_file(
        self, file_path: str | Path, witness_file_path: str | Path | None = None
    ) -> AgentDIDDocument:
        """Import a ``did.jsonl`` file, with its ``did-witness.json`` when the log has witnessed entries."""
        path = Path(file_path)
        witness_file = Path(witness_file_path).read_text(encoding="utf-8") if witness_file_path is not None else None
        return await self.import_did_webvh_history(path.read_text(encoding="utf-8"), witness_file)

    async def persist_did_webvh_history_to_source(
        self,
        did: str,
        document_ref: str,
        source: DIDDocumentSource,
        witness_ref: str | None = None,
    ) -> None:
        """Store the DID's log in *source* under *document_ref*. A DID with witnessed entries also needs *witness_ref*,
        where its ``did-witness.json`` is stored first."""
        store = getattr(source, "store_did_log_by_reference", None)
        if store is None:
            raise ValueError("DIDDocumentSource does not support did:webvh log persistence")
        log = self.export_did_webvh_history(did)
        witness_file = self._did_webvh_witness_store.get(did)
        if witness_file is not None:
            store_witness = getattr(source, "store_did_witness_file_by_reference", None)
            if witness_ref is None or store_witness is None:
                raise ValueError(
                    f"{did} has witnessed entries: pass witness_ref and a source that stores did-witness.json"
                )
            await store_witness(witness_ref, witness_file)

        await store(document_ref, log)

    async def restore_did_webvh_history_from_source(
        self,
        document_ref: str,
        source: DIDDocumentSource,
        witness_ref: str | None = None,
    ) -> AgentDIDDocument:
        """Import a log from *source*, with its ``did-witness.json`` from *witness_ref* when given."""
        loader = getattr(source, "get_did_log_by_reference", None)
        if loader is None:
            raise ValueError("DIDDocumentSource does not support did:webvh log retrieval")

        did_log = await loader(document_ref)
        if not did_log:
            raise ValueError(f"did:webvh DID log not found for reference: {document_ref}")
        witness_file: str | None = None
        if witness_ref is not None:
            load_witness = getattr(source, "get_did_witness_file_by_reference", None)
            if load_witness is None:
                raise ValueError("DIDDocumentSource does not support did:webvh witness file retrieval")
            witness_file = await load_witness(witness_ref)
            if witness_file is None:
                raise ValueError(f"did:webvh witness file not found for reference: {witness_ref}")

        return await self.import_did_webvh_history(did_log, witness_file)

    # ------------------------------------------------------------------
    # Configuration class methods
    # ------------------------------------------------------------------

    def set_resolver(self, resolver: DIDResolver) -> None:
        self._resolver = resolver

    def set_registry(self, registry: AgentRegistry) -> None:
        self._registry = registry

    def use_production_resolver(self, config: ProductionResolverProfileConfig) -> None:
        self._resolver = UniversalResolverClient(
            UniversalResolverConfig(
                registry=config.registry,
                document_source=config.document_source,
                wba_document_source=config.wba_document_source,
                webvh_document_source=config.webvh_document_source,
                fallback_resolver=self._resolver,
                did_webvh_local_log=self._did_webvh_log_store.get,
                did_webvh_local_witness_file=self._did_webvh_witness_store.get,
                cache_ttl_ms=config.cache_ttl_ms or 60_000,
                max_cache_entries=(
                    DEFAULT_RESOLVER_MAX_CACHE_ENTRIES if config.max_cache_entries is None else config.max_cache_entries
                ),
                on_resolution_event=config.on_resolution_event,  # type: ignore[arg-type]
                unverified_document_ref_schemes=config.unverified_document_ref_schemes,
                resolution_limits=config.resolution_limits,
            )
        )

    def use_production_resolver_from_http(self, config: ProductionHttpResolverProfileConfig) -> None:
        source = HttpDIDDocumentSource(
            HttpDIDDocumentSourceConfig(
                reference_to_url=config.reference_to_url,
                reference_to_urls=config.reference_to_urls,
                http_client=config.http_client,
                ipfs_gateways=config.ipfs_gateways,
                http_security=config.http_security,
            )
        )
        webvh_source = WebvhDIDDocumentSource(
            WebvhDIDDocumentSourceConfig(
                reference_to_url=config.reference_to_url,
                reference_to_urls=config.reference_to_urls,
                http_client=config.http_client,
                http_security=config.http_security,
            )
        )
        self.use_production_resolver(
            ProductionResolverProfileConfig(
                registry=config.registry,
                document_source=source,
                wba_document_source=source,
                webvh_document_source=webvh_source,
                cache_ttl_ms=config.cache_ttl_ms,
                max_cache_entries=config.max_cache_entries,
                on_resolution_event=config.on_resolution_event,
                unverified_document_ref_schemes=config.unverified_document_ref_schemes,
                resolution_limits=config.resolution_limits,
            )
        )

    def use_production_resolver_from_json_rpc(self, config: ProductionJsonRpcResolverProfileConfig) -> None:
        source = JsonRpcDIDDocumentSource(
            JsonRpcDIDDocumentSourceConfig(
                endpoint=config.endpoint,
                endpoints=config.endpoints,
                method=config.method or "agent_resolveDocumentRef",
                build_params=config.build_params,
                headers=config.headers,
                http_client=config.http_client,
                http_security=config.http_security,
            )
        )
        self.use_production_resolver(
            ProductionResolverProfileConfig(
                registry=config.registry,
                document_source=source,
                cache_ttl_ms=config.cache_ttl_ms,
                max_cache_entries=config.max_cache_entries,
                on_resolution_event=config.on_resolution_event,
                resolution_limits=config.resolution_limits,
            )
        )

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _next_timestamp(self, previous_timestamp: str | None = None) -> str:
        return next_document_timestamp(self._now_iso_timestamp(), previous_timestamp)

    def _append_history(self, document: AgentDIDDocument, action: AgentDocumentHistoryAction) -> None:
        did = document.id
        current = self._history_store.get(did, [])
        entry = AgentDocumentHistoryEntry(
            did=did,
            revision=len(current) + 1,
            action=action,
            timestamp=self._now_iso_timestamp(),
            version=document.agent_metadata.version,
            document_ref=compute_document_reference(document),
        )
        self._history_store[did] = [*current, entry]


def _active_assertion_key(document: AnyDidDocument, key_id: str) -> bytes | None:
    """The raw public key of *key_id* when it is an active Ed25519 ``assertionMethod`` key of *document*."""
    return _active_key_under(document, key_id, "assertionMethod")


def _active_key_under(document: AnyDidDocument, key_id: str, relationship: VerificationRelationship) -> bytes | None:
    """The raw public key of *key_id* when it is an active Ed25519 key listed under *relationship* of *document*."""
    method = next(
        (candidate for candidate in relationship_methods(document, relationship) if candidate.id == key_id), None
    )
    return None if method is None else active_ed25519_public_key(method)


def _agent_document(document: AnyDidDocument, did: str) -> AgentDIDDocument:
    """*document* as an Agent-DID document; raises ``ValueError`` for a DID Core document that is not one (a plain
    controller)."""
    if isinstance(document, AgentDIDDocument):
        return document
    try:
        return AgentDIDDocument.model_validate(document.model_dump(by_alias=True, exclude_none=True))
    except ValueError as exc:
        raise ValueError(f"The document of {did} is not an Agent-DID document: {exc}") from exc
