"""AgentIdentity — main class for creating, signing, resolving and revoking Agent-DIDs."""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import httpx
from nacl.signing import SigningKey

from ..crypto.hash import create_metadata_commitment, generate_commitment_salt
from ..crypto.multibase import did_key_from_public_key
from ..http_signatures.verify_request import SignatureCheckOutcome, verify_agent_did_http_request
from ..lifecycle.documents import (
    assert_update_patch,
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
    ResolverResolutionEvent,
    UniversalResolverConfig,
)
from ..resolver.universal import UniversalResolverClient
from ..resolver.webvh_source import WebvhDIDDocumentSource, WebvhDIDDocumentSourceConfig
from ..verification.key_at_time import check_did_webvh_key_at_time, signature_result_for_key
from ..verification.signature import verify_with_active_keys
from ..webvh.adapter import (
    DidWebvhError,
    create_did_webvh_log,
    deactivate_did_webvh_log,
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
from .http_security import HttpTargetValidationOptions
from .identity_composition import REQUIRED_RELATIONSHIP_BY_ARTIFACT, IdentityCompositionError
from .nonce_store import InMemoryNonceStore, NonceStore
from .signer import AgentSigner, LocalKeySigner
from .time_utils import normalize_timestamp_to_iso
from .types import (
    AgentDIDDocument,
    AgentDocumentHistoryAction,
    AgentDocumentHistoryEntry,
    CreateAgentParams,
    CreateAgentResult,
    CreateDidWebvhOptions,
    DidWebvhControllerKeys,
    KeyAtTimeResult,
    MetadataCommitmentSalts,
    RotateVerificationMethodResult,
    UpdateAgentDocumentParams,
    VerificationRelationship,
    VerifyHttpRequestSignatureParams,
    VerifyHttpRequestSignatureResult,
    VerifySignatureAtTimeResult,
)


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


class AgentDidClient:
    """Owns all mutable identity state (resolver, registry, replay store, document history,
    did:webvh logs and controller signers). Each client is an isolated instance: two clients
    never share state. ``AgentIdentity``'s static API is a facade over a default client."""

    def __init__(self, options: AgentDidClientOptions | None = None) -> None:
        opts = options or AgentDidClientOptions()
        self._resolver: DIDResolver = opts.resolver or InMemoryDIDResolver()
        self._registry: AgentRegistry = opts.registry or InMemoryAgentRegistry()
        self._nonce_store: NonceStore = opts.nonce_store or InMemoryNonceStore()
        self._clock: Callable[[], datetime] = opts.clock or (lambda: datetime.now(timezone.utc))
        self._webvh_domain: str = opts.webvh_domain
        self._history_store: dict[str, list[AgentDocumentHistoryEntry]] = {}
        # did:webvh v1.0 logs (did.jsonl) of the DIDs created or imported in this process.
        self._did_webvh_log_store: dict[str, str] = {}
        # Deactivation state derived from the verified log, keyed by DID and tied to the exact
        # log text it was computed from. It is recomputed whenever the stored log changes.
        self._did_webvh_state_cache: dict[str, tuple[str, bool]] = {}
        # Controller signers (did:webvh updateKeys) retained for DIDs created in this process.
        self._did_webvh_signer_store: dict[str, AgentSigner] = {}
        # Local bootstrap controllers, keyed by lowercase controller wallet address.
        self._bootstrap_controllers: dict[str, tuple[str, AgentSigner]] = {}
        self._bootstrap_controller_locks: dict[str, asyncio.Lock] = {}

    def _now_iso_timestamp(self) -> str:
        return normalize_timestamp_to_iso(self._clock().isoformat())  # type: ignore[return-value]

    async def create_agent(self, controller_signer: AgentSigner, params: CreateAgentParams) -> CreateAgentResult:
        """Create a new Agent-DID document (passport) in this client's state."""
        # Reject an unsupported relationship before generating keys or touching any store
        additional_relationship_entries(params.additional_verification_relationships, "")
        timestamp = self._now_iso_timestamp()
        # The creator is identified by its Ed25519 key, never by an EVM address
        controller_key_did = did_key_from_public_key(await controller_signer.get_public_key())

        # Commit to the sensitive metadata with salted HMACs so it cannot be guessed by dictionary
        metadata_commitment_salts = MetadataCommitmentSalts(
            core_model=params.core_model_salt or generate_commitment_salt(),
            system_prompt=params.system_prompt_salt or generate_commitment_salt(),
        )
        agent_metadata: dict[str, Any] = {
            "name": params.name,
            "description": params.description,
            "version": params.version or "1.0.0",
            "coreModelHash": create_metadata_commitment(params.core_model, metadata_commitment_salts.core_model),
            "systemPromptHash": create_metadata_commitment(
                params.system_prompt, metadata_commitment_salts.system_prompt
            ),
            "capabilities": params.capabilities or [],
            "memberOf": params.member_of,
        }

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
        if params.webvh is not None and params.webvh.domain.strip():
            options = self._require_webvh_create_options(params)
            domain = options.domain.strip()
            path_segments = list(options.path_segments or [])
            controller_did = options.controller_did.strip()
            controller_signer = options.controller_signer
            next_update_keys = options.next_update_keys
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
        )
        document = AgentDIDDocument.model_validate(created.state)
        self._did_webvh_log_store[document.id] = created.log
        self._did_webvh_signer_store[document.id] = controller_signer

        self._resolver.register_document(document)
        await self._registry.register(document.id, document.controller, compute_document_reference(document))
        self._append_history(document, "created")

        return CreateAgentResult(
            document=document,
            agent_private_key=private_key_hex,
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
        self._did_webvh_log_store[document.id] = created.log
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
            log=log, signer=signer, document=document.model_dump(by_alias=True, exclude_none=True)
        )
        self._did_webvh_log_store[did] = updated.log
        # With pre-rotation active the signer was a committed key and is now the active controller key.
        if await did_webvh_update_key_for(signer) in updated.metadata.update_keys:
            self._did_webvh_signer_store[did] = signer
        return AgentDIDDocument.model_validate(updated.state)

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
        current = await resolve_did_webvh_log(log, did=did)
        signer = (
            new_controller_signer
            if current.metadata.next_key_hashes
            else controller_signer or self._did_webvh_signer_store.get(did)
        )
        if signer is None:
            raise ValueError(f"A controller signer is required to change {did}: pass controller_signer")
        new_key = await did_webvh_update_key_for(new_controller_signer)
        updated = await update_did_webvh_log(
            log=log, signer=signer, update_keys=[new_key], next_update_keys=next_update_keys
        )
        self._did_webvh_log_store[did] = updated.log
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
        resolved = await resolve_did_webvh_log(log, did=did)
        return DidWebvhControllerKeys(
            update_keys=list(resolved.metadata.update_keys),
            next_key_hashes=list(resolved.metadata.next_key_hashes),
        )

    async def _resolve_active_verification_chain(self, did: str) -> list[AgentDIDDocument]:
        chain = await self.resolve_controller_chain(did) if did.startswith("did:webvh:") else [await self.resolve(did)]
        if any(not self._has_active_verification_method(document) for document in chain):
            raise ValueError(f"DID is not active: {did}")
        return chain

    @staticmethod
    def _has_active_verification_method(document: AgentDIDDocument) -> bool:
        return any(method.public_key_multibase and not method.deactivated for method in document.verification_method)

    # ------------------------------------------------------------------
    # Class methods — verification & resolution
    # ------------------------------------------------------------------

    async def verify_http_request_signature(self, params: VerifyHttpRequestSignatureParams) -> bool:
        """Verify an Agent-DID RFC 9421 HTTP Message Signature.

        Requires the Agent-DID profile (covered components, ``tag="agent-did"``, ``alg="ed25519"``,
        ``created``, ``expires``, ``nonce``, a ``keyid`` under the ``Signature-Agent`` DID), a matching
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

    async def _check_signature(
        self,
        did: str,
        payload: str,
        signature: str,
        key_id: str,
        required_purpose: VerificationRelationship,
    ) -> SignatureCheckOutcome:
        """``verify_signature`` that tells apart the ways a verification can fail."""
        try:
            verification_chain = await self._resolve_active_verification_chain(did)
        except Exception:
            return "did_resolution_failed"
        try:
            valid = verify_with_active_keys(verification_chain[0], payload, signature, key_id, required_purpose)
        except IdentityCompositionError:
            return "key_not_authorized"
        return "valid" if valid else "invalid"

    async def verify_signature(
        self,
        did: str,
        payload: str,
        signature: str,
        key_id: str | None = None,
        required_purpose: VerificationRelationship = REQUIRED_RELATIONSHIP_BY_ARTIFACT["assertion"],
    ) -> bool:
        """Verify that *signature* was produced by *did* for *payload*."""
        try:
            verification_chain = await self._resolve_active_verification_chain(did)
        except Exception:
            return False

        return verify_with_active_keys(verification_chain[0], payload, signature, key_id, required_purpose)

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
    ) -> VerifySignatureAtTimeResult:
        """Verify a signature made with *key_id* at the time the signed artifact states (RFC-001 §6.2.2).

        Uses the DID's did:webvh log as created or imported in this client (``import_did_webvh_history``).

        * ``valid``: the signature verifies and the key was authorized for *required_purpose* at *stated_time*,
          with no later change that retires it, or with *trusted_time_not_after* earlier than that change.
        * ``invalid``: the signature does not verify, the key was not authorized at *stated_time*, or the log
          fails verification.
        * ``indeterminate``: the key was retired or the DID deactivated after *stated_time* and there is no
          trusted time evidence, or this client has no did:webvh log for the DID. Do not accept it.

        The stated time is asserted by the signer, so a retired key is never accepted on the signer's word alone.
        """
        log = self._did_webvh_log_store.get(did) if did.startswith("did:webvh:") else None
        if log is None:
            return VerifySignatureAtTimeResult(
                status="indeterminate",
                key=KeyAtTimeResult(status="indeterminate", key_id=key_id, reason="history_unavailable"),
            )
        try:
            key = await check_did_webvh_key_at_time(
                log,
                key_id=key_id,
                stated_time=stated_time,
                required_purpose=required_purpose,
                did=did,
                trusted_time_not_after=trusted_time_not_after,
            )
        except DidWebvhError:
            return VerifySignatureAtTimeResult(status="invalid", reason="did_resolution_failed")
        return signature_result_for_key(key, payload, signature)

    async def resolve(self, did: str) -> AgentDIDDocument:
        if did.startswith("did:webvh:"):
            # For did:webvh the verified log is the only source of revocation state: a DID is
            # revoked only by a controller-signed deactivation entry. The registry record is a
            # derived index and is not consulted. DIDs without a local log are resolved (and
            # their logs verified) by the configured resolver.
            if await self._is_did_webvh_deactivated(did):
                raise ValueError(f"DID is revoked: {did}")
            return await self._resolver.resolve(did)

        is_revoked = await self._registry.is_revoked(did)
        if is_revoked:
            raise ValueError(f"DID is revoked: {did}")
        return await self._resolver.resolve(did)

    async def _is_did_webvh_deactivated(self, did: str) -> bool:
        """Whether the locally stored did:webvh log ends in a deactivation entry.

        The log is verified (SCID, hash chain, controller proofs) before its state is
        trusted; a log that fails verification is an error, never "not revoked". Returns
        False when no log is stored for the DID.
        """
        log = self._did_webvh_log_store.get(did)
        if log is None:
            return False
        cached = self._did_webvh_state_cache.get(did)
        if cached is not None and cached[0] == log:
            return cached[1]
        resolved = await resolve_did_webvh_log(log, did=did)
        self._did_webvh_state_cache[did] = (log, resolved.metadata.deactivated)
        return resolved.metadata.deactivated

    async def resolve_controller_chain(self, did: str, max_depth: int = 8) -> list[AgentDIDDocument]:
        if max_depth < 1:
            raise ValueError("max_depth must be a positive integer")

        chain: list[AgentDIDDocument] = []
        visited: set[str] = set()
        current_did = did

        while True:
            if current_did in visited:
                raise ValueError(f"Controller chain cycle detected at DID: {current_did}")

            if len(chain) >= max_depth:
                raise ValueError(f"Controller chain exceeded max depth of {max_depth} starting from DID: {did}")

            visited.add(current_did)
            current = await self.resolve(current_did)
            chain.append(current)

            controller_did = current.controller.strip() if current.controller else ""
            if not controller_did or controller_did == current_did or not controller_did.startswith("did:"):
                return chain

            current_did = controller_did

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
            deactivated = await deactivate_did_webvh_log(log=log, signer=signer)
            self._did_webvh_log_store[did] = deactivated.log
        await self._registry.revoke(did)
        self._append_history(existing, "revoked")

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

    async def rotate_verification_method(
        self, did: str, *, controller_signer: AgentSigner | None = None
    ) -> RotateVerificationMethodResult:
        existing = await self.resolve(did)
        updated, vm_id, private_key_hex = build_rotated_document(did, existing, self._next_timestamp(existing.updated))

        if did.startswith("did:webvh:"):
            updated = await self._append_did_webvh_entry(did, updated, controller_signer)

        self._resolver.register_document(updated)
        await self._registry.set_document_reference(did, compute_document_reference(updated))
        self._append_history(updated, "rotated-key")

        return RotateVerificationMethodResult(
            document=updated, verification_method_id=vm_id, agent_private_key=private_key_hex
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

    async def import_did_webvh_history(self, did_log: str) -> AgentDIDDocument:
        """Verify a did:webvh v1.0 log and load it into this process.

        Checks the SCID, hash chain and controller-signed proofs, then loads the latest
        document, registry record and document history. Changing the DID afterwards requires
        its controller signer (``controller_signer=``).
        """
        resolved = await resolve_did_webvh_log(did_log)
        did = resolved.did
        latest = AgentDIDDocument.model_validate(resolved.state)
        document_ref = compute_document_reference(latest)

        self._history_store[did] = history_from_did_webvh_log(resolved.log)
        self._did_webvh_log_store[did] = resolved.log
        self._did_webvh_signer_store.pop(did, None)

        self._resolver.register_document(latest)
        await self._registry.register(latest.id, latest.controller, document_ref)
        await self._registry.set_document_reference(latest.id, document_ref)
        if resolved.metadata.deactivated:
            await self._registry.revoke(did)

        return latest

    def save_did_webvh_history_to_file(self, did: str, file_path: str | Path) -> Path:
        path = Path(file_path)
        path.write_text(self.export_did_webvh_history(did), encoding="utf-8")
        return path

    async def load_did_webvh_history_from_file(self, file_path: str | Path) -> AgentDIDDocument:
        path = Path(file_path)
        return await self.import_did_webvh_history(path.read_text(encoding="utf-8"))

    async def persist_did_webvh_history_to_source(
        self,
        did: str,
        document_ref: str,
        source: DIDDocumentSource,
    ) -> None:
        store = getattr(source, "store_did_log_by_reference", None)
        if store is None:
            raise ValueError("DIDDocumentSource does not support did:webvh log persistence")

        await store(document_ref, self.export_did_webvh_history(did))

    async def restore_did_webvh_history_from_source(
        self,
        document_ref: str,
        source: DIDDocumentSource,
    ) -> AgentDIDDocument:
        loader = getattr(source, "get_did_log_by_reference", None)
        if loader is None:
            raise ValueError("DIDDocumentSource does not support did:webvh log retrieval")

        did_log = await loader(document_ref)
        if not did_log:
            raise ValueError(f"did:webvh DID log not found for reference: {document_ref}")

        return await self.import_did_webvh_history(did_log)

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
                cache_ttl_ms=config.cache_ttl_ms or 60_000,
                max_cache_entries=(
                    DEFAULT_RESOLVER_MAX_CACHE_ENTRIES if config.max_cache_entries is None else config.max_cache_entries
                ),
                on_resolution_event=config.on_resolution_event,  # type: ignore[arg-type]
                unverified_document_ref_schemes=config.unverified_document_ref_schemes,
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
