"""AgentIdentity — main class for creating, signing, resolving and revoking Agent-DIDs."""

from __future__ import annotations

import hashlib
import json
import os
import re
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import httpx
from nacl.signing import SigningKey, VerifyKey

from ..crypto.hash import (
    create_metadata_commitment,
    generate_agent_metadata_hash,
    generate_canonical_document_hash,
    generate_commitment_salt,
)
from ..crypto.multibase import (
    decode_public_key_multibase,
    did_key_from_public_key,
    encode_public_key_multibase,
)
from ..registry.in_memory import InMemoryAgentRegistry
from ..registry.types import AgentRegistry
from ..resolver.http_source import HttpDIDDocumentSource, HttpDIDDocumentSourceConfig
from ..resolver.in_memory import InMemoryDIDResolver
from ..resolver.jsonrpc_source import JsonRpcDIDDocumentSource, JsonRpcDIDDocumentSourceConfig
from ..resolver.types import (
    DIDDocumentSource,
    DIDResolver,
    ResolverResolutionEvent,
    UniversalResolverConfig,
)
from ..resolver.universal import UniversalResolverClient
from ..resolver.webvh_source import WebvhDIDDocumentSource, WebvhDIDDocumentSourceConfig
from ..webvh.adapter import (
    DID_WEBVH_PLACEHOLDER,
    create_did_webvh_log,
    deactivate_did_webvh_log,
    resolve_did_webvh_log,
    update_did_webvh_log,
)
from .http_profile import AGENT_DID_HTTP_SIGNATURE_COMPONENTS, AGENT_DID_HTTP_SIGNATURE_TAG, compute_content_digest
from .http_security import HttpTargetValidationOptions
from .http_signatures import (
    HttpRequestLike,
    HttpSignatureError,
    build_signature_base,
    parse_signature_header,
    parse_signature_input_header,
)
from .identity_composition import assert_key_purpose, assert_signing_purpose, get_relationship_key_ids
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
    MetadataCommitmentSalts,
    RotateVerificationMethodResult,
    UpdateAgentDocumentParams,
    VerificationMethod,
    VerificationRelationship,
    VerifyHttpRequestSignatureParams,
)


@dataclass
class ProductionResolverProfileConfig:
    registry: AgentRegistry
    document_source: DIDDocumentSource
    wba_document_source: DIDDocumentSource | None = None
    webvh_document_source: DIDDocumentSource | None = None
    cache_ttl_ms: int | None = None
    on_resolution_event: object | None = None
    unverified_document_ref_schemes: list[str] | None = None


@dataclass
class ProductionHttpResolverProfileConfig:
    registry: AgentRegistry
    cache_ttl_ms: int | None = None
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

    def _now_iso_timestamp(self) -> str:
        return normalize_timestamp_to_iso(self._clock().isoformat())  # type: ignore[return-value]

    async def create_agent(
        self, controller_signer: AgentSigner, network: str, params: CreateAgentParams
    ) -> CreateAgentResult:
        """Create a new Agent-DID document (passport) in this client's state."""
        did_method = params.did_method or "webvh"
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

        if did_method == "webvh":
            return await self._create_did_webvh_agent(
                params,
                controller_key_did=controller_key_did,
                timestamp=timestamp,
                agent_metadata=agent_metadata,
                public_key_bytes=public_key_bytes,
                private_key_hex=private_key_hex,
                metadata_commitment_salts=metadata_commitment_salts,
            )

        # Legacy did:agent profile
        nonce = os.urandom(16).hex()
        raw_id = hashlib.sha256(f"{controller_key_did}-{timestamp}-{nonce}".encode()).hexdigest()
        agent_did = f"did:agent:{network}:{raw_id}"
        controller_did = controller_key_did
        verification_method_id = f"{agent_did}#key-1"
        vm = VerificationMethod(
            id=verification_method_id,
            type="Ed25519VerificationKey2020",
            controller=controller_did,
            publicKeyMultibase=encode_public_key_multibase(public_key_bytes),
        )
        document = AgentDIDDocument(
            **{
                "@context": ["https://www.w3.org/ns/did/v1", "https://agent-did.org/v1"],
                "id": agent_did,
                "controller": controller_did,
                "created": timestamp,
                "updated": timestamp,
                "agentMetadata": agent_metadata,
                "verificationMethod": [vm.model_dump(by_alias=True, exclude_none=True)],
                "authentication": [verification_method_id],
                "assertionMethod": [verification_method_id],
            }
        )

        self._resolver.register_document(document)
        await self._registry.register(document.id, document.controller, self._compute_document_reference(document))
        self._append_history(document, "created")

        return CreateAgentResult(
            document=document,
            agent_private_key=private_key_hex,
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
        if params.webvh is not None and params.webvh.domain.strip():
            options = self._require_webvh_create_options(params)
            domain = options.domain.strip()
            path_segments = list(options.path_segments or [])
            controller_did = options.controller_did.strip()
            controller_signer = options.controller_signer
        else:
            # Only the implicit local profile bootstraps a controller. An explicitly supplied
            # controller DID must be published by its owner; the SDK never fabricates it.
            controller_did, controller_signer, controller_private_key = await self._ensure_bootstrap_controller(
                controller_key_did
            )
            domain = self._webvh_domain
            path_segments = ["agents", self._normalize_did_path_segment(params.name)]

        verification_method_id = f"{DID_WEBVH_PLACEHOLDER}#key-1"
        template = {
            "@context": ["https://www.w3.org/ns/did/v1", "https://agent-did.org/v1"],
            "id": DID_WEBVH_PLACEHOLDER,
            "controller": controller_did,
            "created": timestamp,
            "updated": timestamp,
            "agentMetadata": {k: v for k, v in agent_metadata.items() if v is not None},
            "verificationMethod": [
                {
                    "id": verification_method_id,
                    "type": "Ed25519VerificationKey2020",
                    "controller": controller_did,
                    "publicKeyMultibase": encode_public_key_multibase(public_key_bytes),
                }
            ],
            "authentication": [verification_method_id],
            "assertionMethod": [verification_method_id],
        }

        created = await create_did_webvh_log(
            domain=domain, path_segments=path_segments, document=template, signer=controller_signer
        )
        document = AgentDIDDocument.model_validate(created.state)
        self._did_webvh_log_store[document.id] = created.log
        self._did_webvh_signer_store[document.id] = controller_signer

        self._resolver.register_document(document)
        await self._registry.register(document.id, document.controller, self._compute_document_reference(document))
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
            raise ValueError("webvh.domain is required when did_method is webvh")

        if not params.webvh.controller_did.strip():
            raise ValueError("webvh.controller_did is required when did_method is webvh")

        return params.webvh

    @staticmethod
    def _normalize_did_path_segment(value: str) -> str:
        normalized = re.sub(r"[^a-z0-9]+", "-", value.strip().lower()).strip("-")
        return normalized or "agent"

    async def _ensure_bootstrap_controller(self, controller_key_did: str) -> tuple[str, AgentSigner, str | None]:
        """Return the local bootstrap controller for a creator's did:key, creating it on first use.

        Its did:webvh log is signed by a controller key generated with a CSPRNG; the key is
        returned to the caller exactly once (third element) and never derived from public data.
        """
        address = controller_key_did.strip()
        key_id = address.removeprefix("did:key:")
        existing = self._bootstrap_controllers.get(address)
        if existing is not None and await self._registry.get_record(existing[0]) is not None:
            return existing[0], existing[1], None

        signer, private_key = LocalKeySigner.generate()
        timestamp = self._now_iso_timestamp()
        verification_method_id = f"{DID_WEBVH_PLACEHOLDER}#key-1"
        template = {
            "@context": ["https://www.w3.org/ns/did/v1", "https://agent-did.org/v1"],
            "id": DID_WEBVH_PLACEHOLDER,
            "controller": DID_WEBVH_PLACEHOLDER,
            "created": timestamp,
            "updated": timestamp,
            "agentMetadata": {
                "name": f"controller-{self._normalize_did_path_segment(key_id)}",
                "description": "Local bootstrap controller root for canonical did:webvh flows.",
                "version": "1.0.0",
                "coreModelHash": generate_agent_metadata_hash(f"controller:{address}"),
                "systemPromptHash": generate_agent_metadata_hash("controller-bootstrap-root"),
            },
            "verificationMethod": [
                {
                    "id": verification_method_id,
                    "type": "Ed25519VerificationKey2020",
                    "controller": DID_WEBVH_PLACEHOLDER,
                    "publicKeyMultibase": encode_public_key_multibase(await signer.get_public_key()),
                }
            ],
            "authentication": [verification_method_id],
            "assertionMethod": [verification_method_id],
        }

        created = await create_did_webvh_log(
            domain=self._webvh_domain,
            path_segments=["controllers", self._normalize_did_path_segment(key_id)],
            document=template,
            signer=signer,
        )
        document = AgentDIDDocument.model_validate(created.state)
        self._did_webvh_log_store[document.id] = created.log
        self._did_webvh_signer_store[document.id] = signer
        self._bootstrap_controllers[address] = (document.id, signer)

        self._resolver.register_document(document)
        await self._registry.register(document.id, document.controller, self._compute_document_reference(document))
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
        return AgentDIDDocument.model_validate(updated.state)

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
        recorded in ``nonce_store`` (default: a process-wide :class:`InMemoryNonceStore`), so a
        replayed request is rejected. Returns ``False`` on any failure.
        """
        headers = {key.lower(): value for key, value in params.headers.items()}
        signature_agent = headers.get("signature-agent")
        if not headers.get("signature") or not headers.get("signature-input") or not signature_agent:
            return False
        if headers.get("content-digest") != compute_content_digest(params.body):
            return False

        try:
            inputs = parse_signature_input_header(headers["signature-input"])
            signatures = parse_signature_header(headers["signature"])
        except HttpSignatureError:
            return False

        now = int(self._clock().timestamp())
        max_skew = params.max_created_skew_seconds if params.max_created_skew_seconds is not None else 300
        nonce_store = params.nonce_store if params.nonce_store is not None else self._nonce_store
        request = HttpRequestLike(method=params.method.upper(), url=params.url, headers=headers)

        for label, signature_input in inputs.items():
            signature = signatures.get(label)
            if signature is None:
                continue

            created = signature_input.get("created")
            expires = signature_input.get("expires")
            nonce = signature_input.get("nonce")
            key_id = signature_input.get("keyid")
            if (
                signature_input.get("tag") != AGENT_DID_HTTP_SIGNATURE_TAG
                or signature_input.get("alg") != "ed25519"
                or not isinstance(created, int)
                or isinstance(created, bool)
                or not isinstance(expires, int)
                or isinstance(expires, bool)
                or not isinstance(nonce, str)
                or not nonce
                or not isinstance(key_id, str)
                or not key_id.startswith(f"{signature_agent}#")
                or not all(c in signature_input.components for c in AGENT_DID_HTTP_SIGNATURE_COMPONENTS)
                or abs(now - created) > max_skew
                or expires < created
                or now > expires
            ):
                continue

            try:
                signature_base = build_signature_base(request, signature_input)
            except HttpSignatureError:
                continue

            is_valid = await self.verify_signature(
                signature_agent, signature_base, signature.hex(), key_id, required_purpose="assertionMethod"
            )
            if not is_valid:
                continue

            # Record the nonce only for a valid signature, so forged requests cannot burn nonces.
            return await nonce_store.check_and_store(f"{key_id} {nonce}", expires)

        return False

    async def verify_signature(
        self,
        did: str,
        payload: str,
        signature: str,
        key_id: str | None = None,
        required_purpose: VerificationRelationship = "assertionMethod",
    ) -> bool:
        """Verify that *signature* was produced by *did* for *payload*."""
        try:
            verification_chain = await self._resolve_active_verification_chain(did)
        except Exception:
            return False

        doc = verification_chain[0]
        assert_signing_purpose(required_purpose, doc, key_id or "")
        if key_id is not None:
            assert_key_purpose(key_id, doc, required_purpose)

        message_bytes = payload.encode("utf-8")
        sig_bytes = bytes.fromhex(signature)

        active_ids = set(get_relationship_key_ids(doc, required_purpose))
        candidates = [
            m
            for m in doc.verification_method
            if m.public_key_multibase
            and not m.deactivated
            and (m.id == key_id and m.id in active_ids if key_id else m.id in active_ids)
        ]

        for vm in candidates:
            pk_raw = vm.public_key_multibase
            if not pk_raw:
                continue
            try:
                pk_bytes = decode_public_key_multibase(pk_raw)
                vk = VerifyKey(pk_bytes)
                vk.verify(message_bytes, sig_bytes)
                return True
            except Exception:
                continue
        return False

    async def verify_historical_signature(
        self,
        did: str,
        payload: str,
        signature: str,
        key_id: str,
        required_purpose: VerificationRelationship = "assertionMethod",
    ) -> bool:
        """Verify a historical signature against any key (including deactivated) in the DID document."""
        try:
            verification_chain = await self._resolve_active_verification_chain(did)
        except Exception:
            return False

        doc = verification_chain[0]
        assert_signing_purpose(required_purpose, doc, key_id)
        assert_key_purpose(key_id, doc, required_purpose)

        message_bytes = payload.encode("utf-8")
        sig_bytes = bytes.fromhex(signature)

        candidate = next(
            (m for m in doc.verification_method if m.id == key_id and m.public_key_multibase),
            None,
        )
        if candidate is None or not candidate.public_key_multibase:
            return False

        try:
            pk_bytes = decode_public_key_multibase(candidate.public_key_multibase)
            vk = VerifyKey(pk_bytes)
            vk.verify(message_bytes, sig_bytes)
            return True
        except Exception:
            return False

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
        if not did or not did.strip():
            raise ValueError("DID is required")

        if patch.core_model and not patch.core_model_salt:
            raise ValueError(
                "core_model_salt is required when updating core_model "
                "(use generate_commitment_salt() and keep it private)"
            )
        if patch.system_prompt and not patch.system_prompt_salt:
            raise ValueError(
                "system_prompt_salt is required when updating system_prompt "
                "(use generate_commitment_salt() and keep it private)"
            )

        existing = await self.resolve(did)
        now = self._next_document_timestamp(existing.updated)

        updated = AgentDIDDocument(
            **{
                "@context": existing.context,
                "id": existing.id,
                "controller": existing.controller,
                "created": existing.created,
                "updated": now,
                "agentMetadata": {
                    "name": existing.agent_metadata.name,
                    "description": (
                        patch.description if patch.description is not None else existing.agent_metadata.description
                    ),
                    "version": (patch.version if patch.version is not None else existing.agent_metadata.version),
                    "coreModelHash": (
                        create_metadata_commitment(patch.core_model, patch.core_model_salt or "")
                        if patch.core_model
                        else existing.agent_metadata.core_model_hash
                    ),
                    "systemPromptHash": (
                        create_metadata_commitment(patch.system_prompt, patch.system_prompt_salt or "")
                        if patch.system_prompt
                        else existing.agent_metadata.system_prompt_hash
                    ),
                    "capabilities": (
                        patch.capabilities if patch.capabilities is not None else existing.agent_metadata.capabilities
                    ),
                    "memberOf": (patch.member_of if patch.member_of is not None else existing.agent_metadata.member_of),
                },
                "complianceCertifications": (
                    [c.model_dump(by_alias=True) for c in patch.compliance_certifications]
                    if patch.compliance_certifications is not None
                    else (
                        [c.model_dump(by_alias=True) for c in existing.compliance_certifications]
                        if existing.compliance_certifications
                        else None
                    )
                ),
                "verificationMethod": [
                    vm.model_dump(by_alias=True, exclude_none=True) for vm in existing.verification_method
                ],
                "authentication": existing.authentication,
                "assertionMethod": existing.assertion_method,
                "capabilityDelegation": existing.capability_delegation,
                "capabilityInvocation": existing.capability_invocation,
                "keyAgreement": existing.key_agreement,
            }
        )

        if did.startswith("did:webvh:"):
            updated = await self._append_did_webvh_entry(did, updated, controller_signer)

        self._resolver.register_document(updated)
        await self._registry.set_document_reference(did, self._compute_document_reference(updated))
        self._append_history(updated, "updated")
        return updated

    async def rotate_verification_method(
        self, did: str, *, controller_signer: AgentSigner | None = None
    ) -> RotateVerificationMethodResult:
        existing = await self.resolve(did)
        key_indexes: list[int] = []
        for m in existing.verification_method:
            match = re.search(r"#key-(\d+)$", m.id)
            key_indexes.append(int(match.group(1)) if match else 0)

        next_idx = (max(key_indexes) if key_indexes else 0) + 1
        vm_id = f"{did}#key-{next_idx}"

        signing_key = SigningKey.generate()
        private_key_hex = signing_key.encode().hex()
        public_key_bytes = bytes(signing_key.verify_key)

        new_vm = VerificationMethod(
            id=vm_id,
            type="Ed25519VerificationKey2020",
            controller=existing.controller,
            publicKeyMultibase=encode_public_key_multibase(public_key_bytes),
        )

        deactivated_timestamp = self._next_document_timestamp(existing.updated)
        deactivated_vms = []
        for vm in existing.verification_method:
            d = vm.model_dump(by_alias=True, exclude_none=True)
            if "deactivated" not in d:
                d["deactivated"] = deactivated_timestamp
            deactivated_vms.append(d)

        all_vms = deactivated_vms
        all_vms.append(new_vm.model_dump(by_alias=True, exclude_none=True))

        updated = AgentDIDDocument(
            **{
                "@context": existing.context,
                "id": existing.id,
                "controller": existing.controller,
                "created": existing.created,
                "updated": deactivated_timestamp,
                "agentMetadata": existing.agent_metadata.model_dump(by_alias=True, exclude_none=True),
                "verificationMethod": all_vms,
                "authentication": [vm_id],
                "assertionMethod": list(dict.fromkeys([*(existing.assertion_method or []), vm_id])),
                "capabilityDelegation": existing.capability_delegation,
                "capabilityInvocation": existing.capability_invocation,
                "keyAgreement": existing.key_agreement,
            }
        )

        if did.startswith("did:webvh:"):
            updated = await self._append_did_webvh_entry(did, updated, controller_signer)

        self._resolver.register_document(updated)
        await self._registry.set_document_reference(did, self._compute_document_reference(updated))
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
        document_ref = self._compute_document_reference(latest)

        self._history_store[did] = self._history_from_did_webvh_log(resolved.log)
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
                on_resolution_event=config.on_resolution_event,
            )
        )

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _compute_document_reference(document: AgentDIDDocument) -> str:
        return generate_canonical_document_hash(document.model_dump_jsonld())

    def _history_from_did_webvh_log(self, log: str) -> list[AgentDocumentHistoryEntry]:
        """History entries for a verified did:webvh log, one per log entry."""
        entries: list[AgentDocumentHistoryEntry] = []
        previous: AgentDIDDocument | None = None
        for index, line in enumerate((line for line in log.splitlines() if line.strip()), start=1):
            entry = json.loads(line)
            document = AgentDIDDocument.model_validate(entry["state"])
            action: AgentDocumentHistoryAction = "updated"
            if index == 1 or previous is None:
                action = "created"
            elif (entry.get("parameters") or {}).get("deactivated") is True:
                action = "revoked"
            elif len(document.verification_method) != len(previous.verification_method):
                action = "rotated-key"
            entries.append(
                AgentDocumentHistoryEntry(
                    did=document.id,
                    revision=index,
                    action=action,
                    timestamp=entry["versionTime"],
                    version=document.agent_metadata.version,
                    documentRef=self._compute_document_reference(document),
                )
            )
            previous = document
        return entries

    def _next_document_timestamp(self, previous_timestamp: str | None = None) -> str:
        candidate = self._now_iso_timestamp()
        if previous_timestamp:
            try:
                previous_normalized = normalize_timestamp_to_iso(previous_timestamp)
                if previous_normalized is None:
                    return candidate
                previous_dt = datetime.fromisoformat(previous_normalized.replace("Z", "+00:00"))
            except ValueError:
                return candidate

            if candidate <= previous_normalized:
                next_timestamp = normalize_timestamp_to_iso((previous_dt + timedelta(milliseconds=1)).isoformat())
                return next_timestamp or candidate

        return candidate

    def _append_history(self, document: AgentDIDDocument, action: AgentDocumentHistoryAction) -> None:
        did = document.id
        current = self._history_store.get(did, [])
        entry = AgentDocumentHistoryEntry(
            did=did,
            revision=len(current) + 1,
            action=action,
            timestamp=self._now_iso_timestamp(),
            version=document.agent_metadata.version,
            document_ref=self._compute_document_reference(document),
        )
        self._history_store[did] = [*current, entry]
