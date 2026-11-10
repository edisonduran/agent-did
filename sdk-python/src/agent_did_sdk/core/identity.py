"""AgentIdentity — main class for creating, signing, resolving and revoking Agent-DIDs."""

from __future__ import annotations

import os
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import ClassVar

from nacl.signing import SigningKey

from ..registry.types import AgentRegistry
from ..resolver.types import (
    DIDDocumentSource,
    DIDResolver,
)
from .client import (
    AgentDidClient as AgentDidClient,
)
from .client import (
    ProductionHttpResolverProfileConfig as ProductionHttpResolverProfileConfig,
)
from .client import (
    ProductionJsonRpcResolverProfileConfig as ProductionJsonRpcResolverProfileConfig,
)
from .client import (
    ProductionResolverProfileConfig as ProductionResolverProfileConfig,
)
from .http_profile import (
    AGENT_DID_HTTP_SIGNATURE_COMPONENTS as AGENT_DID_HTTP_SIGNATURE_COMPONENTS,
)
from .http_profile import (
    AGENT_DID_HTTP_SIGNATURE_TAG as AGENT_DID_HTTP_SIGNATURE_TAG,
)
from .http_profile import compute_content_digest
from .http_security import validate_http_target
from .http_signatures import (
    HttpRequestLike,
    SignatureInput,
    build_signature_base,
    serialize_signature,
    serialize_signature_input,
)
from .identity_composition import REQUIRED_RELATIONSHIP_BY_ARTIFACT
from .signer import AgentSigner
from .types import (
    AgentDIDDocument,
    AgentDocumentHistoryEntry,
    CreateAgentParams,
    CreateAgentResult,
    RotateVerificationMethodResult,
    SignHttpRequestParams,
    UpdateAgentDocumentParams,
    VerificationRelationship,
    VerifyHttpRequestSignatureParams,
)


@dataclass
class AgentIdentityConfig:
    controller_signer: AgentSigner
    """Ed25519 signer of the controller (creator); its public key identifies it (``did:key``)."""
    network: str = "polygon"
    client: AgentDidClient | None = None
    """Client owning the identity state; defaults to the process-wide default client."""


class AgentIdentity:
    """Full-lifecycle Agent-DID management: create, sign, verify, resolve, revoke.

    Instances create and sign; the class-level API is a deprecated facade over a default
    :class:`AgentDidClient` (state is owned by the client, not by this class).
    """

    _default_client: ClassVar[AgentDidClient] = AgentDidClient()

    def __init__(self, config: AgentIdentityConfig) -> None:
        self._controller_signer = config.controller_signer
        self._network = config.network
        self._explicit_client = config.client

    @property
    def client(self) -> AgentDidClient:
        """The client this identity creates documents in."""
        return self._explicit_client or AgentIdentity._default_client

    @classmethod
    def get_default_client(cls) -> AgentDidClient:
        """The client behind the deprecated class-level API."""
        return cls._default_client

    @classmethod
    def set_default_client(cls, client: AgentDidClient) -> None:
        """Replace the client behind the deprecated class-level API (and identities without one)."""
        cls._default_client = client

    async def create(self, params: CreateAgentParams) -> CreateAgentResult:
        """Create a new Agent-DID document (passport) from raw parameters."""
        return await self.client.create_agent(self._controller_signer, self._network, params)

    async def sign_message(self, payload: str, key_or_signer: str | AgentSigner) -> str:
        """Sign *payload* with an Ed25519 private key (hex) or an AgentSigner."""
        message_bytes = payload.encode("utf-8")
        if isinstance(key_or_signer, str):
            private_bytes = bytes.fromhex(key_or_signer)
            signing_key = SigningKey(private_bytes)
            signed = signing_key.sign(message_bytes)
            return signed.signature.hex()
        return await key_or_signer.sign(message_bytes)

    async def sign_http_request(self, params: SignHttpRequestParams) -> dict[str, str]:
        """Sign an HTTP request with an RFC 9421 HTTP Message Signature (Agent-DID profile).

        Covered components: ``"@method" "@authority" "@path" "@query" "content-digest" "date"
        "signature-agent"``; parameters: ``created``, ``expires``, ``nonce``, ``keyid``,
        ``alg="ed25519"`` and ``tag="agent-did"``. Returns the header fields to add to the request.
        """
        if not (params.method and params.method.strip()):
            raise ValueError("HTTP method is required")
        if not (params.url and params.url.strip()):
            raise ValueError("HTTP URL is required")

        validate_http_target(params.url, params.http_security)

        if not (params.agent_did and params.agent_did.strip()):
            raise ValueError("Agent DID is required")

        key_or_signer = params.signer or params.agent_private_key
        if key_or_signer is None:
            raise ValueError("Either signer or agent_private_key must be provided")

        created = int(time.time())
        expires_in = params.expires_in_seconds if params.expires_in_seconds is not None else 30
        headers = {
            "Signature-Agent": params.agent_did,
            "Date": datetime.fromtimestamp(created, timezone.utc).strftime("%a, %d %b %Y %H:%M:%S GMT"),
            "Content-Digest": compute_content_digest(params.body),
        }
        signature_input = SignatureInput(
            components=list(AGENT_DID_HTTP_SIGNATURE_COMPONENTS),
            params=[
                ("created", created),
                ("expires", created + expires_in),
                ("nonce", os.urandom(16).hex()),
                ("keyid", params.verification_method_id or f"{params.agent_did}#key-1"),
                ("alg", "ed25519"),
                ("tag", AGENT_DID_HTTP_SIGNATURE_TAG),
            ],
        )
        signature_base = build_signature_base(
            HttpRequestLike(method=params.method.upper(), url=params.url, headers=headers), signature_input
        )

        signature_hex = await self.sign_message(signature_base, key_or_signer)
        return {
            **headers,
            "Signature-Input": f"sig1={serialize_signature_input(signature_input)}",
            "Signature": serialize_signature("sig1", bytes.fromhex(signature_hex)),
        }

    @classmethod
    async def verify_http_request_signature(cls, params: VerifyHttpRequestSignatureParams) -> bool:
        """Deprecated: use the same method on an ``AgentDidClient``; removed in 2.0."""
        return await cls._default_client.verify_http_request_signature(params)

    @classmethod
    async def verify_signature(
        cls,
        did: str,
        payload: str,
        signature: str,
        key_id: str | None = None,
        required_purpose: VerificationRelationship = REQUIRED_RELATIONSHIP_BY_ARTIFACT["assertion"],
    ) -> bool:
        """Deprecated: use the same method on an ``AgentDidClient``; removed in 2.0."""
        return await cls._default_client.verify_signature(did, payload, signature, key_id, required_purpose)

    @classmethod
    async def resolve(cls, did: str) -> AgentDIDDocument:
        """Deprecated: use the same method on an ``AgentDidClient``; removed in 2.0."""
        return await cls._default_client.resolve(did)

    @classmethod
    async def resolve_controller_chain(cls, did: str, max_depth: int = 8) -> list[AgentDIDDocument]:
        """Deprecated: use the same method on an ``AgentDidClient``; removed in 2.0."""
        return await cls._default_client.resolve_controller_chain(did, max_depth)

    @classmethod
    async def revoke_did(cls, did: str, *, controller_signer: AgentSigner | None = None) -> None:
        """Deprecated: use the same method on an ``AgentDidClient``; removed in 2.0."""
        return await cls._default_client.revoke_did(did, controller_signer=controller_signer)

    @classmethod
    async def update_did_document(
        cls, did: str, patch: UpdateAgentDocumentParams, *, controller_signer: AgentSigner | None = None
    ) -> AgentDIDDocument:
        """Deprecated: use the same method on an ``AgentDidClient``; removed in 2.0."""
        return await cls._default_client.update_did_document(did, patch, controller_signer=controller_signer)

    @classmethod
    async def rotate_verification_method(
        cls, did: str, *, controller_signer: AgentSigner | None = None
    ) -> RotateVerificationMethodResult:
        """Deprecated: use the same method on an ``AgentDidClient``; removed in 2.0."""
        return await cls._default_client.rotate_verification_method(did, controller_signer=controller_signer)

    @classmethod
    def get_document_history(cls, did: str) -> list[AgentDocumentHistoryEntry]:
        """Deprecated: use the same method on an ``AgentDidClient``; removed in 2.0."""
        return cls._default_client.get_document_history(did)

    @classmethod
    def export_did_webvh_history(cls, did: str) -> str:
        """Deprecated: use the same method on an ``AgentDidClient``; removed in 2.0."""
        return cls._default_client.export_did_webvh_history(did)

    @classmethod
    async def import_did_webvh_history(cls, did_log: str) -> AgentDIDDocument:
        """Deprecated: use the same method on an ``AgentDidClient``; removed in 2.0."""
        return await cls._default_client.import_did_webvh_history(did_log)

    @classmethod
    def save_did_webvh_history_to_file(cls, did: str, file_path: str | Path) -> Path:
        """Deprecated: use the same method on an ``AgentDidClient``; removed in 2.0."""
        return cls._default_client.save_did_webvh_history_to_file(did, file_path)

    @classmethod
    async def load_did_webvh_history_from_file(cls, file_path: str | Path) -> AgentDIDDocument:
        """Deprecated: use the same method on an ``AgentDidClient``; removed in 2.0."""
        return await cls._default_client.load_did_webvh_history_from_file(file_path)

    @classmethod
    async def persist_did_webvh_history_to_source(cls, did: str, document_ref: str, source: DIDDocumentSource) -> None:
        """Deprecated: use the same method on an ``AgentDidClient``; removed in 2.0."""
        return await cls._default_client.persist_did_webvh_history_to_source(did, document_ref, source)

    @classmethod
    async def restore_did_webvh_history_from_source(
        cls, document_ref: str, source: DIDDocumentSource
    ) -> AgentDIDDocument:
        """Deprecated: use the same method on an ``AgentDidClient``; removed in 2.0."""
        return await cls._default_client.restore_did_webvh_history_from_source(document_ref, source)

    @classmethod
    def set_resolver(cls, resolver: DIDResolver) -> None:
        """Deprecated: use the same method on an ``AgentDidClient``; removed in 2.0."""
        return cls._default_client.set_resolver(resolver)

    @classmethod
    def set_registry(cls, registry: AgentRegistry) -> None:
        """Deprecated: use the same method on an ``AgentDidClient``; removed in 2.0."""
        return cls._default_client.set_registry(registry)

    @classmethod
    def use_production_resolver(cls, config: ProductionResolverProfileConfig) -> None:
        """Deprecated: use the same method on an ``AgentDidClient``; removed in 2.0."""
        return cls._default_client.use_production_resolver(config)

    @classmethod
    def use_production_resolver_from_http(cls, config: ProductionHttpResolverProfileConfig) -> None:
        """Deprecated: use the same method on an ``AgentDidClient``; removed in 2.0."""
        return cls._default_client.use_production_resolver_from_http(config)

    @classmethod
    def use_production_resolver_from_json_rpc(cls, config: ProductionJsonRpcResolverProfileConfig) -> None:
        """Deprecated: use the same method on an ``AgentDidClient``; removed in 2.0."""
        return cls._default_client.use_production_resolver_from_json_rpc(config)
