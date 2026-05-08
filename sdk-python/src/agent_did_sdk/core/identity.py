"""AgentIdentity — main class for creating, signing, resolving and revoking Agent-DIDs."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import time
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import ClassVar, TypedDict
from urllib.parse import quote, urlparse

from eth_utils.address import to_checksum_address
from eth_utils.crypto import keccak
from nacl.signing import SigningKey, VerifyKey

from ..crypto.hash import (
    generate_agent_metadata_hash,
    generate_canonical_document_hash,
)
from ..crypto.multibase import decode_public_key_multibase, encode_public_key_multibase
from ..registry.in_memory import InMemoryAgentRegistry
from ..registry.types import AgentRegistry
from ..resolver.http_source import HttpDIDDocumentSource, HttpDIDDocumentSourceConfig
from ..resolver.in_memory import InMemoryDIDResolver
from ..resolver.jsonrpc_source import JsonRpcDIDDocumentSource, JsonRpcDIDDocumentSourceConfig
from ..resolver.webvh_source import WebvhDIDDocumentSource, WebvhDIDDocumentSourceConfig
from ..resolver.types import (
    DIDDocumentSource,
    DIDResolver,
    UniversalResolverConfig,
)
from ..resolver.universal import UniversalResolverClient
from .http_security import validate_http_target
from .identity_composition import assert_key_purpose, assert_signing_purpose, get_relationship_key_ids
from .signer import AgentSigner
from .time_utils import normalize_timestamp_to_iso
from .types import (
    AgentDIDDocument,
    AgentDocumentHistoryAction,
    AgentDocumentHistoryEntry,
    CreateAgentParams,
    CreateAgentResult,
    CreateDidWebvhOptions,
    RotateVerificationMethodResult,
    SignHttpRequestParams,
    UpdateAgentDocumentParams,
    VerificationMethod,
    VerificationRelationship,
    VerifyHttpRequestSignatureParams,
)


class _ParsedSigInputEntry(TypedDict):
    label: str
    components: list[str]
    params: dict[str, str]


@dataclass
class AgentIdentityConfig:
    signer_address: str  # Controller wallet address (e.g. 0x…)
    network: str = "polygon"


@dataclass
class ProductionResolverProfileConfig:
    registry: AgentRegistry
    document_source: DIDDocumentSource
    wba_document_source: DIDDocumentSource | None = None
    webvh_document_source: DIDDocumentSource | None = None
    cache_ttl_ms: int | None = None
    on_resolution_event: object | None = None


@dataclass
class ProductionHttpResolverProfileConfig:
    registry: AgentRegistry
    cache_ttl_ms: int | None = None
    reference_to_url: object | None = None
    reference_to_urls: object | None = None
    http_client: object | None = None
    ipfs_gateways: list[str] | None = None
    on_resolution_event: object | None = None
    http_security: object | None = None


@dataclass
class ProductionJsonRpcResolverProfileConfig:
    registry: AgentRegistry
    cache_ttl_ms: int | None = None
    endpoint: str | None = None
    endpoints: list[str] | None = None
    method: str | None = None
    build_params: object | None = None
    headers: dict[str, str] | None = None
    http_client: object | None = None
    on_resolution_event: object | None = None
    http_security: object | None = None


class AgentIdentity:
    """Full-lifecycle Agent-DID management: create, sign, verify, resolve, revoke."""

    _DEFAULT_WEBVH_DOMAIN: ClassVar[str] = "agents.local"
    _resolver: ClassVar[DIDResolver] = InMemoryDIDResolver()
    _registry: ClassVar[AgentRegistry] = InMemoryAgentRegistry()
    _history_store: ClassVar[dict[str, list[AgentDocumentHistoryEntry]]] = {}
    _history_revision_store: ClassVar[dict[str, list[tuple[AgentDocumentHistoryEntry, AgentDIDDocument]]]] = {}

    def __init__(self, config: AgentIdentityConfig) -> None:
        self._signer_address = config.signer_address
        self._network = config.network

    @staticmethod
    def _now_iso_timestamp() -> str:
        return normalize_timestamp_to_iso(datetime.now(timezone.utc).isoformat())  # type: ignore[return-value]

    # ------------------------------------------------------------------
    # Instance methods
    # ------------------------------------------------------------------

    async def create(self, params: CreateAgentParams) -> CreateAgentResult:
        """Create a new Agent-DID document (passport) from raw parameters."""
        did_method = params.did_method or "webvh"
        webvh_options = AgentIdentity._resolve_webvh_create_options(params, self._signer_address) if did_method == "webvh" else None

        controller_did = webvh_options.controller_did if webvh_options is not None else f"did:ethr:{self._signer_address}"
        if did_method == "webvh":
            await AgentIdentity._ensure_bootstrap_controller_document(controller_did)
        timestamp = AgentIdentity._now_iso_timestamp()
        nonce = os.urandom(16).hex()
        identity_seed = webvh_options.controller_did if webvh_options is not None else self._signer_address
        raw_id = keccak(text=f"{identity_seed}-{timestamp}-{nonce}").hex()
        agent_did = (
            AgentIdentity._build_did_webvh(raw_id, webvh_options)
            if did_method == "webvh"
            else f"did:agent:{self._network}:{raw_id}"
        )

        core_model_hash_uri = generate_agent_metadata_hash(params.core_model)
        system_prompt_hash_uri = generate_agent_metadata_hash(params.system_prompt)

        # Ed25519 keypair for agent signatures
        private_key_hex = ""
        if params.signer is not None:
            public_key_bytes = await params.signer.get_public_key()
        else:
            signing_key = SigningKey.generate()
            private_key_hex = signing_key.encode().hex()
            public_key_bytes = bytes(signing_key.verify_key)

        verification_method_id = f"{agent_did}#key-1"
        vm = VerificationMethod(
            id=verification_method_id,
            type="Ed25519VerificationKey2020",
            controller=controller_did,
            publicKeyMultibase=encode_public_key_multibase(public_key_bytes),
            blockchainAccountId=(None if did_method == "webvh" else f"eip155:1:{to_checksum_address(os.urandom(20))}"),
        )

        document = AgentDIDDocument(
            **{
                "@context": ["https://www.w3.org/ns/did/v1", "https://agent-did.org/v1"],
                "id": agent_did,
                "controller": controller_did,
                "created": timestamp,
                "updated": timestamp,
                "agentMetadata": {
                    "name": params.name,
                    "description": params.description,
                    "version": params.version or "1.0.0",
                    "coreModelHash": core_model_hash_uri,
                    "systemPromptHash": system_prompt_hash_uri,
                    "capabilities": params.capabilities or [],
                    "memberOf": params.member_of,
                },
                "verificationMethod": [vm.model_dump(by_alias=True, exclude_none=True)],
                "authentication": [verification_method_id],
                "assertionMethod": [verification_method_id],
            }
        )

        AgentIdentity._resolver.register_document(document)
        await AgentIdentity._registry.register(
            document.id, document.controller, AgentIdentity._compute_document_reference(document)
        )
        AgentIdentity._append_history(document, "created")

        return CreateAgentResult(document=document, agent_private_key=private_key_hex)

    @staticmethod
    def _resolve_webvh_create_options(
        params: CreateAgentParams,
        signer_address: str,
    ) -> CreateDidWebvhOptions:
        if params.webvh is not None and params.webvh.domain.strip():
            return AgentIdentity._require_webvh_create_options(params)

        normalized_controller_address = signer_address.strip().lower()
        controller_scid = keccak(text=f"{normalized_controller_address}:controller").hex()
        controller_did = AgentIdentity._compose_did_webvh(
            controller_scid,
            AgentIdentity._DEFAULT_WEBVH_DOMAIN,
            ["controllers", AgentIdentity._normalize_did_path_segment(normalized_controller_address)],
        )
        return CreateDidWebvhOptions(
            domain=AgentIdentity._DEFAULT_WEBVH_DOMAIN,
            controller_did=controller_did,
            path_segments=["agents", AgentIdentity._normalize_did_path_segment(params.name)],
        )

    @staticmethod
    def _require_webvh_create_options(params: CreateAgentParams) -> CreateDidWebvhOptions:
        if params.webvh is None or not params.webvh.domain.strip():
            raise ValueError("webvh.domain is required when did_method is webvh")

        if not params.webvh.controller_did.strip():
            raise ValueError("webvh.controller_did is required when did_method is webvh")

        return params.webvh

    @staticmethod
    def _build_did_webvh(raw_id: str, options: CreateDidWebvhOptions) -> str:
        scid = options.scid.strip() if options.scid is not None and options.scid.strip() else raw_id
        return AgentIdentity._compose_did_webvh(scid, options.domain, options.path_segments)

    @staticmethod
    def _compose_did_webvh(scid: str, domain: str, path_segments: list[str] | None = None) -> str:
        encoded_domain = quote(domain.strip(), safe="")
        encoded_path_segments = [
            quote(segment.strip(), safe="") for segment in (path_segments or []) if segment.strip()
        ]
        return ":".join(["did:webvh", scid.strip().removeprefix("0x"), encoded_domain, *encoded_path_segments])

    @staticmethod
    def _normalize_did_path_segment(value: str) -> str:
        normalized = re.sub(r"[^a-z0-9]+", "-", value.strip().lower()).strip("-")
        return normalized or "agent"

    @classmethod
    async def _ensure_bootstrap_controller_document(cls, controller_did: str) -> None:
        existing = await cls._registry.get_record(controller_did)
        if existing is not None:
            return

        controller_key_seed = keccak(text=f"{controller_did}:bootstrap-key").hex()
        controller_signing_key = SigningKey(bytes.fromhex(controller_key_seed))
        controller_verification_method_id = f"{controller_did}#key-1"
        timestamp = cls._now_iso_timestamp()
        controller_document = AgentDIDDocument(
            **{
                "@context": ["https://www.w3.org/ns/did/v1", "https://agent-did.org/v1"],
                "id": controller_did,
                "controller": controller_did,
                "created": timestamp,
                "updated": timestamp,
                "agentMetadata": {
                    "name": f"controller-{cls._normalize_did_path_segment(controller_did.split(':')[-1])}",
                    "description": "Local bootstrap controller root for canonical did:webvh flows.",
                    "version": "1.0.0",
                    "coreModelHash": generate_agent_metadata_hash(f"controller:{controller_did}"),
                    "systemPromptHash": generate_agent_metadata_hash("controller-bootstrap-root"),
                },
                "verificationMethod": [
                    {
                        "id": controller_verification_method_id,
                        "type": "Ed25519VerificationKey2020",
                        "controller": controller_did,
                        "publicKeyMultibase": encode_public_key_multibase(bytes(controller_signing_key.verify_key)),
                    }
                ],
                "authentication": [controller_verification_method_id],
                "assertionMethod": [controller_verification_method_id],
            }
        )

        cls._resolver.register_document(controller_document)
        await cls._registry.register(
            controller_document.id,
            controller_document.controller,
            cls._compute_document_reference(controller_document),
        )
        cls._append_history(controller_document, "created")

    @classmethod
    async def _resolve_active_verification_chain(cls, did: str) -> list[AgentDIDDocument]:
        chain = await cls.resolve_controller_chain(did) if did.startswith("did:webvh:") else [await cls.resolve(did)]
        if any(not cls._has_active_verification_method(document) for document in chain):
            raise ValueError(f"DID is not active: {did}")
        return chain

    @staticmethod
    def _has_active_verification_method(document: AgentDIDDocument) -> bool:
        return any(method.public_key_multibase and not method.deactivated for method in document.verification_method)

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
        """Sign an HTTP request (Web Bot Auth) and return the headers to inject."""
        if not (params.method and params.method.strip()):
            raise ValueError("HTTP method is required")
        if not (params.url and params.url.strip()):
            raise ValueError("HTTP URL is required")

        validate_http_target(params.url, params.http_security)

        if not (params.agent_did and params.agent_did.strip()):
            raise ValueError("Agent DID is required")

        timestamp = int(time.time())
        expires_at = timestamp + (params.expires_in_seconds if params.expires_in_seconds is not None else 30)
        nonce = os.urandom(16).hex()
        date_header = datetime.now(timezone.utc).strftime("%a, %d %b %Y %H:%M:%S GMT")
        vm_id = params.verification_method_id or f"{params.agent_did}#key-1"
        content_digest = AgentIdentity._compute_content_digest(params.body)
        string_to_sign = AgentIdentity._build_http_signature_base(
            method=params.method, url=params.url, date_header=date_header, content_digest=content_digest, nonce=nonce
        )

        key_or_signer = params.signer or params.agent_private_key
        if key_or_signer is None:
            raise ValueError("Either signer or agent_private_key must be provided")
        signature_hex = await self.sign_message(string_to_sign, key_or_signer)
        signature_b64 = base64.b64encode(bytes.fromhex(signature_hex)).decode("ascii")

        return {
            "Signature": f"sig1=:{signature_b64}:",
            "Signature-Input": (
                f'sig1=("@request-target" "host" "date" "content-digest" "x-request-nonce");'
                f'created={timestamp};expires={expires_at};keyid="{vm_id}";alg="ed25519"'
            ),
            "Signature-Agent": params.agent_did,
            "Date": date_header,
            "Content-Digest": content_digest,
            "X-Request-Nonce": nonce,
        }

    # ------------------------------------------------------------------
    # Class methods — verification & resolution
    # ------------------------------------------------------------------

    @classmethod
    async def verify_http_request_signature(cls, params: VerifyHttpRequestSignatureParams) -> bool:
        norm = {k.lower(): v for k, v in params.headers.items()}
        sig_header = norm.get("signature")
        sig_input_header = norm.get("signature-input")
        sig_agent = norm.get("signature-agent")
        date_header = norm.get("date")
        digest_header = norm.get("content-digest")
        nonce_header = norm.get("x-request-nonce")

        if not all([sig_header, sig_input_header, sig_agent, date_header, digest_header]):
            return False
        assert sig_header is not None
        assert sig_input_header is not None
        assert sig_agent is not None
        assert date_header is not None
        assert digest_header is not None

        expected_digest = cls._compute_content_digest(params.body)
        if expected_digest != digest_header:
            return False

        parsed_inputs = cls._parse_http_signature_input_dictionary(sig_input_header)
        parsed_sigs = cls._parse_http_signature_dictionary(sig_header)

        now = int(time.time())
        max_skew = params.max_created_skew_seconds if params.max_created_skew_seconds is not None else 300

        for entry in parsed_inputs:
            if not entry["params"].get("keyid") or not entry["params"].get("created"):
                continue
            sig_b64 = parsed_sigs.get(entry["label"])
            if not sig_b64:
                continue

            covered = {c.lower() for c in entry["components"]}
            required = {"@request-target", "host", "date", "content-digest", "x-request-nonce"}
            if not required.issubset(covered):
                continue

            # Nonce header must be present when x-request-nonce is a covered component
            if not nonce_header:
                continue

            key_id: str = entry["params"]["keyid"]
            created_raw: str = entry["params"]["created"]
            algorithm = entry["params"].get("alg")
            if algorithm and algorithm.lower() != "ed25519":
                continue

            try:
                created = int(created_raw)
            except ValueError:
                continue
            if abs(now - created) > max_skew:
                continue

            # Check expiration if present
            expires_raw = entry["params"].get("expires")
            if expires_raw:
                try:
                    expires = int(expires_raw)
                except ValueError:
                    continue
                if now > expires:
                    continue

            if not key_id.startswith(f"{sig_agent}#"):
                continue

            # Rebuild signature base including nonce
            sig_base = cls._build_http_signature_base(
                method=params.method, url=params.url, date_header=date_header,
                content_digest=digest_header, nonce=nonce_header,
            )

            sig_hex = bytes(base64.b64decode(sig_b64)).hex()
            is_valid = await cls.verify_signature(
                sig_agent,
                sig_base,
                sig_hex,
                key_id,
                required_purpose="assertionMethod",
            )
            if is_valid:
                return True

        return False

    @classmethod
    async def verify_signature(
        cls,
        did: str,
        payload: str,
        signature: str,
        key_id: str | None = None,
        required_purpose: VerificationRelationship = "assertionMethod",
    ) -> bool:
        """Verify that *signature* was produced by *did* for *payload*."""
        try:
            verification_chain = await cls._resolve_active_verification_chain(did)
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
            m for m in doc.verification_method
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

    @classmethod
    async def verify_historical_signature(
        cls,
        did: str,
        payload: str,
        signature: str,
        key_id: str,
        required_purpose: VerificationRelationship = "assertionMethod",
    ) -> bool:
        """Verify a historical signature against any key (including deactivated) in the DID document."""
        try:
            verification_chain = await cls._resolve_active_verification_chain(did)
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

    @classmethod
    async def resolve(cls, did: str) -> AgentDIDDocument:
        is_revoked = await cls._registry.is_revoked(did)
        if is_revoked:
            raise ValueError(f"DID is revoked: {did}")
        return await cls._resolver.resolve(did)

    @classmethod
    async def resolve_controller_chain(cls, did: str, max_depth: int = 8) -> list[AgentDIDDocument]:
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
            current = await cls.resolve(current_did)
            chain.append(current)

            controller_did = current.controller.strip() if current.controller else ""
            if not controller_did or controller_did == current_did or not controller_did.startswith("did:"):
                return chain

            current_did = controller_did

    @classmethod
    async def revoke_did(cls, did: str) -> None:
        existing = await cls.resolve(did)
        await cls._registry.revoke(did)
        cls._append_history(existing, "revoked")

    @classmethod
    async def update_did_document(cls, did: str, patch: UpdateAgentDocumentParams) -> AgentDIDDocument:
        if not did or not did.strip():
            raise ValueError("DID is required")

        existing = await cls.resolve(did)
        now = cls._next_document_timestamp(existing.updated)

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
                        patch.description if patch.description is not None
                        else existing.agent_metadata.description
                    ),
                    "version": (
                        patch.version if patch.version is not None
                        else existing.agent_metadata.version
                    ),
                    "coreModelHash": (
                        generate_agent_metadata_hash(patch.core_model)
                        if patch.core_model else existing.agent_metadata.core_model_hash
                    ),
                    "systemPromptHash": (
                        generate_agent_metadata_hash(patch.system_prompt)
                        if patch.system_prompt else existing.agent_metadata.system_prompt_hash
                    ),
                    "capabilities": (
                        patch.capabilities if patch.capabilities is not None
                        else existing.agent_metadata.capabilities
                    ),
                    "memberOf": (
                        patch.member_of if patch.member_of is not None
                        else existing.agent_metadata.member_of
                    ),
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
                    vm.model_dump(by_alias=True, exclude_none=True)
                    for vm in existing.verification_method
                ],
                "authentication": existing.authentication,
                "assertionMethod": existing.assertion_method,
                "capabilityDelegation": existing.capability_delegation,
                "capabilityInvocation": existing.capability_invocation,
                "keyAgreement": existing.key_agreement,
            }
        )

        cls._resolver.register_document(updated)
        await cls._registry.set_document_reference(did, cls._compute_document_reference(updated))
        cls._append_history(updated, "updated")
        return updated

    @classmethod
    async def rotate_verification_method(cls, did: str) -> RotateVerificationMethodResult:
        existing = await cls.resolve(did)
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

        deactivated_timestamp = cls._next_document_timestamp(existing.updated)
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

        cls._resolver.register_document(updated)
        await cls._registry.set_document_reference(did, cls._compute_document_reference(updated))
        cls._append_history(updated, "rotated-key")

        return RotateVerificationMethodResult(
            document=updated, verification_method_id=vm_id, agent_private_key=private_key_hex
        )

    @classmethod
    def get_document_history(cls, did: str) -> list[AgentDocumentHistoryEntry]:
        entries = cls._history_store.get(did, [])
        return [e.model_copy(deep=True) for e in entries]

    @classmethod
    def export_did_webvh_history(cls, did: str) -> str:
        scid = cls._extract_did_webvh_scid(did)
        revisions = cls._history_revision_store.get(did, [])

        if not revisions:
            raise ValueError(f"No document history found for DID: {did}")

        state_revisions = [revision for revision in revisions if revision[0].action != "revoked"]
        if not state_revisions:
            raise ValueError(f"No did:webvh state revisions available for DID: {did}")

        return "\n".join(
            json.dumps({
                "versionId": f"{index}-{scid}",
                "versionTime": document.updated,
                "state": document.model_dump(by_alias=True, exclude_none=True),
            })
            for index, (_entry, document) in enumerate(state_revisions, start=1)
        )

    @classmethod
    async def import_did_webvh_history(cls, did_log: str) -> AgentDIDDocument:
        revisions = cls._parse_did_webvh_history(did_log)
        latest_entry, latest_document = revisions[-1]
        latest = latest_document.model_copy(deep=True)
        document_ref = cls._compute_document_reference(latest)

        cls._history_store[latest.id] = [entry.model_copy(deep=True) for entry, _document in revisions]
        cls._history_revision_store[latest.id] = [
            (entry.model_copy(deep=True), document.model_copy(deep=True))
            for entry, document in revisions
        ]

        cls._resolver.register_document(latest)
        await cls._registry.register(latest.id, latest.controller, document_ref)
        await cls._registry.set_document_reference(latest.id, document_ref)

        return latest

    @classmethod
    def save_did_webvh_history_to_file(cls, did: str, file_path: str | Path) -> Path:
        path = Path(file_path)
        path.write_text(cls.export_did_webvh_history(did), encoding="utf-8")
        return path

    @classmethod
    async def load_did_webvh_history_from_file(cls, file_path: str | Path) -> AgentDIDDocument:
        path = Path(file_path)
        return await cls.import_did_webvh_history(path.read_text(encoding="utf-8"))

    @classmethod
    async def persist_did_webvh_history_to_source(
        cls,
        did: str,
        document_ref: str,
        source: DIDDocumentSource,
    ) -> None:
        store = getattr(source, "store_did_log_by_reference", None)
        if store is None:
            raise ValueError("DIDDocumentSource does not support did:webvh log persistence")

        await store(document_ref, cls.export_did_webvh_history(did))

    @classmethod
    async def restore_did_webvh_history_from_source(
        cls,
        document_ref: str,
        source: DIDDocumentSource,
    ) -> AgentDIDDocument:
        loader = getattr(source, "get_did_log_by_reference", None)
        if loader is None:
            raise ValueError("DIDDocumentSource does not support did:webvh log retrieval")

        did_log = await loader(document_ref)
        if not did_log:
            raise ValueError(f"did:webvh DID log not found for reference: {document_ref}")

        return await cls.import_did_webvh_history(did_log)

    # ------------------------------------------------------------------
    # Configuration class methods
    # ------------------------------------------------------------------

    @classmethod
    def set_resolver(cls, resolver: DIDResolver) -> None:
        cls._resolver = resolver

    @classmethod
    def set_registry(cls, registry: AgentRegistry) -> None:
        cls._registry = registry

    @classmethod
    def use_production_resolver(cls, config: ProductionResolverProfileConfig) -> None:
        cls._resolver = UniversalResolverClient(UniversalResolverConfig(
            registry=config.registry,
            document_source=config.document_source,
            wba_document_source=config.wba_document_source,
            webvh_document_source=config.webvh_document_source,
            fallback_resolver=cls._resolver,
            cache_ttl_ms=config.cache_ttl_ms or 60_000,
            on_resolution_event=config.on_resolution_event,  # type: ignore[arg-type]
        ))

    @classmethod
    def use_production_resolver_from_http(cls, config: ProductionHttpResolverProfileConfig) -> None:
        source = HttpDIDDocumentSource(HttpDIDDocumentSourceConfig(
            reference_to_url=config.reference_to_url,  # type: ignore[arg-type]
            reference_to_urls=config.reference_to_urls,  # type: ignore[arg-type]
            http_client=config.http_client,  # type: ignore[arg-type]
            ipfs_gateways=config.ipfs_gateways,
            http_security=config.http_security,  # type: ignore[arg-type]
        ))
        webvh_source = WebvhDIDDocumentSource(WebvhDIDDocumentSourceConfig(
            reference_to_url=config.reference_to_url,  # type: ignore[arg-type]
            reference_to_urls=config.reference_to_urls,  # type: ignore[arg-type]
            http_client=config.http_client,  # type: ignore[arg-type]
            http_security=config.http_security,  # type: ignore[arg-type]
        ))
        cls.use_production_resolver(ProductionResolverProfileConfig(
            registry=config.registry,
            document_source=source,
            wba_document_source=source,
            webvh_document_source=webvh_source,
            cache_ttl_ms=config.cache_ttl_ms,
            on_resolution_event=config.on_resolution_event,
        ))

    @classmethod
    def use_production_resolver_from_json_rpc(cls, config: ProductionJsonRpcResolverProfileConfig) -> None:
        source = JsonRpcDIDDocumentSource(JsonRpcDIDDocumentSourceConfig(
            endpoint=config.endpoint,
            endpoints=config.endpoints,
            method=config.method or "agent_resolveDocumentRef",
            build_params=config.build_params,  # type: ignore[arg-type]
            headers=config.headers,
            http_client=config.http_client,  # type: ignore[arg-type]
            http_security=config.http_security,  # type: ignore[arg-type]
        ))
        cls.use_production_resolver(ProductionResolverProfileConfig(
            registry=config.registry,
            document_source=source,
            cache_ttl_ms=config.cache_ttl_ms,
            on_resolution_event=config.on_resolution_event,
        ))

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _compute_document_reference(document: AgentDIDDocument) -> str:
        return generate_canonical_document_hash(document.model_dump_jsonld())

    @staticmethod
    def _compute_content_digest(body: str | None) -> str:
        raw = (body or "").encode("utf-8")
        digest = hashlib.sha256(raw).digest()
        b64 = base64.b64encode(digest).decode("ascii")
        return f"sha-256=:{b64}:"

    @staticmethod
    def _build_http_signature_base(
        *, method: str, url: str, date_header: str, content_digest: str, nonce: str | None = None,
    ) -> str:
        parsed = urlparse(url)
        path_query = parsed.path + (f"?{parsed.query}" if parsed.query else "")
        lines = [
            f"(request-target): {method.lower()} {path_query}",
            f"host: {parsed.netloc}",
            f"date: {date_header}",
            f"content-digest: {content_digest}",
        ]
        if nonce:
            lines.append(f"x-request-nonce: {nonce}")
        return "\n".join(lines)

    @staticmethod
    def _parse_http_signature_input_dictionary(value: str) -> list[_ParsedSigInputEntry]:
        results: list[_ParsedSigInputEntry] = []
        for entry in value.split(","):
            entry = entry.strip()
            if not entry:
                continue
            m = re.match(r"^([a-zA-Z0-9_-]+)=\(([^)]*)\)(.*)$", entry)
            if not m:
                continue
            label, comp_section, params_section = m.group(1), m.group(2), m.group(3)
            components = re.findall(r'"([^"]+)"', comp_section)
            params: dict[str, str] = {}
            for seg in params_section.split(";"):
                seg = seg.strip()
                if not seg:
                    continue
                eq = seg.find("=")
                if eq == -1:
                    continue
                key = seg[:eq].strip().lower()
                raw_val = seg[eq + 1:].strip()
                if raw_val.startswith('"') and raw_val.endswith('"'):
                    raw_val = raw_val[1:-1]
                params[key] = raw_val
            results.append({"label": label, "components": components, "params": params})
        return results

    @staticmethod
    def _parse_http_signature_dictionary(value: str) -> dict[str, str]:
        result: dict[str, str] = {}
        for entry in value.split(","):
            entry = entry.strip()
            m = re.match(r"^([a-zA-Z0-9_-]+)=:([A-Za-z0-9+/=]+):$", entry)
            if m:
                result[m.group(1)] = m.group(2)
        return result

    @staticmethod
    def _extract_did_webvh_scid(did: str) -> str:
        if not did.startswith("did:webvh:"):
            raise ValueError(f"did:webvh DID is required for history export: {did}")

        suffix = did[len("did:webvh:"):]
        scid, *_rest = suffix.split(":")
        if not scid:
            raise ValueError(f"Invalid did:webvh DID: {did}")
        return scid

    @classmethod
    def _parse_did_webvh_history(cls, did_log: str) -> list[tuple[AgentDocumentHistoryEntry, AgentDIDDocument]]:
        lines = [line.strip() for line in did_log.splitlines() if line.strip()]
        if not lines:
            raise ValueError("did:webvh DID log is empty")

        current_did: str | None = None
        previous_document: AgentDIDDocument | None = None
        revisions: list[tuple[AgentDocumentHistoryEntry, AgentDIDDocument]] = []

        for index, line in enumerate(lines, start=1):
            parsed = json.loads(line)
            state = parsed.get("state") if isinstance(parsed, dict) else None
            if not isinstance(state, dict):
                raise ValueError("did:webvh DID log does not contain a resolvable state entry")

            document = AgentDIDDocument.model_validate(state)
            scid = cls._extract_did_webvh_scid(document.id)
            version_id = parsed.get("versionId") if isinstance(parsed, dict) else None
            if isinstance(version_id, str) and not version_id.endswith(f"-{scid}"):
                raise ValueError(f"did:webvh DID log versionId does not match DID SCID: {version_id}")

            if current_did is not None and document.id != current_did:
                raise ValueError(f"did:webvh DID log mixes multiple DIDs: {current_did} and {document.id}")
            current_did = document.id

            entry = AgentDocumentHistoryEntry(
                did=document.id,
                revision=index,
                action=cls._infer_imported_history_action(previous_document, document, index),
                timestamp=(parsed.get("versionTime") if isinstance(parsed, dict) and isinstance(parsed.get("versionTime"), str) else document.updated),
                version=document.agent_metadata.version,
                documentRef=cls._compute_document_reference(document),
            )

            revisions.append((entry, document.model_copy(deep=True)))
            previous_document = document.model_copy(deep=True)

        return revisions

    @classmethod
    def _infer_imported_history_action(
        cls,
        previous_document: AgentDIDDocument | None,
        current_document: AgentDIDDocument,
        revision: int,
    ) -> AgentDocumentHistoryAction:
        if revision == 1 or previous_document is None:
            return "created"

        if len(current_document.verification_method) != len(previous_document.verification_method):
            return "rotated-key"

        return "updated"

    @classmethod
    def _next_document_timestamp(cls, previous_timestamp: str | None = None) -> str:
        candidate = cls._now_iso_timestamp()
        if previous_timestamp:
            try:
                previous_normalized = normalize_timestamp_to_iso(previous_timestamp)
                previous_dt = datetime.fromisoformat(previous_normalized.replace("Z", "+00:00"))
            except ValueError:
                return candidate

            if candidate <= previous_normalized:
                return normalize_timestamp_to_iso((previous_dt + timedelta(milliseconds=1)).isoformat())  # type: ignore[return-value]

        return candidate

    @classmethod
    def _append_history(cls, document: AgentDIDDocument, action: AgentDocumentHistoryAction) -> None:
        did = document.id
        current = cls._history_store.get(did, [])
        current_revisions = cls._history_revision_store.get(did, [])
        entry = AgentDocumentHistoryEntry(
            did=did,
            revision=len(current) + 1,
            action=action,
            timestamp=cls._now_iso_timestamp(),
            version=document.agent_metadata.version,
            document_ref=cls._compute_document_reference(document),
        )
        cls._history_store[did] = [*current, entry]
        cls._history_revision_store[did] = [
            *current_revisions,
            (entry.model_copy(deep=True), document.model_copy(deep=True)),
        ]
