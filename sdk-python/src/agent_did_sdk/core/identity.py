"""AgentIdentity — main class for creating, signing, resolving and revoking Agent-DIDs."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import ClassVar, TypedDict
from urllib.parse import urlparse

from nacl.signing import SigningKey, VerifyKey
from web3 import Web3

from ..crypto.hash import generate_agent_metadata_hash
from ..registry.in_memory import InMemoryAgentRegistry
from ..registry.types import AgentRegistry
from ..resolver.http_source import HttpDIDDocumentSource, HttpDIDDocumentSourceConfig
from ..resolver.in_memory import InMemoryDIDResolver
from ..resolver.jsonrpc_source import JsonRpcDIDDocumentSource, JsonRpcDIDDocumentSourceConfig
from ..resolver.types import (
    DIDDocumentSource,
    DIDResolver,
    UniversalResolverConfig,
)
from ..resolver.universal import UniversalResolverClient
from .types import (
    AgentDIDDocument,
    AgentDocumentHistoryAction,
    AgentDocumentHistoryEntry,
    CreateAgentParams,
    CreateAgentResult,
    RotateVerificationMethodResult,
    SignHttpRequestParams,
    UpdateAgentDocumentParams,
    VerificationMethod,
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


class AgentIdentity:
    """Full-lifecycle Agent-DID management: create, sign, verify, resolve, revoke."""

    _resolver: ClassVar[DIDResolver] = InMemoryDIDResolver()
    _registry: ClassVar[AgentRegistry] = InMemoryAgentRegistry()
    _history_store: ClassVar[dict[str, list[AgentDocumentHistoryEntry]]] = {}

    def __init__(self, config: AgentIdentityConfig) -> None:
        self._signer_address = config.signer_address
        self._network = config.network

    # ------------------------------------------------------------------
    # Instance methods
    # ------------------------------------------------------------------

    async def create(self, params: CreateAgentParams) -> CreateAgentResult:
        """Create a new Agent-DID document (passport) from raw parameters."""
        controller_did = f"did:ethr:{self._signer_address}"
        timestamp = datetime.now(timezone.utc).isoformat()
        nonce = os.urandom(16).hex()
        raw_id = Web3.keccak(text=f"{self._signer_address}-{timestamp}-{nonce}").hex()
        agent_did = f"did:agent:{self._network}:{raw_id}"

        core_model_hash_uri = generate_agent_metadata_hash(params.core_model)
        system_prompt_hash_uri = generate_agent_metadata_hash(params.system_prompt)

        # Ed25519 keypair for agent signatures
        signing_key = SigningKey.generate()
        private_key_hex = signing_key.encode().hex()
        public_key_hex = signing_key.verify_key.encode().hex()

        verification_method_id = f"{agent_did}#key-1"
        vm = VerificationMethod(
            id=verification_method_id,
            type="Ed25519VerificationKey2020",
            controller=controller_did,
            publicKeyMultibase=f"z{public_key_hex}",
            blockchainAccountId=f"eip155:1:{Web3.to_checksum_address(os.urandom(20))}",
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
            }
        )

        AgentIdentity._resolver.register_document(document)
        await AgentIdentity._registry.register(
            document.id, document.controller, AgentIdentity._compute_document_reference(document)
        )
        AgentIdentity._append_history(document, "created")

        return CreateAgentResult(document=document, agent_private_key=private_key_hex)

    async def sign_message(self, payload: str, agent_private_key_hex: str) -> str:
        """Sign *payload* with an Ed25519 private key, returning the hex signature."""
        private_bytes = bytes.fromhex(agent_private_key_hex)
        signing_key = SigningKey(private_bytes)
        signed = signing_key.sign(payload.encode("utf-8"))
        return signed.signature.hex()

    async def sign_http_request(self, params: SignHttpRequestParams) -> dict[str, str]:
        """Sign an HTTP request (Web Bot Auth) and return the headers to inject."""
        if not (params.method and params.method.strip()):
            raise ValueError("HTTP method is required")
        if not (params.url and params.url.strip()):
            raise ValueError("HTTP URL is required")
        if not (params.agent_did and params.agent_did.strip()):
            raise ValueError("Agent DID is required")

        timestamp = str(int(time.time()))
        date_header = datetime.now(timezone.utc).strftime("%a, %d %b %Y %H:%M:%S GMT")
        vm_id = params.verification_method_id or f"{params.agent_did}#key-1"
        content_digest = AgentIdentity._compute_content_digest(params.body)
        string_to_sign = AgentIdentity._build_http_signature_base(
            method=params.method, url=params.url, date_header=date_header, content_digest=content_digest
        )

        signature_hex = await self.sign_message(string_to_sign, params.agent_private_key)
        signature_b64 = base64.b64encode(bytes.fromhex(signature_hex)).decode("ascii")

        return {
            "Signature": f"sig1=:{signature_b64}:",
            "Signature-Input": (
                f'sig1=("@request-target" "host" "date" "content-digest");'
                f'created={timestamp};keyid="{vm_id}";alg="ed25519"'
            ),
            "Signature-Agent": params.agent_did,
            "Date": date_header,
            "Content-Digest": content_digest,
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

        if not all([sig_header, sig_input_header, sig_agent, date_header, digest_header]):
            return False

        expected_digest = cls._compute_content_digest(params.body)
        if expected_digest != digest_header:
            return False

        parsed_inputs = cls._parse_http_signature_input_dictionary(sig_input_header)  # type: ignore[arg-type]
        parsed_sigs = cls._parse_http_signature_dictionary(sig_header)  # type: ignore[arg-type]

        sig_base = cls._build_http_signature_base(
            method=params.method, url=params.url, date_header=date_header, content_digest=digest_header  # type: ignore[arg-type]
        )
        now = int(time.time())
        max_skew = params.max_created_skew_seconds if params.max_created_skew_seconds is not None else 300

        for entry in parsed_inputs:
            if not entry["params"].get("keyid") or not entry["params"].get("created"):
                continue
            sig_b64 = parsed_sigs.get(entry["label"])
            if not sig_b64:
                continue

            covered = {c.lower() for c in entry["components"]}
            if not {"@request-target", "host", "date", "content-digest"}.issubset(covered):
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

            if not key_id.startswith(f"{sig_agent}#"):
                continue

            sig_hex = bytes(base64.b64decode(sig_b64)).hex()
            is_valid = await cls.verify_signature(sig_agent, sig_base, sig_hex, key_id)  # type: ignore[arg-type]
            if is_valid:
                return True

        return False

    @classmethod
    async def verify_signature(cls, did: str, payload: str, signature: str, key_id: str | None = None) -> bool:
        """Verify that *signature* was produced by *did* for *payload*."""
        is_revoked = await cls._registry.is_revoked(did)
        if is_revoked:
            return False

        doc = await cls.resolve(did)
        message_bytes = payload.encode("utf-8")
        sig_bytes = bytes.fromhex(signature)

        active_ids = set(doc.authentication or [])
        candidates = [
            m for m in doc.verification_method
            if m.public_key_multibase
            and (m.id == key_id and m.id in active_ids if key_id else m.id in active_ids)
        ]

        for vm in candidates:
            pk_raw = vm.public_key_multibase
            if not pk_raw:
                continue
            pk_hex = pk_raw[1:] if pk_raw.startswith("z") else pk_raw
            try:
                vk = VerifyKey(bytes.fromhex(pk_hex))
                vk.verify(message_bytes, sig_bytes)
                return True
            except Exception:
                continue
        return False

    @classmethod
    async def resolve(cls, did: str) -> AgentDIDDocument:
        is_revoked = await cls._registry.is_revoked(did)
        if is_revoked:
            raise ValueError(f"DID is revoked: {did}")
        return await cls._resolver.resolve(did)

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
        now = datetime.now(timezone.utc).isoformat()

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
        public_key_hex = signing_key.verify_key.encode().hex()

        new_vm = VerificationMethod(
            id=vm_id,
            type="Ed25519VerificationKey2020",
            controller=existing.controller,
            publicKeyMultibase=f"z{public_key_hex}",
        )

        all_vms = [vm.model_dump(by_alias=True, exclude_none=True) for vm in existing.verification_method]
        all_vms.append(new_vm.model_dump(by_alias=True, exclude_none=True))

        updated = AgentDIDDocument(
            **{
                "@context": existing.context,
                "id": existing.id,
                "controller": existing.controller,
                "created": existing.created,
                "updated": datetime.now(timezone.utc).isoformat(),
                "agentMetadata": existing.agent_metadata.model_dump(by_alias=True, exclude_none=True),
                "verificationMethod": all_vms,
                "authentication": [vm_id],
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
        ))
        cls.use_production_resolver(ProductionResolverProfileConfig(
            registry=config.registry,
            document_source=source,
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
        return generate_agent_metadata_hash(json.dumps(document.model_dump_jsonld(), sort_keys=False))

    @staticmethod
    def _compute_content_digest(body: str | None) -> str:
        raw = (body or "").encode("utf-8")
        digest = hashlib.sha256(raw).digest()
        b64 = base64.b64encode(digest).decode("ascii")
        return f"sha-256=:{b64}:"

    @staticmethod
    def _build_http_signature_base(*, method: str, url: str, date_header: str, content_digest: str) -> str:
        parsed = urlparse(url)
        path_query = parsed.path + (f"?{parsed.query}" if parsed.query else "")
        return "\n".join([
            f"(request-target): {method.lower()} {path_query}",
            f"host: {parsed.netloc}",
            f"date: {date_header}",
            f"content-digest: {content_digest}",
        ])

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

    @classmethod
    def _append_history(cls, document: AgentDIDDocument, action: AgentDocumentHistoryAction) -> None:
        did = document.id
        current = cls._history_store.get(did, [])
        entry = AgentDocumentHistoryEntry(
            did=did,
            revision=len(current) + 1,
            action=action,
            timestamp=datetime.now(timezone.utc).isoformat(),
            version=document.agent_metadata.version,
            document_ref=cls._compute_document_reference(document),
        )
        cls._history_store[did] = [*current, entry]
