"""Tests for UniversalResolverClient."""

from __future__ import annotations

import asyncio

import pytest

from agent_did_sdk.core.signer import LocalKeySigner
from agent_did_sdk.core.types import AgentDIDDocument
from agent_did_sdk.crypto.hash import generate_canonical_document_hash
from agent_did_sdk.registry.in_memory import InMemoryAgentRegistry
from agent_did_sdk.resolver.in_memory import InMemoryDIDResolver
from agent_did_sdk.resolver.types import DocumentIntegrityError, ResolverResolutionEvent, UniversalResolverConfig
from agent_did_sdk.resolver.universal import UniversalResolverClient
from agent_did_sdk.webvh.adapter import DidWebvhError, deactivate_did_webvh_log

from .webvh_helpers import TEST_CONTROLLER_KEY, create_agent_webvh_log, tamper_last_state


def _make_doc(did: str = "did:agent:polygon:0xtest") -> AgentDIDDocument:
    return AgentDIDDocument(
        **{
            "@context": ["https://www.w3.org/ns/did/v1", "https://agent-did.org/v1"],
            "id": did,
            "controller": "did:ethr:0xcontroller",
            "created": "2024-01-01T00:00:00Z",
            "updated": "2024-01-01T00:00:00Z",
            "agentMetadata": {
                "name": "TestAgent",
                "version": "1.0.0",
                "coreModelHash": "hash://sha256/abc",
                "systemPromptHash": "hash://sha256/def",
            },
            "verificationMethod": [
                {
                    "id": f"{did}#key-1",
                    "type": "Ed25519VerificationKey2020",
                    "controller": "did:ethr:0xcontroller",
                    "publicKeyMultibase": "z1234",
                }
            ],
            "authentication": [f"{did}#key-1"],
        }
    )


def _make_webvh_doc(did: str = "did:webvh:QmExampleScid:example.com:agents:test") -> AgentDIDDocument:
    return AgentDIDDocument(
        **{
            "@context": ["https://www.w3.org/ns/did/v1", "https://agent-did.org/v1"],
            "id": did,
            "controller": "did:webvh:QmControllerScid:example.com:organizations:acme-support",
            "created": "2024-01-01T00:00:00Z",
            "updated": "2024-01-01T00:00:00Z",
            "agentMetadata": {
                "name": "WebvhTestAgent",
                "version": "1.0.0",
                "coreModelHash": "hash://sha256/abc",
                "systemPromptHash": "hash://sha256/def",
            },
            "verificationMethod": [
                {
                    "id": f"{did}#key-1",
                    "type": "Ed25519VerificationKey2020",
                    "controller": "did:webvh:QmControllerScid:example.com:organizations:acme-support",
                    "publicKeyMultibase": "z1234",
                }
            ],
            "authentication": [f"{did}#key-1"],
            "assertionMethod": [f"{did}#key-1"],
        }
    )


class FakeSource:
    def __init__(self, doc: AgentDIDDocument | None = None) -> None:
        self._doc = doc
        self.calls: list[str] = []

    async def get_by_reference(self, ref: str) -> AgentDIDDocument | None:
        self.calls.append(ref)
        return self._doc


class SpyRegistry:
    def __init__(self) -> None:
        self.get_record_calls = 0

    async def register(self, did: str, controller: str, document_ref: str | None = None) -> None:
        return None

    async def set_document_reference(self, did: str, document_ref: str) -> None:
        return None

    async def revoke(self, did: str) -> None:
        return None

    async def get_record(self, did: str):
        self.get_record_calls += 1
        return None

    async def is_revoked(self, did: str) -> bool:
        return False


class TestUniversalResolverClient:
    async def test_cache_hit(self) -> None:
        registry = InMemoryAgentRegistry()
        source = FakeSource()
        resolver = UniversalResolverClient(UniversalResolverConfig(
            registry=registry, document_source=source, cache_ttl_ms=60_000,
        ))
        doc = _make_doc()
        resolver.register_document(doc)
        resolved = await resolver.resolve("did:agent:polygon:0xtest")
        assert resolved.id == doc.id
        stats = resolver.get_cache_stats()
        assert stats.hits == 1

    async def test_fallback(self) -> None:
        registry = InMemoryAgentRegistry()
        source = FakeSource(None)
        fallback = InMemoryDIDResolver()
        doc = _make_doc()
        fallback.register_document(doc)
        resolver = UniversalResolverClient(UniversalResolverConfig(
            registry=registry, document_source=source, fallback_resolver=fallback, cache_ttl_ms=60_000,
        ))
        resolved = await resolver.resolve("did:agent:polygon:0xtest")
        assert resolved.id == doc.id

    async def test_error_no_fallback(self) -> None:
        registry = InMemoryAgentRegistry()
        source = FakeSource(None)
        resolver = UniversalResolverClient(UniversalResolverConfig(
            registry=registry, document_source=source, cache_ttl_ms=60_000,
        ))
        with pytest.raises(ValueError, match="not found"):
            await resolver.resolve("did:agent:polygon:0xmissing")

    async def test_resolve_did_wba_from_well_known_without_registry_lookup(self) -> None:
        did = "did:wba:agents.example"
        registry = SpyRegistry()
        source = FakeSource(_make_doc())
        wba_source = FakeSource(_make_doc(did))
        resolver = UniversalResolverClient(UniversalResolverConfig(
            registry=registry,
            document_source=source,
            wba_document_source=wba_source,
            cache_ttl_ms=60_000,
        ))

        resolved = await resolver.resolve(did)

        assert resolved.id == did
        assert registry.get_record_calls == 0
        assert source.calls == []
        assert wba_source.calls == ["https://agents.example/.well-known/did.json"]

    async def test_resolve_did_wba_nested_path(self) -> None:
        did = "did:wba:agents.example%3A8443:profiles:alice"
        registry = SpyRegistry()
        wba_source = FakeSource(_make_doc(did))
        resolver = UniversalResolverClient(UniversalResolverConfig(
            registry=registry,
            document_source=FakeSource(None),
            wba_document_source=wba_source,
            cache_ttl_ms=60_000,
        ))

        resolved = await resolver.resolve(did)

        assert resolved.id == did
        assert registry.get_record_calls == 0
        assert wba_source.calls == ["https://agents.example:8443/profiles/alice/did.json"]
        assert resolver.get_cache_stats().misses == 1



class _RaisingSource:
    async def get_by_reference(self, ref: str) -> AgentDIDDocument | None:
        raise ConnectionError("503 Service Unavailable")


class _StoringSource:
    def __init__(self) -> None:
        self.store: dict[str, AgentDIDDocument] = {}

    async def get_by_reference(self, ref: str) -> AgentDIDDocument | None:
        return self.store.get(ref)

    async def store_by_reference(self, ref: str, document: AgentDIDDocument) -> None:
        self.store[ref] = document


def _tampered(doc: AgentDIDDocument) -> AgentDIDDocument:
    data = doc.model_dump_jsonld()
    data["verificationMethod"][0]["publicKeyMultibase"] = "zattacker"  # type: ignore[index]
    return AgentDIDDocument(**data)  # type: ignore[arg-type]


async def _registry_with(did: str, document_ref: str) -> InMemoryAgentRegistry:
    registry = InMemoryAgentRegistry()
    await registry.register(did, "did:ethr:0xcontroller", document_ref)
    return registry


class TestDocumentRefIntegrity:
    async def test_rejects_document_that_does_not_hash_to_document_ref(self) -> None:
        doc = _make_doc()
        resolver = UniversalResolverClient(UniversalResolverConfig(
            registry=await _registry_with(doc.id, generate_canonical_document_hash(doc.model_dump_jsonld())),
            document_source=FakeSource(_tampered(doc)),
        ))
        with pytest.raises(DocumentIntegrityError, match="Document integrity check failed"):
            await resolver.resolve(doc.id)

    async def test_never_falls_back_on_integrity_failure(self) -> None:
        doc = _make_doc()
        fallback = InMemoryDIDResolver()
        fallback.register_document(doc)
        events: list[ResolverResolutionEvent] = []
        resolver = UniversalResolverClient(UniversalResolverConfig(
            registry=await _registry_with(doc.id, generate_canonical_document_hash(doc.model_dump_jsonld())),
            document_source=FakeSource(_tampered(doc)),
            fallback_resolver=fallback,
            on_resolution_event=events.append,
        ))
        with pytest.raises(DocumentIntegrityError):
            await resolver.resolve(doc.id)
        assert "fallback" not in [event.stage for event in events]
        assert events[-1].stage == "error"
        assert resolver.get_cache_stats().size == 0

    async def test_rejects_document_id_mismatch_without_fallback(self) -> None:
        doc = _make_doc()
        other = _make_doc("did:agent:polygon:0xother")
        fallback = InMemoryDIDResolver()
        fallback.register_document(doc)
        resolver = UniversalResolverClient(UniversalResolverConfig(
            registry=await _registry_with(doc.id, generate_canonical_document_hash(other.model_dump_jsonld())),
            document_source=FakeSource(other),
            fallback_resolver=fallback,
        ))
        with pytest.raises(DocumentIntegrityError, match="DID mismatch"):
            await resolver.resolve(doc.id)

    async def test_rejects_unverifiable_scheme_unless_allowed(self) -> None:
        doc = _make_doc()
        resolver = UniversalResolverClient(UniversalResolverConfig(
            registry=await _registry_with(doc.id, "ipfs://bafybeigdyrztcid/example.json"),
            document_source=FakeSource(doc),
        ))
        with pytest.raises(DocumentIntegrityError, match="Unsupported documentRef scheme"):
            await resolver.resolve(doc.id)

    async def test_accepts_allowed_unverifiable_scheme_and_reports_it(self) -> None:
        doc = _make_doc()
        events: list[ResolverResolutionEvent] = []
        resolver = UniversalResolverClient(UniversalResolverConfig(
            registry=await _registry_with(doc.id, "ipfs://bafybeigdyrztcid/example.json"),
            document_source=FakeSource(doc),
            unverified_document_ref_schemes=["IPFS"],
            on_resolution_event=events.append,
        ))
        resolved = await resolver.resolve(doc.id)
        assert resolved.id == doc.id
        assert any((event.message or "").startswith("integrity=unverified scheme=ipfs") for event in events)

    async def test_still_falls_back_when_source_is_unavailable(self) -> None:
        doc = _make_doc()
        fallback = InMemoryDIDResolver()
        fallback.register_document(doc)
        resolver = UniversalResolverClient(UniversalResolverConfig(
            registry=await _registry_with(doc.id, generate_canonical_document_hash(doc.model_dump_jsonld())),
            document_source=_RaisingSource(),
            fallback_resolver=fallback,
        ))
        resolved = await resolver.resolve(doc.id)
        assert resolved.id == doc.id

    async def test_resolves_documents_stored_under_canonical_reference(self) -> None:
        doc = _make_doc()
        document_ref = generate_canonical_document_hash(doc.model_dump_jsonld())
        source = _StoringSource()
        resolver = UniversalResolverClient(UniversalResolverConfig(
            registry=await _registry_with(doc.id, document_ref),
            document_source=source,
            cache_ttl_ms=0,
        ))
        resolver.register_document(doc)
        await asyncio.sleep(0)
        assert list(source.store) == [document_ref]
        resolved = await resolver.resolve(doc.id)
        assert resolved.id == doc.id

    def test_python_and_typescript_agree_on_fixture_document_ref(self, canonical_document_fixture: dict) -> None:
        document = AgentDIDDocument(**canonical_document_fixture["document"])
        assert generate_canonical_document_hash(document.model_dump_jsonld()) == (
            canonical_document_fixture["expectedDocumentRef"]
        )


class LogSource:
    """did:webvh source double that returns raw log text."""

    def __init__(self, log: str | None) -> None:
        self._log = log
        self.log_calls: list[str] = []
        self.document_calls: list[str] = []

    async def get_by_reference(self, ref: str) -> AgentDIDDocument | None:
        self.document_calls.append(ref)
        return None

    async def get_did_log_by_reference(self, ref: str) -> str | None:
        self.log_calls.append(ref)
        return self._log


def _webvh_resolver(source: object, fallback: InMemoryDIDResolver | None = None) -> UniversalResolverClient:
    return UniversalResolverClient(UniversalResolverConfig(
        registry=SpyRegistry(),
        document_source=FakeSource(None),
        webvh_document_source=source,  # type: ignore[arg-type]
        fallback_resolver=fallback,
        cache_ttl_ms=60_000,
    ))


class TestUniversalResolverDidWebvh:
    """Parity: the did:webvh block in sdk/tests/UniversalResolverClient.test.ts."""

    async def test_fetches_well_known_log_verifies_it_and_returns_the_signed_state(self) -> None:
        created = await create_agent_webvh_log("agents.example")
        source = LogSource(created.log)
        registry = SpyRegistry()
        resolver = UniversalResolverClient(UniversalResolverConfig(
            registry=registry,
            document_source=FakeSource(None),
            webvh_document_source=source,  # type: ignore[arg-type]
            cache_ttl_ms=60_000,
        ))

        resolved = await resolver.resolve(created.did)

        assert resolved.model_dump_jsonld() == AgentDIDDocument.model_validate(created.state).model_dump_jsonld()
        assert registry.get_record_calls == 0
        assert source.document_calls == []
        assert source.log_calls == ["https://agents.example/.well-known/did.jsonl"]

    async def test_maps_port_and_path_segments(self) -> None:
        created = await create_agent_webvh_log("agents.example:8443", ["profiles", "alice"])
        source = LogSource(created.log)

        resolved = await _webvh_resolver(source).resolve(created.did)

        assert resolved.id == created.did
        assert source.log_calls == ["https://agents.example:8443/profiles/alice/did.jsonl"]

    async def test_never_falls_back_when_the_log_fails_verification(self) -> None:
        created = await create_agent_webvh_log("agents.example")
        tampered = tamper_last_state(
            created.log, lambda state: state.__setitem__("controller", "did:webvh:QmAttacker:attacker.example")
        )
        fallback = InMemoryDIDResolver()
        fallback.register_document(AgentDIDDocument.model_validate(created.state))

        with pytest.raises(DocumentIntegrityError):
            await _webvh_resolver(LogSource(tampered), fallback).resolve(created.did)

    async def test_rejects_a_valid_log_that_belongs_to_another_did(self) -> None:
        other = await create_agent_webvh_log("agents.example")
        created = await create_agent_webvh_log("agents.example", ["agents", "bot"])

        with pytest.raises(DocumentIntegrityError):
            await _webvh_resolver(LogSource(other.log)).resolve(created.did)

    async def test_refuses_a_deactivated_did_without_falling_back(self) -> None:
        created = await create_agent_webvh_log("agents.example")
        deactivated = await deactivate_did_webvh_log(log=created.log, signer=LocalKeySigner(TEST_CONTROLLER_KEY))
        fallback = InMemoryDIDResolver()
        fallback.register_document(AgentDIDDocument.model_validate(created.state))

        with pytest.raises(ValueError, match="deactivated"):
            await _webvh_resolver(LogSource(deactivated.log), fallback).resolve(created.did)

    async def test_falls_back_only_when_the_log_is_unavailable(self) -> None:
        created = await create_agent_webvh_log("agents.example")
        fallback = InMemoryDIDResolver()
        fallback.register_document(AgentDIDDocument.model_validate(created.state))

        resolved = await _webvh_resolver(LogSource(None), fallback).resolve(created.did)

        assert resolved.id == created.did

    @pytest.mark.parametrize(
        "did",
        [
            "did:webvh:QmUy89VrfryQ254CeHZzQfmcKqByPoKNGqYykP3SeXuegQ:127.0.0.1",
            "did:webvh:QmUy89VrfryQ254CeHZzQfmcKqByPoKNGqYykP3SeXuegQ:127%2E0%2E0%2E1",
            "did:webvh:QmUy89VrfryQ254CeHZzQfmcKqByPoKNGqYykP3SeXuegQ:example.com:..:admin",
            "did:webvh:QmUy89VrfryQ254CeHZzQfmcKqByPoKNGqYykP3SeXuegQ:example.com:%2E%2E:admin",
            "did:webvh:QmUy89VrfryQ254CeHZzQfmcKqByPoKNGqYykP3SeXuegQ:example.com#x",
        ],
        ids=["ipv4", "encoded-ipv4", "traversal", "encoded-traversal", "fragment"],
    )
    async def test_rejects_invalid_dids_before_any_fetch(self, did: str) -> None:
        source = LogSource(None)

        with pytest.raises(DidWebvhError, match="Invalid did:webvh DID"):
            await _webvh_resolver(source, InMemoryDIDResolver()).resolve(did)
        assert source.log_calls == []

    async def test_refuses_a_source_that_cannot_return_the_raw_log(self) -> None:
        created = await create_agent_webvh_log("agents.example")

        with pytest.raises(TypeError, match="get_did_log_by_reference"):
            await _webvh_resolver(FakeSource(AgentDIDDocument.model_validate(created.state))).resolve(created.did)


class TestCacheBound:
    """TypeScript parity: ``cache bound`` in ``sdk/tests/UniversalResolverClient.test.ts``."""

    @staticmethod
    def _resolver(**overrides: int) -> UniversalResolverClient:
        return UniversalResolverClient(
            UniversalResolverConfig(registry=InMemoryAgentRegistry(), document_source=FakeSource(), **overrides)
        )

    @staticmethod
    async def _is_cached(resolver: UniversalResolverClient, did: str) -> bool:
        before = resolver.get_cache_stats().hits
        try:
            await resolver.resolve(did)
        except ValueError:
            pass
        return resolver.get_cache_stats().hits > before

    @pytest.mark.parametrize("value", [0, -1, True])
    def test_rejects_max_cache_entries_that_is_not_a_positive_integer(self, value: int) -> None:
        with pytest.raises(TypeError, match="max_cache_entries"):
            self._resolver(max_cache_entries=value)

    async def test_keeps_at_most_max_cache_entries_evicting_the_least_recently_used(self) -> None:
        resolver = self._resolver(max_cache_entries=2)

        resolver.register_document(_make_doc("did:example:a"))
        resolver.register_document(_make_doc("did:example:b"))
        await resolver.resolve("did:example:a")  # a becomes the most recently used
        resolver.register_document(_make_doc("did:example:c"))

        assert resolver.get_cache_stats().size == 2
        assert await self._is_cached(resolver, "did:example:a")
        assert await self._is_cached(resolver, "did:example:c")
        assert not await self._is_cached(resolver, "did:example:b")

    async def test_drops_expired_documents_before_evicting_live_ones(self, monkeypatch: pytest.MonkeyPatch) -> None:
        clock = [0.0]
        monkeypatch.setattr(UniversalResolverClient, "_now_ms", staticmethod(lambda: clock[0]))
        resolver = self._resolver(cache_ttl_ms=2000, max_cache_entries=2)

        resolver.register_document(_make_doc("did:example:a"))  # expires at 2000
        clock[0] = 500
        resolver.register_document(_make_doc("did:example:b"))  # expires at 2500
        clock[0] = 1000
        await resolver.resolve("did:example:a")  # a is now the most recently used, b the least
        clock[0] = 2100
        resolver.register_document(_make_doc("did:example:c"))

        assert resolver.get_cache_stats().size == 2
        assert await self._is_cached(resolver, "did:example:b")
        assert await self._is_cached(resolver, "did:example:c")
