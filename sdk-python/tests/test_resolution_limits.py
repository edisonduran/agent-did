"""Resolution limits of the universal resolver (parity: sdk/tests/ResolutionLimits.test.ts)."""

from __future__ import annotations

import asyncio
import time
from collections.abc import Awaitable, Callable, Iterator

import pytest

from agent_did_sdk import InMemoryAgentRegistry, ResolutionLimits, UniversalResolverClient
from agent_did_sdk.core.client import AgentDidClient
from agent_did_sdk.core.identity import AgentIdentity, AgentIdentityConfig
from agent_did_sdk.core.signer import LocalKeySigner
from agent_did_sdk.core.types import CreateAgentParams
from agent_did_sdk.resolver.types import UniversalResolverConfig
from agent_did_sdk.webvh.adapter import derive_did_webvh_log_url

DID = "did:webvh:QmScid:host.example.com:agents:a"


@pytest.fixture()
def clock_offset_ms(monkeypatch: pytest.MonkeyPatch) -> Iterator[list[float]]:
    offset = [0.0]
    real = time.time
    monkeypatch.setattr(time, "time", lambda: real() + offset[0] / 1000)
    yield offset


class _NoDocuments:
    async def get_by_reference(self, ref: str) -> None:
        return None


class _LogSource:
    def __init__(self, fetch: Callable[[str], Awaitable[str | None]]) -> None:
        self.fetch = fetch
        self.calls = 0

    async def get_by_reference(self, ref: str) -> None:
        return None

    async def get_did_log_by_reference(self, url: str) -> str | None:
        self.calls += 1
        return await self.fetch(url)


def _resolver(source: _LogSource, limits: ResolutionLimits | None = None) -> UniversalResolverClient:
    return UniversalResolverClient(UniversalResolverConfig(
        registry=InMemoryAgentRegistry(),
        document_source=_NoDocuments(),  # type: ignore[arg-type]
        webvh_document_source=source,  # type: ignore[arg-type]
        resolution_limits=limits,
    ))


async def _failing(url: str) -> str | None:
    raise RuntimeError("connect timeout")


async def test_answers_a_recent_failure_again_without_fetching_until_it_expires(clock_offset_ms: list[float]) -> None:
    source = _LogSource(_failing)
    resolver = _resolver(source, ResolutionLimits(negative_cache_ttl_ms=5_000))

    for _ in range(2):
        with pytest.raises(ValueError, match="could not be fetched"):
            await resolver.resolve(DID)
    with pytest.raises(ValueError, match="could not be fetched"):
        await resolver.resolve_did_webvh_log(DID)
    assert source.calls == 1

    clock_offset_ms[0] += 5_001
    with pytest.raises(ValueError, match="could not be fetched"):
        await resolver.resolve(DID)
    assert source.calls == 2


async def test_does_not_remember_failures_when_the_negative_cache_is_off() -> None:
    source = _LogSource(_failing)
    resolver = _resolver(source, ResolutionLimits(negative_cache_ttl_ms=0))

    for _ in range(2):
        with pytest.raises(ValueError):
            await resolver.resolve(DID)
    assert source.calls == 2


async def test_shares_one_fetch_between_concurrent_resolutions_of_the_same_did() -> None:
    owner = AgentDidClient()
    identity = AgentIdentity(AgentIdentityConfig(controller_signer=LocalKeySigner.generate()[0], client=owner))
    created = await identity.create(CreateAgentParams(name="LimitsBot", core_model="test", system_prompt="test"))
    did = created.document.id

    async def serve(url: str) -> str | None:
        await asyncio.sleep(0.01)
        return owner.export_did_webvh_history(did) if url == derive_did_webvh_log_url(did) else None

    source = _LogSource(serve)
    resolver = _resolver(source)

    first, second, log = await asyncio.gather(
        resolver.resolve(did), resolver.resolve(did), resolver.resolve_did_webvh_log(did)
    )

    assert source.calls == 1
    assert first == second
    assert log is not None
    first.verification_method.clear()  # each caller gets its own copy
    assert second.verification_method


async def test_runs_at_most_max_concurrent_fetches_at_once() -> None:
    active = 0
    peak = 0

    async def slow(url: str) -> str | None:
        nonlocal active, peak
        active += 1
        peak = max(peak, active)
        await asyncio.sleep(0.02)
        active -= 1
        raise RuntimeError("not here")

    resolver = _resolver(_LogSource(slow), ResolutionLimits(max_concurrent_fetches=2))

    await asyncio.gather(
        *(resolver.resolve(f"did:webvh:QmScid:host.example.com:agents:{name}") for name in "abcde"),
        return_exceptions=True,
    )

    assert peak == 2


async def test_fetches_only_dids_on_allowed_hosts_before_any_request() -> None:
    async def missing(url: str) -> str | None:
        return None

    source = _LogSource(missing)
    resolver = _resolver(source, ResolutionLimits(allowed_hosts=["trusted.example.com", "*.partner.example"]))

    for did in (
        "did:webvh:QmScid:evil.example:agents:a",
        "did:webvh:QmScid:partner.example:agents:a",
        "did:wba:evil.example:agents:a",
    ):
        with pytest.raises(ValueError, match="not in allowed_hosts"):
            await resolver.resolve(did)
    assert source.calls == 0

    for did in ("did:webvh:QmScid:trusted.example.com:agents:a", "did:webvh:QmScid:agents.partner.example:a"):
        with pytest.raises(ValueError, match="not found"):
            await resolver.resolve(did)
    assert source.calls == 2


def test_rejects_invalid_limits() -> None:
    source = _LogSource(_failing)
    with pytest.raises(TypeError):
        _resolver(source, ResolutionLimits(negative_cache_ttl_ms=-1))
    with pytest.raises(TypeError):
        _resolver(source, ResolutionLimits(max_concurrent_fetches=0))
    with pytest.raises(TypeError):
        _resolver(source, ResolutionLimits(allowed_hosts=[""]))
