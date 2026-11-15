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


async def test_fetches_again_after_evict_or_remove_even_within_the_negative_cache_ttl() -> None:
    source = _LogSource(_failing)
    resolver = _resolver(source, ResolutionLimits(negative_cache_ttl_ms=5_000))

    with pytest.raises(ValueError, match="could not be fetched"):
        await resolver.resolve(DID)
    resolver.evict(DID)
    with pytest.raises(ValueError, match="could not be fetched"):
        await resolver.resolve(DID)
    resolver.remove(DID)
    with pytest.raises(ValueError, match="could not be fetched"):
        await resolver.resolve(DID)
    assert source.calls == 3


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
    with pytest.raises(TypeError):
        _resolver(source, ResolutionLimits(max_concurrent_fetches_per_host=0))
    with pytest.raises(TypeError):
        _resolver(source, ResolutionLimits(max_queued_fetches=-1))
    with pytest.raises(TypeError):
        _resolver(source, ResolutionLimits(fetch_deadline_ms=0))


# --- Fetch queue (parity: "fetch queue of the universal resolver" in sdk/tests/ResolutionLimits.test.ts) -------


class _Hanging:
    """Fetches hang until ``release_all``; tracks the peak of active fetches per host. *only* limits it to URLs
    containing that text (others answer "not found" at once)."""

    def __init__(self, only: str | None = None) -> None:
        self.only = only
        self.pending: list[asyncio.Future[None]] = []
        self.active: dict[str, int] = {}
        self.peak: dict[str, int] = {}
        self.calls = 0

    async def __call__(self, url: str) -> str | None:
        if self.only is not None and self.only not in url:
            return None
        self.calls += 1
        host = url.split("/")[2]
        self.active[host] = self.active.get(host, 0) + 1
        self.peak[host] = max(self.peak.get(host, 0), self.active[host])
        gate: asyncio.Future[None] = asyncio.get_running_loop().create_future()
        self.pending.append(gate)
        await gate
        self.active[host] -= 1
        raise RuntimeError("connect ETIMEDOUT")

    async def release_all(self) -> None:
        while self.pending:
            for gate in self.pending[:]:
                self.pending.remove(gate)
                if not gate.done():
                    gate.set_result(None)
            await _flush()


async def _flush() -> None:
    for _ in range(5):
        await asyncio.sleep(0)


def _settle(coro: Awaitable[object]) -> asyncio.Task[BaseException | None]:
    async def run() -> BaseException | None:
        try:
            await coro
        except Exception as exc:
            return exc
        return None

    return asyncio.ensure_future(run())


async def test_runs_at_most_max_concurrent_fetches_per_host_for_one_host() -> None:
    hanging = _Hanging()
    source = _LogSource(hanging)
    resolver = _resolver(source, ResolutionLimits(max_concurrent_fetches_per_host=2))
    tasks = [_settle(resolver.resolve(f"did:webvh:QmScid:slow.example:agents:{n}")) for n in "abcde"]
    await _flush()
    assert hanging.calls == 2
    await hanging.release_all()
    await asyncio.gather(*tasks)
    assert hanging.peak["slow.example"] == 2
    assert hanging.calls == 5


async def test_a_busy_host_does_not_hold_up_fetches_for_another_host() -> None:
    hanging = _Hanging(only="slow.example")
    resolver = _resolver(
        _LogSource(hanging), ResolutionLimits(max_concurrent_fetches=3, max_concurrent_fetches_per_host=2)
    )
    tasks = [_settle(resolver.resolve(f"did:webvh:QmScid:slow.example:agents:{n}")) for n in "abc"]
    await _flush()
    # slow.example holds 2 slots and has one waiter; the third slot goes to another host at once.
    with pytest.raises(ValueError, match="not found"):
        await resolver.resolve("did:webvh:QmScid:fast.example:agents:x")
    await hanging.release_all()
    await asyncio.gather(*tasks)


async def test_refuses_at_once_when_the_queue_is_full_without_remembering_the_refusal() -> None:
    hanging = _Hanging()
    resolver = _resolver(_LogSource(hanging), ResolutionLimits(max_concurrent_fetches=1, max_queued_fetches=1))
    first = _settle(resolver.resolve("did:webvh:QmScid:one.example:agents:a"))
    second = _settle(resolver.resolve("did:webvh:QmScid:two.example:agents:b"))
    await _flush()

    started = time.monotonic()
    with pytest.raises(ValueError, match="too many DID fetches are waiting"):
        await resolver.resolve("did:webvh:QmScid:three.example:agents:c")
    assert time.monotonic() - started < 1
    assert hanging.calls == 1

    await hanging.release_all()
    await asyncio.gather(first, second)
    # The refusal was about load, not about the DID: the next resolution fetches.
    third = _settle(resolver.resolve("did:webvh:QmScid:three.example:agents:c"))
    await _flush()
    await hanging.release_all()
    assert "could not be fetched" in str(await third)
    assert hanging.calls == 3


async def test_the_time_spent_waiting_counts_toward_fetch_deadline_ms() -> None:
    hanging = _Hanging()
    resolver = _resolver(_LogSource(hanging), ResolutionLimits(max_concurrent_fetches=1, fetch_deadline_ms=100))
    first = _settle(resolver.resolve("did:webvh:QmScid:one.example:agents:a"))
    await _flush()
    started = time.monotonic()
    with pytest.raises(ValueError, match="no fetch slot freed up within 100 ms"):
        await resolver.resolve("did:webvh:QmScid:two.example:agents:b")
    assert time.monotonic() - started < 1
    assert "did not finish within 100 ms" in str(await first)
    await hanging.release_all()


async def test_a_fetch_past_the_deadline_fails_is_remembered_and_keeps_its_slot_until_it_settles() -> None:
    hanging = _Hanging()
    resolver = _resolver(
        _LogSource(hanging), ResolutionLimits(max_concurrent_fetches=1, max_queued_fetches=0, fetch_deadline_ms=50)
    )
    did = "did:webvh:QmScid:slow.example:agents:a"
    with pytest.raises(ValueError, match="did not finish within 50 ms"):
        await resolver.resolve(did)
    with pytest.raises(ValueError, match="did not finish within 50 ms"):  # negative cache
        await resolver.resolve(did)
    # The hung fetch still holds the only slot, and nothing may wait.
    with pytest.raises(ValueError, match="too many DID fetches"):
        await resolver.resolve("did:webvh:QmScid:other.example:agents:b")
    assert hanging.calls == 1
    await hanging.release_all()
    with pytest.raises(ValueError, match="did not finish"):
        await resolver.resolve("did:webvh:QmScid:other.example:agents:b")
    await hanging.release_all()


async def test_a_legitimate_resolution_stays_fast_while_many_fetches_to_one_unresponsive_host_are_pending() -> None:
    hanging = _Hanging(only="attacker.example")
    resolver = _resolver(_LogSource(hanging))
    attack = [_settle(resolver.resolve(f"did:webvh:QmScid:attacker.example:agents:n{i}")) for i in range(160)]
    await _flush()

    started = time.monotonic()
    with pytest.raises(ValueError, match="not found"):
        await resolver.resolve("did:webvh:QmScid:partner.example:agents:a")
    assert time.monotonic() - started < 1
    assert hanging.calls == 4  # DEFAULT_MAX_CONCURRENT_FETCHES_PER_HOST

    # 4 fetches run and 64 wait (DEFAULT_MAX_QUEUED_FETCHES); the other 92 were refused at once.
    refused = await asyncio.gather(*attack[68:])
    assert len(refused) == 92
    assert all("too many DID fetches are waiting" in str(error) for error in refused)
    await hanging.release_all()
    await asyncio.gather(*attack)
