"""verify_signature_at_time with a resolver that fetches logs (parity: sdk/tests/KeyAtTimeResolver.test.ts)."""

from __future__ import annotations

import json
import time
from collections.abc import Iterator
from dataclasses import dataclass, field

import pytest

from agent_did_sdk import InMemoryAgentRegistry
from agent_did_sdk.core.client import AgentDidClient, ProductionResolverProfileConfig
from agent_did_sdk.core.identity import AgentIdentity, AgentIdentityConfig
from agent_did_sdk.core.signer import LocalKeySigner
from agent_did_sdk.core.types import CreateAgentParams
from agent_did_sdk.webvh.adapter import derive_did_webvh_log_url


@pytest.fixture()
def clock_offset_ms(monkeypatch: pytest.MonkeyPatch) -> Iterator[list[float]]:
    """The resolver cache reads ``time.time()``: moving it forward expires cache entries without waiting."""
    offset = [0.0]
    real = time.time
    monkeypatch.setattr(time, "time", lambda: real() + offset[0] / 1000)
    yield offset


def _first_version_time(log: str) -> str:
    first = next(line for line in log.split("\n") if line.strip())
    return str(json.loads(first)["versionTime"])


class _NoDocuments:
    async def get_by_reference(self, ref: str) -> None:
        return None


@dataclass
class _Setup:
    owner: AgentDidClient
    did: str
    controller: str
    key_id: str
    signature: str
    stated_time: str
    reachable: list[bool] = field(default_factory=lambda: [True])

    def verifier(self) -> AgentDidClient:
        setup = self

        class _Host:
            async def get_by_reference(self, ref: str) -> None:
                return None

            async def get_did_log_by_reference(self, url: str) -> str | None:
                if not setup.reachable[0]:
                    raise RuntimeError("connect timeout")
                for served in (setup.did, setup.controller):
                    if derive_did_webvh_log_url(served) == url:
                        return setup.owner.export_did_webvh_history(served)
                return None

        client = AgentDidClient()
        client.use_production_resolver(ProductionResolverProfileConfig(
            registry=InMemoryAgentRegistry(),
            document_source=_NoDocuments(),  # type: ignore[arg-type]
            webvh_document_source=_Host(),  # type: ignore[arg-type]
            cache_ttl_ms=60_000,
        ))
        return client


async def _set_up() -> _Setup:
    owner = AgentDidClient()
    identity = AgentIdentity(AgentIdentityConfig(controller_signer=LocalKeySigner.generate()[0], client=owner))
    result = await identity.create(CreateAgentParams(name="AtTimeBot", core_model="test", system_prompt="test"))
    did = result.document.id
    signature = await identity.sign_message("approve", result.agent_private_key)
    return _Setup(
        owner=owner,
        did=did,
        controller=str(result.document.controller),
        key_id=f"{did}#key-1",
        signature=signature,
        stated_time=_first_version_time(owner.export_did_webvh_history(did)),
    )


async def _check(client: AgentDidClient, setup: _Setup, trusted: str | None = None):  # type: ignore[no-untyped-def]
    return await client.verify_signature_at_time(
        setup.did,
        "approve",
        setup.signature,
        setup.key_id,
        stated_time=setup.stated_time,
        trusted_time_not_after=trusted,
    )


async def test_checks_a_did_this_client_never_imported_against_the_fetched_log() -> None:
    setup = await _set_up()

    assert (await _check(setup.verifier(), setup)).status == "valid"


async def test_sees_a_rotation_published_after_the_import_once_the_cache_entry_expires(
    clock_offset_ms: list[float],
) -> None:
    setup = await _set_up()
    client = setup.verifier()
    await client.import_did_webvh_history(setup.owner.export_did_webvh_history(setup.controller))
    await client.import_did_webvh_history(setup.owner.export_did_webvh_history(setup.did))
    assert (await _check(client, setup)).status == "valid"

    await setup.owner.rotate_verification_method(setup.did)
    clock_offset_ms[0] += 120_000

    result = await _check(client, setup)
    assert result.status == "indeterminate"
    assert result.key is not None and result.key.reason == "key_retired_after_stated_time"


async def test_returns_a_status_for_a_deactivated_did_instead_of_raising() -> None:
    setup = await _set_up()
    await setup.owner.revoke_did(setup.did)
    client = setup.verifier()

    result = await _check(client, setup)
    assert result.status == "indeterminate"
    assert result.key is not None and result.key.reason == "did_deactivated_after_stated_time"

    # Trusted evidence earlier than the deactivation makes the signature valid; the DID itself stays unresolvable
    assert (await _check(client, setup, trusted=setup.stated_time)).status == "valid"
    with pytest.raises(ValueError, match="deactivated|revoked"):
        await client.resolve(setup.did)


async def test_fails_closed_when_the_log_host_cannot_be_reached_and_nothing_was_imported() -> None:
    setup = await _set_up()
    setup.reachable[0] = False

    result = await _check(setup.verifier(), setup)

    assert result.status == "invalid"
    assert result.reason == "did_resolution_failed"


async def test_keeps_answering_from_the_imported_log_while_the_resolver_does_not_fetch_logs() -> None:
    setup = await _set_up()
    client = AgentDidClient()
    await client.import_did_webvh_history(setup.owner.export_did_webvh_history(setup.controller))
    await client.import_did_webvh_history(setup.owner.export_did_webvh_history(setup.did))

    assert (await _check(client, setup)).status == "valid"
