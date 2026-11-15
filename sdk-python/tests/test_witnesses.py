"""did:webvh witnesses (ADR-007): witness configuration at create and update, approvals collected before an entry is
returned, and resolution that fails closed without them. The DIF suite scenarios run in test_webvh_test_suite.py.

Parity: sdk/tests/Witnesses.test.ts.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pytest

from agent_did_sdk import (
    REMOVE_WITNESSES,
    DidWebvhWitnessCollector,
    DidWebvhWitnessConfig,
    DidWebvhWitnessProofEntry,
    DidWebvhWitnessRequest,
    InMemoryAgentRegistry,
    create_did_webvh_witness_proof,
)
from agent_did_sdk.core.client import AgentDidClient, AgentDidClientOptions, ProductionResolverProfileConfig
from agent_did_sdk.core.identity import AgentIdentity, AgentIdentityConfig
from agent_did_sdk.core.signer import LocalKeySigner
from agent_did_sdk.core.types import CreateAgentParams, CreateDidWebvhOptions, UpdateAgentDocumentParams
from agent_did_sdk.crypto.multibase import encode_public_key_multibase
from agent_did_sdk.verification.key_at_time import check_did_webvh_key_at_time
from agent_did_sdk.webvh.adapter import (
    DID_WEBVH_PLACEHOLDER,
    DidWebvhError,
    DidWebvhLogResult,
    create_did_webvh_log,
    deactivate_did_webvh_log,
    derive_did_webvh_log_url,
    derive_did_webvh_witness_url,
    did_webvh_log_requires_witnesses,
    resolve_did_webvh_log,
    update_did_webvh_log,
)

D = DID_WEBVH_PLACEHOLDER


async def _did_key_of(signer: LocalKeySigner) -> str:
    return f"did:key:{encode_public_key_multibase(await signer.get_public_key())}"


@dataclass
class _Witnesses:
    """Witnesses that approve in process, and the collector a controller would call."""

    signers: list[LocalKeySigner]
    dids: list[str]

    def approving(self, subset: list[LocalKeySigner] | None = None) -> DidWebvhWitnessCollector:
        # Asks the members of the rule that governs the entry, like a controller contacting its witnesses.
        chosen = self.signers if subset is None else subset

        async def collect(request: DidWebvhWitnessRequest) -> list[DidWebvhWitnessProofEntry]:
            return [
                await create_did_webvh_witness_proof(log=request.log, witness_file=request.witness_file, signer=signer)
                for signer in chosen
                if self.dids[self.signers.index(signer)] in request.witness.witnesses
            ]

        return collect

    @property
    def collect(self) -> DidWebvhWitnessCollector:
        return self.approving()


async def _witnesses(count: int) -> _Witnesses:
    signers = [LocalKeySigner.generate()[0] for _ in range(count)]
    return _Witnesses(signers, [await _did_key_of(signer) for signer in signers])


async def _controller_document(signer: LocalKeySigner) -> dict[str, Any]:
    return {
        "@context": ["https://www.w3.org/ns/did/v1", "https://w3id.org/security/multikey/v1"],
        "id": D,
        "verificationMethod": [
            {
                "id": f"{D}#key-1",
                "type": "Multikey",
                "controller": D,
                "publicKeyMultibase": encode_public_key_multibase(await signer.get_public_key()),
            }
        ],
        "assertionMethod": [f"{D}#key-1"],
        "capabilityInvocation": [f"{D}#key-1"],
    }


async def _witnessed_log(count: int = 2, threshold: int = 2) -> tuple[LocalKeySigner, _Witnesses, DidWebvhLogResult]:
    signer = LocalKeySigner.generate()[0]
    w = await _witnesses(count)
    created = await create_did_webvh_log(
        domain="witness.example",
        document=await _controller_document(signer),
        signer=signer,
        witness=DidWebvhWitnessConfig(threshold=threshold, witnesses=w.dids),
        collect_witness_proofs=w.collect,
    )
    return signer, w, created


class TestAdapter:
    async def test_creates_a_witnessed_log_and_exposes_the_rule(self) -> None:
        _signer, w, created = await _witnessed_log()

        assert created.witness_file is not None
        file = json.loads(created.witness_file)
        assert [entry["versionId"] for entry in file] == [created.metadata.version_id]
        assert len(file[0]["proof"]) == 2
        assert created.metadata.witness_threshold == "2"
        assert created.metadata.witnesses == w.dids
        assert did_webvh_log_requires_witnesses(created.log) is True
        assert derive_did_webvh_witness_url(created.did) == "https://witness.example/.well-known/did-witness.json"

    async def test_reports_no_witnesses_for_a_log_without_them(self) -> None:
        signer = LocalKeySigner.generate()[0]
        created = await create_did_webvh_log(
            domain="plain.example", document=await _controller_document(signer), signer=signer
        )

        assert created.witness_file is None
        assert created.metadata.witness_threshold == "0"
        assert created.metadata.witnesses == []
        assert did_webvh_log_requires_witnesses(created.log) is False

    async def test_fails_closed_without_the_file_with_an_empty_one_or_too_few_approvals(self) -> None:
        _signer, _w, created = await _witnessed_log()
        assert created.witness_file is not None
        file = json.loads(created.witness_file)

        with pytest.raises(DidWebvhError, match="no witness proofs"):
            await resolve_did_webvh_log(created.log)
        with pytest.raises(DidWebvhError):
            await resolve_did_webvh_log(created.log, witness_file="[]")
        one_proof = json.dumps([{**file[0], "proof": file[0]["proof"][:1]}])
        with pytest.raises(DidWebvhError):
            await resolve_did_webvh_log(created.log, witness_file=one_proof)
        with pytest.raises(DidWebvhError, match="not valid JSON"):
            await resolve_did_webvh_log(created.log, witness_file="{")
        with pytest.raises(DidWebvhError, match="JSON array"):
            await resolve_did_webvh_log(created.log, witness_file="{}")
        with pytest.raises(DidWebvhError, match="versionId"):
            await resolve_did_webvh_log(created.log, witness_file='[{"versionId":1}]')

    async def test_rejects_a_proof_altered_after_signing(self) -> None:
        _signer, _w, created = await _witnessed_log(1, 1)
        assert created.witness_file is not None
        file = json.loads(created.witness_file)
        value = file[0]["proof"][0]["proofValue"]
        file[0]["proof"][0]["proofValue"] = value[:-2] + ("BB" if value.endswith("A") else "AA")

        with pytest.raises(DidWebvhError):
            await resolve_did_webvh_log(created.log, witness_file=json.dumps(file))

    async def test_refuses_a_governed_entry_without_a_collector_or_with_too_few_approvals(self) -> None:
        signer = LocalKeySigner.generate()[0]
        w = await _witnesses(2)
        document = await _controller_document(signer)
        rule = DidWebvhWitnessConfig(threshold=2, witnesses=w.dids)

        with pytest.raises(DidWebvhError, match="pass collect_witness_proofs"):
            await create_did_webvh_log(domain="witness.example", document=document, signer=signer, witness=rule)
        with pytest.raises(DidWebvhError):
            await create_did_webvh_log(
                domain="witness.example",
                document=document,
                signer=signer,
                witness=rule,
                collect_witness_proofs=w.approving(w.signers[:1]),
            )

        owner, _w, created = await _witnessed_log()
        with pytest.raises(DidWebvhError, match="pass collect_witness_proofs"):
            await update_did_webvh_log(log=created.log, signer=owner, witness_file=created.witness_file)
        with pytest.raises(DidWebvhError, match="no witness proofs"):
            await update_did_webvh_log(log=created.log, signer=owner)

    async def test_never_lets_a_did_outside_the_rule_approve_an_entry(self) -> None:
        signer, _w, created = await _witnessed_log(1, 1)
        stranger = LocalKeySigner.generate()[0]

        async def collect(request: DidWebvhWitnessRequest) -> list[DidWebvhWitnessProofEntry]:
            return [
                await create_did_webvh_witness_proof(
                    log=request.log, witness_file=request.witness_file, signer=stranger
                )
            ]

        with pytest.raises(DidWebvhError, match="not a member"):
            await update_did_webvh_log(
                log=created.log, signer=signer, witness_file=created.witness_file, collect_witness_proofs=collect
            )

    async def test_updates_under_the_rule_changes_it_removes_it_and_deactivates(self) -> None:
        signer, w, created = await _witnessed_log()
        requests: list[tuple[str, int]] = []

        async def recording(request: DidWebvhWitnessRequest) -> list[DidWebvhWitnessProofEntry]:
            requests.append((request.version_id, request.witness.threshold))
            return await w.collect(request)

        # The 2-of-2 witnesses approve the entry that changes the rule to 1-of-1.
        changed = await update_did_webvh_log(
            log=created.log,
            signer=signer,
            witness_file=created.witness_file,
            witness=DidWebvhWitnessConfig(threshold=1, witnesses=[w.dids[0]]),
            collect_witness_proofs=recording,
        )
        assert changed.metadata.witness_threshold == "1"
        assert changed.metadata.witnesses == [w.dids[0]]

        # Under 1-of-1 the first witness alone is enough.
        updated = await update_did_webvh_log(
            log=changed.log,
            signer=signer,
            witness_file=changed.witness_file,
            collect_witness_proofs=w.approving(w.signers[:1]),
        )
        # Removing the rule is approved by the rule in force; later entries need no approval.
        removed = await update_did_webvh_log(
            log=updated.log,
            signer=signer,
            witness_file=updated.witness_file,
            witness=REMOVE_WITNESSES,
            collect_witness_proofs=w.approving(w.signers[:1]),
        )
        assert removed.metadata.witness_threshold == "0"
        assert removed.metadata.witnesses == []
        unwitnessed = await update_did_webvh_log(log=removed.log, signer=signer, witness_file=removed.witness_file)
        # The history still has witnessed entries, so the file stays required.
        assert unwitnessed.witness_file is not None
        with pytest.raises(DidWebvhError, match="no witness proofs"):
            await resolve_did_webvh_log(unwitnessed.log)

        deactivated = await deactivate_did_webvh_log(
            log=unwitnessed.log, signer=signer, witness_file=unwitnessed.witness_file
        )
        assert deactivated.metadata.deactivated is True
        assert requests == [(changed.metadata.version_id, 2)]

    @pytest.mark.parametrize(
        ("threshold", "witnesses", "message"),
        [
            (1, [], "must not be empty"),
            (0, None, "threshold"),
            (3, None, "threshold"),
            (True, None, "threshold"),
            (1, "repeat", "repeat"),
            (1, ["did:web:example.com"], "did:key"),
            (1, "fragment", "did:key"),
            (1, ["did:key:zQ3shokFTS3brHcDQrn82RUDfCZESWL1ZdCEJwekUDPQiYBme"], "Ed25519"),
        ],
    )
    async def test_validates_the_witness_configuration(self, threshold: Any, witnesses: Any, message: str) -> None:
        signer = LocalKeySigner.generate()[0]
        w = await _witnesses(2)
        if witnesses is None:
            witnesses = w.dids
        elif witnesses == "repeat":
            witnesses = [w.dids[0], w.dids[0]]
        elif witnesses == "fragment":
            witnesses = [f"{w.dids[0]}#key"]
        with pytest.raises(DidWebvhError, match=message):
            await create_did_webvh_log(
                domain="witness.example",
                document=await _controller_document(signer),
                signer=signer,
                witness=DidWebvhWitnessConfig(threshold=threshold, witnesses=witnesses),
                collect_witness_proofs=w.collect,
            )

    async def test_checks_a_key_at_a_stated_time_only_with_the_witness_file(self) -> None:
        _signer, _w, created = await _witnessed_log(1, 1)
        key_id = f"{created.did}#key-1"
        stated_time = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

        with pytest.raises(DidWebvhError):
            await check_did_webvh_key_at_time(created.log, key_id=key_id, stated_time=stated_time)
        result = await check_did_webvh_key_at_time(
            created.log, key_id=key_id, stated_time=stated_time, witness_file=created.witness_file
        )
        assert result.status == "authorized"


class _NoDocuments:
    async def get_by_reference(self, ref: str) -> None:
        return None


class _Host:
    def __init__(self, files: dict[str, str], *, witness_files: bool = True) -> None:
        self._files = files
        if witness_files:
            self.get_did_witness_file_by_reference = self._get

    async def get_by_reference(self, ref: str) -> None:
        return None

    async def get_did_log_by_reference(self, url: str) -> str | None:
        return self._files.get(url)

    async def _get(self, url: str) -> str | None:
        return self._files.get(url)


def _with_host(client: AgentDidClient, host: object) -> AgentDidClient:
    client.use_production_resolver(ProductionResolverProfileConfig(
        registry=InMemoryAgentRegistry(),
        document_source=_NoDocuments(),  # type: ignore[arg-type]
        webvh_document_source=host,  # type: ignore[arg-type]
    ))
    return client


@dataclass
class _Setup:
    controller_signer: LocalKeySigner
    files: dict[str, str]
    owner: AgentDidClient
    agent_did: str
    agent_witnesses: _Witnesses
    signature: str

    def verifier(self, *, witness_files: bool = True) -> AgentDidClient:
        return _with_host(AgentDidClient(), _Host(self.files, witness_files=witness_files))

    def publish(self) -> None:
        witness_file = self.owner.export_did_webvh_witness_file(self.agent_did)
        assert witness_file is not None
        self.files[derive_did_webvh_witness_url(self.agent_did)] = witness_file
        self.files[derive_did_webvh_log_url(self.agent_did)] = self.owner.export_did_webvh_history(self.agent_did)


async def _set_up() -> _Setup:
    """A controller published with a 1-of-1 witness, an agent under it with 2-of-2 witnesses, served by one host."""
    controller_witnesses = await _witnesses(1)
    controller_signer = LocalKeySigner.generate()[0]
    controller = await create_did_webvh_log(
        domain="org.example",
        path_segments=["controllers", "acme"],
        document=await _controller_document(controller_signer),
        signer=controller_signer,
        witness=DidWebvhWitnessConfig(threshold=1, witnesses=controller_witnesses.dids),
        collect_witness_proofs=controller_witnesses.collect,
    )
    assert controller.witness_file is not None
    files = {
        derive_did_webvh_log_url(controller.did): controller.log,
        derive_did_webvh_witness_url(controller.did): controller.witness_file,
    }
    agent_witnesses = await _witnesses(2)
    owner = _with_host(
        AgentDidClient(AgentDidClientOptions(collect_witness_proofs=agent_witnesses.collect)), _Host(files)
    )
    identity = AgentIdentity(AgentIdentityConfig(controller_signer=LocalKeySigner.generate()[0], client=owner))
    created = await identity.create(CreateAgentParams(
        name="WitnessedBot",
        webvh=CreateDidWebvhOptions(
            domain="org.example",
            path_segments=["agents", "bot"],
            controller_did=controller.did,
            controller_signer=controller_signer,
            witness=DidWebvhWitnessConfig(threshold=2, witnesses=agent_witnesses.dids),
        ),
    ))
    signature = await identity.sign_message("approve", created.agent_private_key)
    setup = _Setup(controller_signer, files, owner, created.document.id, agent_witnesses, signature)
    setup.publish()
    return setup


class TestResolverAndClient:
    async def test_verifies_a_witnessed_agent_under_a_witnessed_controller(self) -> None:
        setup = await _set_up()

        assert await setup.owner.verify_signature(setup.agent_did, "approve", setup.signature) is True
        assert await setup.verifier().verify_signature(setup.agent_did, "approve", setup.signature) is True
        state = await setup.verifier().resolve_did_webvh_state(setup.agent_did)
        assert state is not None
        assert state.provenance == "fetched"
        assert state.witness_file == setup.owner.export_did_webvh_witness_file(setup.agent_did)

    async def test_fails_closed_without_a_witness_file_or_a_source_that_fetches_one(self) -> None:
        setup = await _set_up()

        with pytest.raises(ValueError, match="cannot fetch did-witness.json"):
            await setup.verifier(witness_files=False).resolve(setup.agent_did)
        del setup.files[derive_did_webvh_witness_url(setup.agent_did)]
        with pytest.raises(ValueError, match="no did-witness.json"):
            await setup.verifier().resolve(setup.agent_did)

    async def test_fails_closed_when_the_witness_file_lacks_the_latest_approval(self) -> None:
        setup = await _set_up()
        before = setup.owner.export_did_webvh_witness_file(setup.agent_did)
        assert before is not None

        await setup.owner.update_did_document(setup.agent_did, UpdateAgentDocumentParams(description="changed"))
        setup.publish()
        setup.files[derive_did_webvh_witness_url(setup.agent_did)] = before

        with pytest.raises(ValueError, match="verification failed"):
            await setup.verifier().resolve(setup.agent_did)

    async def test_updates_rotates_and_revokes_with_the_client_collector(self) -> None:
        setup = await _set_up()
        did = setup.agent_did

        await setup.owner.update_did_document(did, UpdateAgentDocumentParams(description="v2"))
        next_controller = LocalKeySigner.generate()[0]
        await setup.owner.rotate_controller_key(did, next_controller, controller_signer=setup.controller_signer)
        rule = await setup.owner.set_did_webvh_witnesses(
            did, DidWebvhWitnessConfig(threshold=1, witnesses=[setup.agent_witnesses.dids[1]])
        )
        assert rule == DidWebvhWitnessConfig(threshold=1, witnesses=[setup.agent_witnesses.dids[1]])
        await setup.owner.revoke_did(did)

        resolved = await resolve_did_webvh_log(
            setup.owner.export_did_webvh_history(did), witness_file=setup.owner.export_did_webvh_witness_file(did)
        )
        assert resolved.metadata.deactivated is True

    async def test_refuses_to_change_a_witnessed_did_in_a_client_without_a_collector(self) -> None:
        setup = await _set_up()
        did = setup.agent_did
        other = AgentDidClient()
        await other.import_did_webvh_history(
            setup.owner.export_did_webvh_history(did), setup.owner.export_did_webvh_witness_file(did)
        )

        with pytest.raises(DidWebvhError, match="pass collect_witness_proofs"):
            await other.update_did_document(
                did, UpdateAgentDocumentParams(description="x"), controller_signer=setup.controller_signer
            )
        with pytest.raises(DidWebvhError, match="no witness proofs"):
            await other.import_did_webvh_history(setup.owner.export_did_webvh_history(did))

    async def test_saves_loads_persists_and_restores_with_the_witness_file(self, tmp_path: Path) -> None:
        setup = await _set_up()
        did = setup.agent_did
        log_path, witness_path = tmp_path / "did.jsonl", tmp_path / "did-witness.json"

        with pytest.raises(ValueError, match="witness_file_path"):
            setup.owner.save_did_webvh_history_to_file(did, log_path)
        setup.owner.save_did_webvh_history_to_file(did, log_path, witness_path)
        loaded = AgentDidClient()
        assert (await loaded.load_did_webvh_history_from_file(log_path, witness_path)).id == did
        assert loaded.export_did_webvh_witness_file(did) == setup.owner.export_did_webvh_witness_file(did)

        stored: dict[str, str] = {}

        class _Store:
            async def get_by_reference(self, ref: str) -> None:
                return None

            async def store_did_log_by_reference(self, ref: str, text: str) -> None:
                stored[ref] = text

            async def get_did_log_by_reference(self, ref: str) -> str | None:
                return stored.get(ref)

            async def store_did_witness_file_by_reference(self, ref: str, text: str) -> None:
                stored[ref] = text

            async def get_did_witness_file_by_reference(self, ref: str) -> str | None:
                return stored.get(ref)

        source = _Store()
        with pytest.raises(ValueError, match="witness_ref"):
            await setup.owner.persist_did_webvh_history_to_source(did, "log", source)  # type: ignore[arg-type]
        await setup.owner.persist_did_webvh_history_to_source(did, "log", source, "witness")  # type: ignore[arg-type]
        restored = AgentDidClient()
        document = await restored.restore_did_webvh_history_from_source("log", source, "witness")  # type: ignore[arg-type]
        assert document.id == did
        with pytest.raises(ValueError, match="not found"):
            await restored.restore_did_webvh_history_from_source("log", source, "missing")  # type: ignore[arg-type]
