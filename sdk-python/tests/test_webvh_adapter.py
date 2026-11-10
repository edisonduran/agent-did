"""Tests for the did:webvh v1.0 adapter (parity: sdk/tests/WebvhAdapter.test.ts, WebvhVectors.test.ts)."""

from __future__ import annotations

import hashlib
import json
import pathlib
from typing import Any

import pytest

from agent_did_sdk.core.signer import LocalKeySigner
from agent_did_sdk.crypto.multibase import _base58_encode
from agent_did_sdk.webvh.adapter import (
    DID_WEBVH_PLACEHOLDER,
    DidWebvhError,
    create_did_webvh_log,
    deactivate_did_webvh_log,
    derive_did_webvh_log_url,
    did_webvh_update_key_for,
    resolve_did_webvh_log,
    update_did_webvh_log,
)

CONTROLLER_KEY = "1" * 64
OTHER_KEY = "2" * 64
AGENT_PUBLIC_KEY = "z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
VECTORS_PATH = pathlib.Path(__file__).resolve().parents[2] / "fixtures" / "webvh-log-vectors.json"


def agent_document(controller: str) -> dict[str, Any]:
    return {
        "@context": ["https://www.w3.org/ns/did/v1", "https://agent-did.org/v1"],
        "id": DID_WEBVH_PLACEHOLDER,
        "controller": controller,
        "verificationMethod": [
            {
                "id": f"{DID_WEBVH_PLACEHOLDER}#key-1",
                "type": "Multikey",
                "controller": DID_WEBVH_PLACEHOLDER,
                "publicKeyMultibase": AGENT_PUBLIC_KEY,
            }
        ],
        "assertionMethod": [f"{DID_WEBVH_PLACEHOLDER}#key-1"],
        "agentMetadata": {"name": "adapter-test", "version": "1.0.0"},
    }


async def create_log(created: str = "2026-01-01T00:00:00Z") -> Any:
    return await create_did_webvh_log(
        domain="agents.example.com",
        path_segments=["fleet", "agent-1"],
        document=agent_document("did:webvh:controller.example.com"),
        signer=LocalKeySigner(CONTROLLER_KEY),
        created=created,
    )


def rewrite_line(log: str, index: int, mutate: Any) -> str:
    lines = log.rstrip("\n").split("\n")
    entry = json.loads(lines[index])
    mutate(entry)
    lines[index] = json.dumps(entry, separators=(",", ":"))
    return "\n".join(lines) + "\n"


async def resign_line(log: str, index: int, private_key_hex: str) -> str:
    """Replace the proof on one entry with a valid proof from another key."""
    import jsoncanon

    signer = LocalKeySigner(private_key_hex)
    key = await did_webvh_update_key_for(signer)
    lines = log.rstrip("\n").split("\n")
    entry = json.loads(lines[index])
    template = {k: v for k, v in entry["proof"][0].items() if k != "proofValue"}
    template["verificationMethod"] = f"did:key:{key}#{key}"
    unsigned = {k: v for k, v in entry.items() if k != "proof"}
    data = hashlib.sha256(jsoncanon.canonicalize(template)).digest() + hashlib.sha256(
        jsoncanon.canonicalize(unsigned)
    ).digest()
    signature = bytes.fromhex(await signer.sign(data))
    entry["proof"] = [{**template, "proofValue": "z" + _base58_encode(signature)}]
    lines[index] = json.dumps(entry, separators=(",", ":"))
    return "\n".join(lines) + "\n"


class TestDidWebvhAdapter:
    async def test_creates_v1_log_with_scid_and_controller_update_key(self) -> None:
        result = await create_log()
        controller_key = await did_webvh_update_key_for(LocalKeySigner(CONTROLLER_KEY))

        assert result.did == f"did:webvh:{result.metadata.scid}:agents.example.com:fleet:agent-1"
        assert result.document["id"] == result.did
        assert result.metadata.version_id.startswith("1-Qm")
        assert result.version_number == 1
        assert result.metadata.update_keys == [controller_key]
        assert result.metadata.deactivated is False
        assert result.metadata.ttl == "3600"
        assert result.document["agentMetadata"]["name"] == "adapter-test"

        entry = json.loads(result.log.splitlines()[0])
        assert entry["parameters"]["method"] == "did:webvh:1.0"
        assert entry["proof"][0]["cryptosuite"] == "eddsa-jcs-2022"
        assert entry["proof"][0]["verificationMethod"] == f"did:key:{controller_key}#{controller_key}"

    async def test_is_deterministic_for_fixed_key_and_timestamp(self) -> None:
        assert (await create_log()).log == (await create_log()).log

    async def test_appends_updates_and_resolves_earlier_versions(self) -> None:
        created = await create_log()
        next_document = {**created.document, "agentMetadata": {"name": "adapter-test", "version": "1.1.0"}}
        updated = await update_did_webvh_log(
            log=created.log,
            signer=LocalKeySigner(CONTROLLER_KEY),
            document=next_document,
            updated="2026-01-02T00:00:00Z",
        )

        assert updated.did == created.did
        assert updated.version_number == 2
        assert updated.metadata.created == "2026-01-01T00:00:00Z"
        assert updated.metadata.updated == "2026-01-02T00:00:00Z"
        assert updated.document["agentMetadata"]["version"] == "1.1.0"

        first = await resolve_did_webvh_log(updated.log, version_number=1)
        assert first.document["agentMetadata"]["version"] == "1.0.0"
        assert first.metadata.updated == "2026-01-01T00:00:00Z"
        assert first.metadata.update_keys == updated.metadata.update_keys
        by_id = await resolve_did_webvh_log(updated.log, version_id=created.metadata.version_id)
        assert by_id.metadata.version_id == created.metadata.version_id

    async def test_rotates_update_keys(self) -> None:
        created = await create_log()
        new_signer = LocalKeySigner(OTHER_KEY)
        new_key = await did_webvh_update_key_for(new_signer)

        rotated = await update_did_webvh_log(
            log=created.log,
            signer=LocalKeySigner(CONTROLLER_KEY),
            update_keys=[new_key],
            updated="2026-01-02T00:00:00Z",
        )
        assert rotated.metadata.update_keys == [new_key]

        with pytest.raises(DidWebvhError) as excinfo:
            await update_did_webvh_log(log=rotated.log, signer=LocalKeySigner(CONTROLLER_KEY))
        assert excinfo.value.code == "unauthorized"

        following = await update_did_webvh_log(
            log=rotated.log,
            signer=new_signer,
            document={**rotated.document, "controller": "did:webvh:new-controller.example.com"},
        )
        assert following.version_number == 3

    async def test_deactivates_and_refuses_further_updates(self) -> None:
        created = await create_log()
        deactivated = await deactivate_did_webvh_log(log=created.log, signer=LocalKeySigner(CONTROLLER_KEY))

        assert deactivated.metadata.deactivated is True
        resolved = await resolve_did_webvh_log(deactivated.log)
        assert resolved.metadata.deactivated is True
        assert resolved.document["id"] == created.did
        assert resolved.version_number == 2

        with pytest.raises(DidWebvhError) as excinfo:
            await update_did_webvh_log(log=deactivated.log, signer=LocalKeySigner(CONTROLLER_KEY))
        assert excinfo.value.code == "invalidInput"

    async def test_rejects_signer_outside_update_keys(self) -> None:
        created = await create_log()
        with pytest.raises(DidWebvhError) as excinfo:
            await update_did_webvh_log(log=created.log, signer=LocalKeySigner(OTHER_KEY), document=created.document)
        assert excinfo.value.code == "unauthorized"
        with pytest.raises(DidWebvhError) as excinfo:
            await deactivate_did_webvh_log(log=created.log, signer=LocalKeySigner(OTHER_KEY))
        assert excinfo.value.code == "unauthorized"

    async def test_rejects_state_edited_without_resigning(self) -> None:
        created = await create_log()
        tampered = rewrite_line(
            created.log, 0, lambda entry: entry["state"].__setitem__("controller", "did:webvh:attacker.example.com")
        )
        with pytest.raises(DidWebvhError) as excinfo:
            await resolve_did_webvh_log(tampered)
        assert excinfo.value.code == "invalidDid"

    async def test_rejects_entry_resigned_by_unauthorized_key(self) -> None:
        created = await create_log()
        updated = await update_did_webvh_log(
            log=created.log,
            signer=LocalKeySigner(CONTROLLER_KEY),
            document={**created.document, "controller": "did:webvh:attacker.example.com"},
            updated="2026-01-02T00:00:00Z",
        )
        forged = await resign_line(updated.log, 1, OTHER_KEY)
        with pytest.raises(DidWebvhError) as excinfo:
            await resolve_did_webvh_log(forged)
        assert excinfo.value.code == "invalidDid"

    async def test_rejects_log_for_another_did(self) -> None:
        created = await create_log()
        with pytest.raises(DidWebvhError) as excinfo:
            await resolve_did_webvh_log(created.log, did="did:webvh:QmOther:agents.example.com")
        assert excinfo.value.code == "invalidDid"

    @pytest.mark.parametrize(
        ("log", "code"),
        [
            ("", "notFound"),
            ("{not json}\n", "invalidDid"),
            ("[1,2]\n", "invalidDid"),
            ('{"versionId":"1-x"}\n', "invalidDid"),
        ],
    )
    async def test_rejects_malformed_log_text(self, log: str, code: str) -> None:
        with pytest.raises(DidWebvhError) as excinfo:
            await resolve_did_webvh_log(log)
        assert excinfo.value.code == code

    async def test_rejects_invalid_resolution_options(self) -> None:
        created = await create_log()
        with pytest.raises(DidWebvhError) as excinfo:
            await resolve_did_webvh_log(created.log, version_time="not-a-date")
        assert excinfo.value.code == "invalidOptions"
        with pytest.raises(DidWebvhError):
            await resolve_did_webvh_log(created.log, version_number=5)

    @pytest.mark.parametrize(
        "domain",
        [
            "",
            "127.0.0.1",
            "localhost",
            "Agents.Example.com",
            "agents_example.com",
            "agents.example.com:0",
            "agents.example.com:70000",
            "münchen.example",
            "a.example.com",
            "agents.1example.com",
        ],
    )
    async def test_rejects_domain(self, domain: str) -> None:
        with pytest.raises(DidWebvhError) as excinfo:
            await create_did_webvh_log(
                domain=domain, document=agent_document("x"), signer=LocalKeySigner(CONTROLLER_KEY)
            )
        assert excinfo.value.code == "invalidInput"

    @pytest.mark.parametrize("segment", ["..", ".", "a/b", "a:b", ""])
    async def test_rejects_path_segment(self, segment: str) -> None:
        with pytest.raises(DidWebvhError) as excinfo:
            await create_did_webvh_log(
                domain="agents.example.com",
                path_segments=[segment],
                document=agent_document("x"),
                signer=LocalKeySigner(CONTROLLER_KEY),
            )
        assert excinfo.value.code == "invalidInput"

    async def test_accepts_host_with_port(self) -> None:
        result = await create_did_webvh_log(
            domain="agents.example.com:8443",
            document=agent_document("x"),
            signer=LocalKeySigner(CONTROLLER_KEY),
            created="2026-01-01T00:00:00Z",
        )
        assert result.did == f"did:webvh:{result.metadata.scid}:agents.example.com%3A8443"

    @pytest.mark.parametrize(
        "created",
        [
            "2026-01-01",
            "2026-01-01T00:00:00.123Z",
            "2026-01-01T00:00:00+01:00",
            "2026-02-30T00:00:00Z",
            "2999-01-01T00:00:00Z",
        ],
    )
    async def test_rejects_created(self, created: str) -> None:
        with pytest.raises(DidWebvhError) as excinfo:
            await create_did_webvh_log(
                domain="agents.example.com",
                document=agent_document("x"),
                signer=LocalKeySigner(CONTROLLER_KEY),
                created=created,
            )
        assert excinfo.value.code == "invalidInput"

    async def test_rejects_update_timestamp_too_far_in_future(self) -> None:
        created = await create_log()
        with pytest.raises(DidWebvhError) as excinfo:
            await update_did_webvh_log(
                log=created.log, signer=LocalKeySigner(CONTROLLER_KEY), updated="2999-01-01T00:00:00Z"
            )
        assert excinfo.value.code == "invalidInput"

    async def test_rejects_invalid_replacement_update_keys(self) -> None:
        created = await create_log()
        signer = LocalKeySigner(CONTROLLER_KEY)
        for keys in ([], ["z123"]):
            with pytest.raises(DidWebvhError) as excinfo:
                await update_did_webvh_log(log=created.log, signer=signer, update_keys=keys)
            assert excinfo.value.code == "invalidInput"

    async def test_rejects_document_without_did_placeholder(self) -> None:
        with pytest.raises(DidWebvhError) as excinfo:
            await create_did_webvh_log(
                domain="agents.example.com",
                document={"id": "did:example:not-a-placeholder"},
                signer=LocalKeySigner(CONTROLLER_KEY),
            )
        assert excinfo.value.code == "invalidInput"

    async def test_rejects_update_that_changes_document_id(self) -> None:
        created = await create_log()
        with pytest.raises(DidWebvhError) as excinfo:
            await update_did_webvh_log(
                log=created.log,
                signer=LocalKeySigner(CONTROLLER_KEY),
                document={**created.document, "id": "did:webvh:QmOther:agents.example.com"},
            )
        assert excinfo.value.code == "invalidInput"

    async def test_rejects_signer_whose_signature_does_not_match_its_key(self) -> None:
        created = await create_log()

        class LyingSigner:
            async def sign(self, payload: bytes) -> str:
                return await LocalKeySigner(OTHER_KEY).sign(payload)

            async def get_public_key(self) -> bytes:
                return await LocalKeySigner(CONTROLLER_KEY).get_public_key()

        with pytest.raises(DidWebvhError) as excinfo:
            await update_did_webvh_log(log=created.log, signer=LyingSigner(), updated="2026-01-02T00:00:00Z")
        assert excinfo.value.code == "unauthorized"


def _load_vectors() -> dict[str, Any]:
    data: dict[str, Any] = json.loads(VECTORS_PATH.read_text(encoding="utf-8"))
    return data


_VECTORS = _load_vectors()


class TestDidWebvhCrossSdkVectors:
    """fixtures/webvh-log-vectors.json is generated by the TypeScript adapter."""

    async def test_reproduces_deterministic_logs_byte_for_byte(self) -> None:
        inputs = _VECTORS["inputs"]
        controller = LocalKeySigner(inputs["controllerPrivateKeyHex"])
        rotated_controller = LocalKeySigner(inputs["rotatedControllerPrivateKeyHex"])

        created = await create_did_webvh_log(
            domain=inputs["domain"],
            path_segments=inputs["pathSegments"],
            document=inputs["document"],
            signer=controller,
            created=inputs["created"],
        )
        updated = await update_did_webvh_log(
            log=created.log,
            signer=controller,
            document={**created.document, "agentMetadata": inputs["updatedAgentMetadata"]},
            updated=inputs["updated"],
        )
        rotated = await update_did_webvh_log(
            log=updated.log,
            signer=controller,
            update_keys=[await did_webvh_update_key_for(rotated_controller)],
            updated=inputs["rotated"],
        )

        # Pre-rotation: the genesis entry commits to the hash of `next`; only `next` can sign the following entry.
        next_controller = LocalKeySigner(inputs["nextControllerPrivateKeyHex"])
        following_controller = LocalKeySigner(inputs["followingControllerPrivateKeyHex"])
        committed = await create_did_webvh_log(
            domain=inputs["domain"],
            path_segments=inputs["pathSegments"],
            document=inputs["document"],
            signer=controller,
            next_update_keys=[await did_webvh_update_key_for(next_controller)],
            created=inputs["created"],
        )
        pre_rotated = await update_did_webvh_log(
            log=committed.log,
            signer=next_controller,
            next_update_keys=[await did_webvh_update_key_for(following_controller)],
            updated=inputs["updated"],
        )

        produced = [created, updated, rotated, committed, pre_rotated]
        assert len(_VECTORS["deterministic"]) == len(produced)
        for result, vector in zip(produced, _VECTORS["deterministic"]):
            assert result.log == vector["log"], vector["name"]
            assert result.did == vector["did"]
            assert result.metadata.version_id == vector["versionId"]

    @pytest.mark.parametrize(
        "vector",
        [*_VECTORS["deterministic"], *_VECTORS["resolveOnly"]],
        ids=lambda vector: vector["name"],
    )
    async def test_resolves(self, vector: dict[str, Any]) -> None:
        resolved = await resolve_did_webvh_log(vector["log"], did=vector["did"])
        assert resolved.metadata.version_id == vector["versionId"]
        assert resolved.metadata.deactivated is (vector.get("deactivated") is True)
        assert resolved.document == vector["resolved"]["document"]
        expected = vector["resolved"]["metadata"]
        assert {
            "versionId": resolved.metadata.version_id,
            "versionTime": resolved.metadata.version_time,
            "created": resolved.metadata.created,
            "updated": resolved.metadata.updated,
            "scid": resolved.metadata.scid,
            "updateKeys": resolved.metadata.update_keys,
            "nextKeyHashes": resolved.metadata.next_key_hashes,
            "deactivated": resolved.metadata.deactivated,
            "ttl": resolved.metadata.ttl,
        } == expected
        assert resolved.version_number == vector["resolved"]["versionNumber"]

    @pytest.mark.parametrize("vector", _VECTORS["negative"], ids=lambda vector: vector["name"])
    async def test_rejects(self, vector: dict[str, Any]) -> None:
        with pytest.raises(DidWebvhError):
            await resolve_did_webvh_log(vector["log"])


class TestDeriveDidWebvhLogUrl:
    """Parity: the deriveDidWebvhLogUrl block in sdk/tests/WebvhAdapter.test.ts."""

    SCID = "QmUy89VrfryQ254CeHZzQfmcKqByPoKNGqYykP3SeXuegQ"

    async def test_state_is_the_signed_document_without_implicit_services(self) -> None:
        created = await create_log()
        assert "service" not in created.state
        assert isinstance(created.document["service"], list)
        assert {k: v for k, v in created.document.items() if k != "service"} == created.state

    @pytest.mark.parametrize(
        ("suffix", "url"),
        [
            ("example.com", "https://example.com/.well-known/did.jsonl"),
            ("example.com:fleet:agent-1", "https://example.com/fleet/agent-1/did.jsonl"),
            ("agents.example.com%3A8443", "https://agents.example.com:8443/.well-known/did.jsonl"),
            ("agents.example.com%3A8443:a:b", "https://agents.example.com:8443/a/b/did.jsonl"),
        ],
    )
    def test_maps(self, suffix: str, url: str) -> None:
        assert derive_did_webvh_log_url(f"did:webvh:{self.SCID}:{suffix}") == url

    async def test_maps_dids_created_by_the_adapter(self) -> None:
        created = await create_log()
        assert derive_did_webvh_log_url(created.did) == "https://agents.example.com/fleet/agent-1/did.jsonl"

    @pytest.mark.parametrize(
        "did",
        [
            "did:web:example.com",
            "did:webvh::example.com",
            "did:webvh:Qm0000:example.com",
            f"did:webvh:{SCID}",
            f"did:webvh:{SCID}:127.0.0.1",
            f"did:webvh:{SCID}:127%2E0%2E0%2E1",
            f"did:webvh:{SCID}:example.com%3a8443",
            f"did:webvh:{SCID}:example.com%3A0",
            f"did:webvh:{SCID}:Example.com",
            f"did:webvh:{SCID}:localhost",
            f"did:webvh:{SCID}:example.com:..:admin",
            f"did:webvh:{SCID}:example.com:%2E%2E:admin",
            f"did:webvh:{SCID}:example.com:a%2Fb",
            f"did:webvh:{SCID}:example.com::a",
            f"did:webvh:{SCID}:example.com#key-1",
            f"did:webvh:{SCID}:example.com?versionId=1",
            f"did:webvh:{SCID}:example.com/whois",
        ],
    )
    def test_rejects(self, did: str) -> None:
        with pytest.raises(DidWebvhError) as excinfo:
            derive_did_webvh_log_url(did)
        assert excinfo.value.code == "invalidDid"
