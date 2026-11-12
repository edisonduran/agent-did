"""Binary request bodies, shared bootstrap controller and filesystem default paths.

Parity: ``sdk/tests/BinaryBodiesAndSharedBootstrap.test.ts``.
"""

from __future__ import annotations

import asyncio
import re
from pathlib import Path

import pytest

from agent_did_sdk import AgentDidClient
from agent_did_sdk.core.http_profile import compute_content_digest
from agent_did_sdk.core.identity import AgentIdentity, AgentIdentityConfig
from agent_did_sdk.core.signer import LocalKeySigner
from agent_did_sdk.core.types import CreateAgentParams, SignHttpRequestParams, VerifyHttpRequestSignatureParams
from agent_did_sdk.resolver.file_source import FilesystemDIDDocumentSource, FilesystemDIDDocumentSourceConfig


def _identity() -> tuple[AgentDidClient, AgentIdentity]:
    client = AgentDidClient()
    return client, AgentIdentity(AgentIdentityConfig(controller_signer=LocalKeySigner.generate()[0], client=client))


def test_content_digest_hashes_bytes_as_they_are_and_a_string_as_utf8() -> None:
    raw = bytes([0xFF, 0x00, 0xFE, 0x80])
    assert compute_content_digest(raw) != compute_content_digest(raw.decode("latin-1"))
    assert compute_content_digest("héllo") == compute_content_digest("héllo".encode())
    assert compute_content_digest(None) == compute_content_digest(b"")


async def test_signs_and_verifies_a_request_whose_body_is_not_valid_utf8() -> None:
    client, identity = _identity()
    result = await identity.create(CreateAgentParams(name="BinaryBot", core_model="m", system_prompt="p"))
    body = bytes([0xFF, 0x00, 0xFE, 0x80, 0x01])
    url = "https://api.example.com/v1/upload"
    headers = await identity.sign_http_request(
        SignHttpRequestParams(
            method="PUT",
            url=url,
            body=body,
            agent_private_key=result.agent_private_key,
            agent_did=result.document.id,
            verification_method_id=result.document.authentication[0],
        )
    )

    ok = await client.verify_http_request_signature_detailed(
        VerifyHttpRequestSignatureParams(method="PUT", url=url, body=body, headers=headers)
    )
    assert ok.ok is True
    changed = await client.verify_http_request_signature_detailed(
        VerifyHttpRequestSignatureParams(method="PUT", url=url, body=body[:-1] + b"\x02", headers=headers)
    )
    assert changed.ok is False
    assert changed.reason == "digest_mismatch"


async def test_concurrent_creates_share_one_bootstrap_controller() -> None:
    _, identity = _identity()
    created = await asyncio.gather(
        *(
            identity.create(CreateAgentParams(name=name, core_model="m", system_prompt="p"))
            for name in ("ConcurrentOne", "ConcurrentTwo", "ConcurrentThree")
        )
    )

    assert len({result.document.controller for result in created}) == 1
    # the controller key is returned once, to the create that made the controller
    assert len([result for result in created if result.controller_private_key]) == 1


def test_filesystem_source_requires_a_root_directory_or_a_mapping() -> None:
    with pytest.raises(TypeError):
        FilesystemDIDDocumentSource()
    with pytest.raises(TypeError):
        FilesystemDIDDocumentSource(FilesystemDIDDocumentSourceConfig())


async def test_filesystem_source_keeps_every_reference_inside_the_root_directory(tmp_path: Path) -> None:
    source = FilesystemDIDDocumentSource(FilesystemDIDDocumentSourceConfig(root_directory=tmp_path))
    _, identity = _identity()
    document = (await identity.create(CreateAgentParams(name="FsBot", core_model="m", system_prompt="p"))).document
    for reference in ("hash://sha256/abc", "../../escape", "/etc/passwd", "C:\\Windows\\win.ini", ".."):
        await source.store_by_reference(reference, document)
        stored = await source.get_by_reference(reference)
        assert stored is not None
        assert stored.id == document.id
    files = [entry.name for entry in tmp_path.iterdir()]
    assert len(files) == 5
    assert all(re.fullmatch(r"[A-Za-z0-9._-]+\.json", name) and not name.startswith("..") for name in files)
