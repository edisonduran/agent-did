"""Shared AgentMetadataCredential vectors (fixtures/agent-metadata-credential-vectors.json, RFC-001 §4.4).

TypeScript parity: sdk/tests/AgentMetadataCredentialVectors.test.ts.
"""

from __future__ import annotations

import copy
import json
import pathlib
from typing import Any

import pytest

from agent_did_sdk.core.agent_metadata_credential import (
    build_unsigned_agent_metadata_credential,
    check_agent_metadata_credential_form,
)
from agent_did_sdk.core.signer import LocalKeySigner
from agent_did_sdk.crypto.data_integrity import (
    create_eddsa_jcs_2022_proof,
    eddsa_jcs_2022_hash_data,
    verify_eddsa_jcs_2022_proof,
)
from agent_did_sdk.crypto.multibase import decode_public_key_multibase
from agent_did_sdk.verification.key_at_time import parse_rfc3339_millis

_VECTORS: dict[str, Any] = json.loads(
    (pathlib.Path(__file__).resolve().parents[2] / "fixtures" / "agent-metadata-credential-vectors.json").read_text(
        encoding="utf-8"
    )
)


def _mutate(credential: dict[str, Any], mutation: dict[str, Any]) -> None:
    target: Any = credential
    for part in mutation["path"][:-1]:
        target = target[part]
    last = mutation["path"][-1]
    if mutation["op"] == "delete":
        del target[last]
    else:
        target[last] = [credential["proof"]] if mutation.get("value") == "$proofSet" else mutation.get("value")


def _outcome(case: dict[str, Any]) -> str:
    credential: object
    if "replace" in case:
        credential = case["replace"]
    else:
        mutated = copy.deepcopy(_VECTORS["credential"])
        for mutation in case["mutations"]:
            _mutate(mutated, mutation)
        credential = mutated
    now = parse_rfc3339_millis(case.get("now", _VECTORS["now"]))
    assert now is not None
    form = check_agent_metadata_credential_form(credential, now)
    if isinstance(form, str):
        return form
    public_key = decode_public_key_multibase(_VECTORS["publicKeyMultibase"])
    return "ok" if verify_eddsa_jcs_2022_proof(credential, public_key) else "signature_invalid"


async def test_builds_and_signs_the_credential_byte_for_byte() -> None:
    issue = _VECTORS["issue"]
    signer = LocalKeySigner(_VECTORS["seedHex"])
    unsigned = build_unsigned_agent_metadata_credential(
        issuer=issue["issuer"],
        agent_did=issue["agentDid"],
        agent_metadata=issue["agentMetadata"],
        valid_from=issue["validFrom"],
        valid_until=issue["validUntil"],
        credential_id=issue["id"],
    )

    async def sign(hash_data: bytes) -> bytes:
        return bytes.fromhex(await signer.sign(hash_data))

    proof = await create_eddsa_jcs_2022_proof(
        unsigned,
        created=issue["created"],
        verification_method=issue["verificationMethod"],
        proof_purpose="assertionMethod",
        sign=sign,
    )
    config = {key: value for key, value in _VECTORS["credential"]["proof"].items() if key != "proofValue"}
    assert eddsa_jcs_2022_hash_data(unsigned, config).hex() == _VECTORS["hashDataHex"]
    # Same members in the same order as the TypeScript SDK and the generator
    assert json.dumps({**unsigned, "proof": proof}) == json.dumps(_VECTORS["credential"])


@pytest.mark.parametrize("case", _VECTORS["cases"], ids=[case["name"] for case in _VECTORS["cases"]])
def test_case(case: dict[str, Any]) -> None:
    assert _outcome(case) == case["expected"]
