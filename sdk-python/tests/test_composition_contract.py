"""Composition contract: single-key retirement, emergency revocation, signed Agent Cards and the request-against-card
check with the contract reasons (parity: sdk/tests/CompositionContract.test.ts)."""

from __future__ import annotations

import copy
import json
from datetime import datetime, timedelta, timezone
from typing import Any

import pytest
from pydantic import ValidationError

from agent_did_sdk import (
    AGENT_DID_A2A_EXTENSION_URI,
    REVOKED_CONTEXT_TERM,
    AgentDIDDocument,
    VerifyIdentityCompositionParams,
    parse_signed_agent_card,
    sign_agent_card,
)
from agent_did_sdk.core.agent_card import base64url_to_bytes, bytes_to_base64url
from agent_did_sdk.core.client import AgentDidClient, AgentDidClientOptions
from agent_did_sdk.core.identity import AgentIdentity, AgentIdentityConfig
from agent_did_sdk.core.message_signing import message_signing_input
from agent_did_sdk.core.nonce_store import InMemoryNonceStore
from agent_did_sdk.core.signer import LocalKeySigner
from agent_did_sdk.core.types import CreateAgentParams, SignHttpRequestParams

REQUEST = {"method": "POST", "url": "https://agent.example.com/a2a", "body": '{"task":1}'}
BOTH = ["authentication", "assertionMethod"]


class _Setup:
    def __init__(
        self, client: AgentDidClient, identity: AgentIdentity, did: str, key_id: str, signer: LocalKeySigner
    ) -> None:
        self.client, self.identity, self.did = client, identity, did
        self.first_key_id, self.first_signer = key_id, signer


async def _setup() -> _Setup:
    client = AgentDidClient(AgentDidClientOptions(nonce_store=InMemoryNonceStore()))
    identity = AgentIdentity(AgentIdentityConfig(controller_signer=LocalKeySigner.generate()[0], client=client))
    created = await identity.create(CreateAgentParams(name="CardBot", core_model="test", system_prompt="test"))
    assert created.document.assertion_method
    return _Setup(
        client, identity, created.document.id, created.document.assertion_method[0],
        LocalKeySigner(created.agent_private_key),
    )


def _card(did: str, key_ids: list[str]) -> dict[str, Any]:
    return {
        "name": "CardBot",
        "description": "Test agent",
        "version": "1.0.0",
        "capabilities": {
            "extensions": [{"uri": AGENT_DID_A2A_EXTENSION_URI, "params": {"did": did, "keyIds": key_ids}}]
        },
        "skills": [],
    }


async def _request(identity: AgentIdentity, did: str, key_id: str, signer: LocalKeySigner) -> dict[str, Any]:
    headers = await identity.sign_http_request(
        SignHttpRequestParams(**REQUEST, agent_did=did, signer=signer, verification_method_id=key_id)
    )
    return {**REQUEST, "headers": headers}


def _params(request: dict[str, Any], card: object) -> VerifyIdentityCompositionParams:
    return VerifyIdentityCompositionParams(**request, agent_card=card)


def _method(document: AgentDIDDocument, key_id: str) -> Any:
    return next(vm for vm in document.verification_method if vm.id == key_id)


# --- retire_verification_method ---------------------------------------------------------------------


async def test_retires_one_key_and_keeps_the_others() -> None:
    s = await _setup()
    added = await s.client.add_verification_method(s.did, relationships=BOTH)  # type: ignore[arg-type]
    document = await s.client.retire_verification_method(s.did, s.first_key_id)
    method = _method(document, s.first_key_id)
    assert method.deactivated is not None and method.revoked is None
    assert document.assertion_method == [added.verification_method_id]
    assert document.authentication == [added.verification_method_id]
    assert REVOKED_CONTEXT_TERM not in document.context


async def test_revokes_a_key_in_an_emergency_and_adds_the_inline_context_term() -> None:
    s = await _setup()
    await s.client.add_verification_method(s.did, relationships=BOTH)  # type: ignore[arg-type]
    document = await s.client.retire_verification_method(s.did, s.first_key_id, emergency=True)
    method = _method(document, s.first_key_id)
    assert method.revoked == method.deactivated
    assert document.context[-1] == REVOKED_CONTEXT_TERM


async def test_revokes_a_key_that_was_already_retired() -> None:
    s = await _setup()
    await s.client.add_verification_method(s.did, relationships=BOTH)  # type: ignore[arg-type]
    retired = await s.client.retire_verification_method(s.did, s.first_key_id)
    deactivated = _method(retired, s.first_key_id).deactivated
    revoked = await s.client.retire_verification_method(s.did, s.first_key_id, emergency=True)
    assert _method(revoked, s.first_key_id).deactivated == deactivated
    assert _method(revoked, s.first_key_id).revoked is not None
    with pytest.raises(ValueError, match="already revoked"):
        await s.client.retire_verification_method(s.did, s.first_key_id, emergency=True)


async def test_refuses_the_last_key_an_unknown_key_and_a_retired_key() -> None:
    s = await _setup()
    with pytest.raises(ValueError, match="last authentication key"):
        await s.client.retire_verification_method(s.did, s.first_key_id)
    with pytest.raises(ValueError, match="not a verification method"):
        await s.client.retire_verification_method(s.did, f"{s.did}#key-9")
    await s.client.add_verification_method(s.did, relationships=BOTH)  # type: ignore[arg-type]
    await s.client.retire_verification_method(s.did, s.first_key_id)
    with pytest.raises(ValueError, match="already retired"):
        await s.client.retire_verification_method(s.did, s.first_key_id)


async def test_revokes_every_old_key_on_an_emergency_rotation() -> None:
    s = await _setup()
    rotated = await s.client.rotate_verification_method(s.did, emergency=True)
    method = _method(rotated.document, s.first_key_id)
    assert method.revoked == method.deactivated
    planned = await s.client.rotate_verification_method(s.did)
    assert _method(planned.document, s.first_key_id).revoked is not None
    assert _method(planned.document, rotated.verification_method_id).revoked is None


async def test_a_revoked_key_is_not_authorized_at_any_stated_time() -> None:
    s = await _setup()
    stated = (datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat().replace("+00:00", "Z")
    signature = await s.first_signer.sign(message_signing_input("approve"))
    await s.client.add_verification_method(s.did, relationships=BOTH)  # type: ignore[arg-type]

    await s.client.retire_verification_method(s.did, s.first_key_id)
    now = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    retired = await s.client.verify_signature_at_time(s.did, "approve", signature, s.first_key_id, stated_time=now)
    assert retired.status != "valid"

    await s.client.retire_verification_method(s.did, s.first_key_id, emergency=True)
    revoked = await s.client.verify_signature_at_time(
        s.did, "approve", signature, s.first_key_id, stated_time=stated, trusted_time_not_after=stated
    )
    assert revoked.status == "invalid"
    assert revoked.key.status == "not_authorized" and revoked.key.reason == "key_revoked"


async def test_document_model_rejects_inconsistent_revocation() -> None:
    s = await _setup()
    await s.client.add_verification_method(s.did, relationships=BOTH)  # type: ignore[arg-type]
    document = (await s.client.retire_verification_method(s.did, s.first_key_id, emergency=True)).model_dump_jsonld()

    without_term = {**document, "@context": document["@context"][:-1]}  # type: ignore[index]
    with pytest.raises(ValidationError, match="must end with the inline revoked term"):
        AgentDIDDocument.model_validate(without_term)

    not_retired = copy.deepcopy(document)
    del not_retired["verificationMethod"][0]["deactivated"]  # type: ignore[index]
    with pytest.raises(ValidationError, match="revoked requires deactivated"):
        AgentDIDDocument.model_validate(not_retired)

    stray = copy.deepcopy(document)
    del stray["verificationMethod"][0]["revoked"]  # type: ignore[index]
    with pytest.raises(ValidationError, match="no key is revoked"):
        AgentDIDDocument.model_validate(stray)

    other_term = {**document, "@context": [*document["@context"][:-1], {"revoked": "x"}]}  # type: ignore[index]
    with pytest.raises(ValidationError, match=r"@context\[\d+\] must be a string"):
        AgentDIDDocument.model_validate(other_term)


# --- signed Agent Cards -------------------------------------------------------------------------------


async def test_signs_as_an_a2a_jws_over_the_jcs_form_without_signatures() -> None:
    s = await _setup()
    signed = await sign_agent_card(_card(s.did, [s.first_key_id]), s.first_signer, s.first_key_id)
    assert len(signed["signatures"]) == 1
    header_bytes = base64url_to_bytes(signed["signatures"][0]["protected"])
    assert header_bytes is not None
    assert json.loads(header_bytes) == {"alg": "EdDSA", "kid": s.first_key_id, "typ": "JOSE"}
    parsed = parse_signed_agent_card(signed)
    assert parsed is not None and parsed.did == s.did and parsed.published_key_ids == (s.first_key_id,)


async def test_verifies_a_signed_card_and_rejects_a_changed_one_as_tampered() -> None:
    s = await _setup()
    signed = await sign_agent_card(_card(s.did, [s.first_key_id]), s.first_signer, s.first_key_id)
    ok = await s.client.verify_agent_card(signed)
    assert ok.ok and ok.did == s.did and ok.published_key_ids == (s.first_key_id,)
    changed = await s.client.verify_agent_card({**signed, "name": "Other"})
    assert (changed.ok, changed.reason, changed.key_id) == (False, "tampered", s.first_key_id)


async def test_reports_format_drift_for_unsigned_cards_and_malformed_signatures() -> None:
    s = await _setup()
    signed = await sign_agent_card(_card(s.did, [s.first_key_id]), s.first_signer, s.first_key_id)
    entry = signed["signatures"][0]

    def header(**members: Any) -> str:
        return bytes_to_base64url(json.dumps({"alg": "EdDSA", "kid": s.first_key_id, **members}).encode())

    other_ext = {"extensions": [{"uri": AGENT_DID_A2A_EXTENSION_URI, "params": {"did": "did:webvh:x:y", "keyIds": []}}]}
    cases: list[object] = [
        _card(s.did, [s.first_key_id]),
        [],
        {**signed, "signatures": []},
        {**signed, "signatures": [{**entry, "protected": header(alg="ES256")}]},
        {**signed, "signatures": [{**entry, "protected": header(crit=["b64"])}]},
        {**signed, "signatures": [{**entry, "protected": header(kid=s.did)}]},
        {**signed, "signatures": [{**entry, "signature": entry["signature"] + "="}]},
        {**signed, "signatures": [{**entry, "extra": 1}]},
        {**signed, "capabilities": other_ext},
    ]
    for value in cases:
        result = await s.client.verify_agent_card(value)
        assert (result.ok, result.reason) == (False, "format_drift"), value


# --- verify_identity_composition ----------------------------------------------------------------------


async def test_f1_accepts_the_current_key_published_by_the_card() -> None:
    s = await _setup()
    card = await sign_agent_card(_card(s.did, [s.first_key_id]), s.first_signer, s.first_key_id)
    result = await s.client.verify_identity_composition(
        _params(await _request(s.identity, s.did, s.first_key_id, s.first_signer), card)
    )
    assert result.ok and result.did == s.did and result.key_id == s.first_key_id


async def test_f2_accepts_the_prior_key_during_a_planned_overlap() -> None:
    s = await _setup()
    new_signer = LocalKeySigner.generate()[0]
    added = await s.client.add_verification_method(s.did, signer=new_signer, relationships=BOTH)  # type: ignore[arg-type]
    card = await sign_agent_card(
        _card(s.did, [s.first_key_id, added.verification_method_id]), new_signer, added.verification_method_id
    )
    result = await s.client.verify_identity_composition(
        _params(await _request(s.identity, s.did, s.first_key_id, s.first_signer), card)
    )
    assert result.ok and result.key_id == s.first_key_id


async def test_f3_rejects_a_key_the_card_does_not_publish() -> None:
    s = await _setup()
    new_signer = LocalKeySigner.generate()[0]
    added = await s.client.add_verification_method(s.did, signer=new_signer, relationships=BOTH)  # type: ignore[arg-type]
    card = await sign_agent_card(_card(s.did, [added.verification_method_id]), new_signer, added.verification_method_id)
    result = await s.client.verify_identity_composition(
        _params(await _request(s.identity, s.did, s.first_key_id, s.first_signer), card)
    )
    assert (result.ok, result.stage, result.reason, result.key_id) == (
        False, "request", "card_keyid_mismatch", s.first_key_id
    )


async def test_f4_f5_retired_and_revoked_prior_keys() -> None:
    s = await _setup()
    new_signer = LocalKeySigner.generate()[0]
    added = await s.client.add_verification_method(s.did, signer=new_signer, relationships=BOTH)  # type: ignore[arg-type]
    card = await sign_agent_card(
        _card(s.did, [s.first_key_id, added.verification_method_id]), new_signer, added.verification_method_id
    )

    await s.client.retire_verification_method(s.did, s.first_key_id)
    retired = await s.client.verify_identity_composition(
        _params(await _request(s.identity, s.did, s.first_key_id, s.first_signer), card)
    )
    assert (retired.ok, retired.stage, retired.reason, retired.key_id) == (
        False, "request", "rotation_window_closed", s.first_key_id
    )

    await s.client.retire_verification_method(s.did, s.first_key_id, emergency=True)
    revoked = await s.client.verify_identity_composition(
        _params(await _request(s.identity, s.did, s.first_key_id, s.first_signer), card)
    )
    assert (revoked.ok, revoked.stage, revoked.reason) == (False, "request", "emergency_revoked")


async def test_f5_rejects_a_card_signed_by_a_revoked_key() -> None:
    s = await _setup()
    card = await sign_agent_card(_card(s.did, [s.first_key_id]), s.first_signer, s.first_key_id)
    await s.client.rotate_verification_method(s.did, emergency=True)
    result = await s.client.verify_agent_card(card)
    assert (result.ok, result.reason, result.key_id) == (False, "emergency_revoked", s.first_key_id)


async def test_f6_rejects_a_key_that_is_not_an_assertion_method_key() -> None:
    s = await _setup()
    invoke_signer = LocalKeySigner.generate()[0]
    added = await s.client.add_verification_method(
        s.did, signer=invoke_signer, relationships=["capabilityInvocation"]
    )
    card = await sign_agent_card(
        _card(s.did, [s.first_key_id, added.verification_method_id]), s.first_signer, s.first_key_id
    )
    result = await s.client.verify_identity_composition(
        _params(await _request(s.identity, s.did, added.verification_method_id, invoke_signer), card)
    )
    assert (result.ok, result.stage, result.reason, result.http_reason) == (
        False, "request", "key_purpose_violation", "keyid_not_authorized"
    )


async def test_another_agent_did_and_other_http_failures() -> None:
    s = await _setup()
    card = await sign_agent_card(_card(s.did, [s.first_key_id]), s.first_signer, s.first_key_id)
    other = await s.identity.create(CreateAgentParams(name="OtherBot", core_model="test", system_prompt="test"))
    assert other.document.assertion_method
    other_key_id = other.document.assertion_method[0]
    foreign = await _request(s.identity, other.document.id, other_key_id, LocalKeySigner(other.agent_private_key))
    mismatch = await s.client.verify_identity_composition(_params(foreign, card))
    assert (mismatch.ok, mismatch.stage, mismatch.reason, mismatch.key_id) == (
        False, "request", "card_keyid_mismatch", other_key_id
    )

    request = await _request(s.identity, s.did, s.first_key_id, s.first_signer)
    assert (await s.client.verify_identity_composition(_params(request, card))).ok
    replay = await s.client.verify_identity_composition(_params(request, card))
    assert (replay.ok, replay.stage, replay.reason, replay.http_reason) == (
        False, "request", "request_rejected", "nonce_replayed"
    )


async def test_checks_the_card_first_so_a_bad_card_does_not_consume_the_nonce() -> None:
    s = await _setup()
    card = await sign_agent_card(_card(s.did, [s.first_key_id]), s.first_signer, s.first_key_id)
    request = await _request(s.identity, s.did, s.first_key_id, s.first_signer)
    bad = await s.client.verify_identity_composition(_params(request, {**card, "name": "x"}))
    assert (bad.ok, bad.stage, bad.reason) == (False, "agent_card", "tampered")
    assert (await s.client.verify_identity_composition(_params(request, card))).ok
