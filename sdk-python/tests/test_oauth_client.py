"""The OAuth bridge (RFC-001 §6.8, ADR-008 D-12c/e); parity: sdk/tests/OAuthClientAssertion.test.ts."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

import pytest
from nacl.signing import SigningKey

from agent_did_sdk import (
    CLIENT_ASSERTION_TYPE,
    AgentDidClient,
    AgentDidClientOptions,
    build_client_jwks,
    build_client_metadata_document,
    create_client_assertion,
)
from agent_did_sdk.core.agent_card import base64url_to_bytes, bytes_to_base64url
from agent_did_sdk.core.identity import AgentIdentity, AgentIdentityConfig
from agent_did_sdk.core.signer import LocalKeySigner
from agent_did_sdk.core.types import CreateAgentParams, CreateAgentResult

ISSUER = "https://auth.example.com"
CLIENT_ID = "https://agents.example.com/bob/client.json"
NOW = 1_800_000_000


async def _setup() -> tuple[AgentDidClient, CreateAgentResult, str, str, LocalKeySigner]:
    client = AgentDidClient(AgentDidClientOptions(clock=lambda: datetime.fromtimestamp(NOW, timezone.utc)))
    identity = AgentIdentity(AgentIdentityConfig(controller_signer=LocalKeySigner.generate()[0], client=client))
    created = await identity.create(CreateAgentParams(name="Bob"))
    did = created.document.id
    return client, created, did, f"{did}#key-1", LocalKeySigner(created.agent_private_key)


def _decode(segment: str) -> dict[str, Any]:
    raw = base64url_to_bytes(segment)
    assert raw is not None
    value: dict[str, Any] = json.loads(raw)
    return value


def _resign(assertion: str, private_key_hex: str, header: dict[str, Any] | None = None,
            claims: dict[str, Any] | None = None) -> str:
    h, c, _ = assertion.split(".")
    head = header if header is not None else _decode(h)
    body = claims if claims is not None else _decode(c)
    signing_input = (
        bytes_to_base64url(json.dumps(head).encode()) + "." + bytes_to_base64url(json.dumps(body).encode())
    )
    signature = SigningKey(bytes.fromhex(private_key_hex)).sign(signing_input.encode()).signature
    return f"{signing_input}.{bytes_to_base64url(signature)}"


async def test_creates_a_typed_assertion_and_verifies_it_against_the_did() -> None:
    client, _created, did, key_id, signer = await _setup()
    assertion = await create_client_assertion(
        client_id=CLIENT_ID, issuer=ISSUER, verification_method_id=key_id, signer=signer, issued_at=NOW, jti="j-1"
    )
    header, claims, _ = assertion.split(".")
    assert _decode(header) == {"alg": "EdDSA", "kid": key_id, "typ": CLIENT_ASSERTION_TYPE}
    assert _decode(claims) == {
        "iss": CLIENT_ID, "sub": CLIENT_ID, "aud": ISSUER, "jti": "j-1", "iat": NOW, "exp": NOW + 60
    }
    result = await client.verify_client_assertion(assertion, issuer=ISSUER, client_id=CLIENT_ID, did=did)
    assert result.ok and result.did == did and result.key_id == key_id and result.jti == "j-1"
    assert result.expires_at == NOW + 60
    again = await client.verify_client_assertion(assertion, issuer=ISSUER, client_id=CLIENT_ID, did=did)
    assert again.reason == "jti_replayed"


async def test_signs_with_alg_ed25519_on_request_deterministically() -> None:
    client, _created, did, key_id, signer = await _setup()
    params: dict[str, Any] = {
        "client_id": CLIENT_ID, "issuer": ISSUER, "verification_method_id": key_id, "signer": signer,
        "issued_at": NOW, "jti": "j-2", "jws_alg": "Ed25519",
    }
    first = await create_client_assertion(**params)
    assert await create_client_assertion(**params) == first
    assert _decode(first.split(".")[0])["alg"] == "Ed25519"
    assert (await client.verify_client_assertion(first, issuer=ISSUER, client_id=CLIENT_ID, did=did)).ok


async def test_refuses_bad_creation_parameters() -> None:
    _client, _created, _did, key_id, signer = await _setup()
    base: dict[str, Any] = {
        "client_id": CLIENT_ID, "issuer": ISSUER, "verification_method_id": key_id, "signer": signer
    }
    with pytest.raises(ValueError):
        await create_client_assertion(**base, lifetime_seconds=301)
    with pytest.raises(TypeError, match="DID URL"):
        await create_client_assertion(**{**base, "verification_method_id": "did:example:x"})
    with pytest.raises(TypeError, match="issuer"):
        await create_client_assertion(**{**base, "issuer": ""})
    with pytest.raises(TypeError, match="jws_alg"):
        await create_client_assertion(**base, jws_alg="ES256")  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("change", "reason"),
    [
        ({"claims": {"aud": [ISSUER]}}, "audience_invalid"),
        ({"claims": {"aud": f"{ISSUER}/token"}}, "audience_invalid"),
        ({"claims": {"sub": "other"}}, "client_id_mismatch"),
        ({"claims": {"iss": "other"}}, "client_id_mismatch"),
        ({"claims": {"exp": NOW + 301}}, "lifetime_exceeded"),
        ({"claims": {"exp": NOW - 1}}, "lifetime_exceeded"),
        ({"claims": {"iat": NOW + 100, "exp": NOW + 160}}, "not_yet_valid"),
        ({"claims": {"nbf": NOW + 100}}, "not_yet_valid"),
        ({"claims": {"iat": NOW - 200, "exp": NOW - 100}}, "expired"),
        ({"header": {"typ": "JWT"}}, "type_invalid"),
        ({"header": {"alg": "ES256"}}, "alg_unsupported"),
        ({"header": {"alg": "none"}}, "alg_unsupported"),
        ({"header": {"crit": ["exp"]}}, "malformed_assertion"),
        ({"header": {"kid": "did:webvh:other:example.com#key-1"}}, "kid_not_bound"),
        ({"claims": {"jti": 7}}, "malformed_assertion"),
    ],
)
async def test_rejects(change: dict[str, dict[str, Any]], reason: str) -> None:
    client, created, did, key_id, signer = await _setup()
    assertion = await create_client_assertion(
        client_id=CLIENT_ID, issuer=ISSUER, verification_method_id=key_id, signer=signer, issued_at=NOW, jti="j-3"
    )
    h, c, _ = assertion.split(".")
    forged = _resign(
        assertion,
        created.agent_private_key,
        header={**_decode(h), **change["header"]} if "header" in change else None,
        claims={**_decode(c), **change["claims"]} if "claims" in change else None,
    )
    result = await client.verify_client_assertion(forged, issuer=ISSUER, client_id=CLIENT_ID, did=did)
    assert result.reason == reason


async def test_accepts_untyped_and_application_typ_and_rejects_a_bad_signature() -> None:
    client, created, did, key_id, signer = await _setup()
    assertion = await create_client_assertion(
        client_id=CLIENT_ID, issuer=ISSUER, verification_method_id=key_id, signer=signer, issued_at=NOW, jti="j-4"
    )
    h, c, _ = assertion.split(".")
    untyped_header = {k: v for k, v in _decode(h).items() if k != "typ"}
    untyped = _resign(assertion, created.agent_private_key, header=untyped_header)
    assert (await client.verify_client_assertion(untyped, issuer=ISSUER, client_id=CLIENT_ID, did=did)).ok
    app = _resign(
        assertion,
        created.agent_private_key,
        header={**_decode(h), "typ": "application/Client-Authentication+JWT"},
        claims={**_decode(c), "jti": "j-5"},
    )
    assert (await client.verify_client_assertion(app, issuer=ISSUER, client_id=CLIENT_ID, did=did)).ok
    bad = f"{h}.{c}.{bytes_to_base64url(bytes(64))}"
    assert (await client.verify_client_assertion(bad, issuer=ISSUER, client_id=CLIENT_ID, did=did)).reason == (
        "signature_invalid"
    )
    assert (await client.verify_client_assertion("a.b", issuer=ISSUER, client_id=CLIENT_ID, did=did)).reason == (
        "malformed_assertion"
    )


async def test_rejects_a_key_not_under_authentication() -> None:
    client, _created, did, _key_id, signer = await _setup()
    assertion = await create_client_assertion(
        client_id=CLIENT_ID, issuer=ISSUER, verification_method_id=f"{did}#key-9", signer=signer, issued_at=NOW,
        jti="j-6",
    )
    result = await client.verify_client_assertion(assertion, issuer=ISSUER, client_id=CLIENT_ID, did=did)
    assert result.reason == "key_not_authorized"


async def test_exports_a_jwks_and_a_client_id_metadata_document() -> None:
    _client, created, did, key_id, signer = await _setup()
    jwks = build_client_jwks(created.document)
    x = bytes_to_base64url(await signer.get_public_key())
    assert jwks == {"keys": [{"kty": "OKP", "crv": "Ed25519", "x": x, "kid": key_id, "use": "sig"}]}
    metadata = build_client_metadata_document(client_id=CLIENT_ID, client_name="Bob", did_document=created.document)
    assert metadata == {
        "client_id": CLIENT_ID,
        "client_name": "Bob",
        "grant_types": ["client_credentials"],
        "token_endpoint_auth_method": "private_key_jwt",
        "token_endpoint_auth_signing_alg": "EdDSA",
        "agent_did": did,
        "jwks": jwks,
    }
    with_uri = build_client_metadata_document(
        client_id=CLIENT_ID, client_name="Bob", did_document=created.document, jwks_uri=f"{CLIENT_ID}.jwks"
    )
    assert with_uri["jwks_uri"] == f"{CLIENT_ID}.jwks" and "jwks" not in with_uri
    with pytest.raises(TypeError, match="https"):
        build_client_metadata_document(client_id="http://agents.example.com/c", client_name="Bob",
                                       did_document=created.document)
    with pytest.raises(TypeError, match="path"):
        build_client_metadata_document(client_id="https://agents.example.com/", client_name="Bob",
                                       did_document=created.document)


async def test_pyjwt_verifies_our_assertion_against_the_exported_jwks() -> None:
    import jwt

    _client, created, _did, key_id, signer = await _setup()
    assertion = await create_client_assertion(
        client_id=CLIENT_ID, issuer=ISSUER, verification_method_id=key_id, signer=signer, issued_at=NOW, jti="x-1"
    )
    jwk = build_client_jwks(created.document)["keys"][0]
    key = jwt.PyJWK(jwk, algorithm="EdDSA")
    claims = jwt.decode(
        assertion,
        key,
        algorithms=["EdDSA"],
        audience=ISSUER,
        issuer=CLIENT_ID,
        options={"verify_exp": False, "verify_iat": False},
    )
    assert claims["sub"] == CLIENT_ID and claims["jti"] == "x-1"
    assert jwt.get_unverified_header(assertion) == {"alg": "EdDSA", "kid": key_id, "typ": CLIENT_ASSERTION_TYPE}


async def test_accepts_an_assertion_that_pyjwt_signed_with_the_agent_key() -> None:
    import jwt
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    client, created, did, key_id, _signer = await _setup()
    private_key = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(created.agent_private_key))
    assertion = jwt.encode(
        {"iss": CLIENT_ID, "sub": CLIENT_ID, "aud": ISSUER, "jti": "x-2", "iat": NOW, "exp": NOW + 60},
        private_key,
        algorithm="EdDSA",
        headers={"kid": key_id, "typ": CLIENT_ASSERTION_TYPE},
    )
    result = await client.verify_client_assertion(assertion, issuer=ISSUER, client_id=CLIENT_ID, did=did)
    assert result.ok and result.key_id == key_id and result.jti == "x-2"
