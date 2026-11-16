"""The OAuth bridge (RFC-001 §6.8, ADR-008 D-12c/e): the agent's DID key as an OAuth client credential.

* ``create_client_assertion``: a JWT client assertion (``private_key_jwt``, RFC 7523 as updated by
  draft-ietf-oauth-rfc7523bis): ``typ: client-authentication+jwt``, ``iss`` = ``sub`` = client id, ``aud`` = the
  authorization server's issuer identifier as its only value, signed by an ``authentication`` key of the DID.
* ``build_client_jwks`` / ``build_client_metadata_document``: the keys and the OAuth Client ID Metadata Document an
  authorization server that does not know DIDs reads.
* The check of an assertion against the DID is ``AgentDidClient.verify_client_assertion``;
  ``parse_client_assertion`` here holds the checks that need no resolution.

The SDK runs no OAuth flow: no discovery, no token request. Aligned with RFC 7523, draft-ietf-oauth-rfc7523bis and
draft-ietf-oauth-client-id-metadata-document; no conformance is claimed.

TypeScript parity: ``sdk/src/core/oauth-client.ts``.
"""

from __future__ import annotations

import json
import re
import secrets
import time
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit

from ..crypto.hash import canonicalize_json
from .agent_card import base64url_to_bytes, bytes_to_base64url, did_of_key_id
from .signer import AgentSigner, LocalKeySigner
from .types import AnyDidDocument, ClientAssertionRejection, JwsEd25519Alg
from .verification_method import active_ed25519_public_key, relationship_methods

CLIENT_ASSERTION_TYPE = "client-authentication+jwt"
"""``typ`` of a client assertion (draft-ietf-oauth-rfc7523bis)."""

CLIENT_ASSERTION_TYPE_JWT_BEARER = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
"""``client_assertion_type`` of a token request that carries a JWT client assertion (RFC 7523 §2.2)."""

DEFAULT_CLIENT_ASSERTION_LIFETIME_SECONDS = 60
"""Default lifetime of a client assertion, in seconds."""

MAX_CLIENT_ASSERTION_LIFETIME_SECONDS = 300
"""Longest lifetime (``exp - iat``) a client assertion may have, in seconds."""

MAX_CLIENT_ASSERTION_LENGTH = 8192
"""Upper bound, in characters, on an assertion a verifier parses."""

_JWS_ALGS: tuple[JwsEd25519Alg, ...] = ("EdDSA", "Ed25519")
_JTI_PATTERN = re.compile(r"[\x21-\x7e]{1,256}")


def _encode_segment(value: dict[str, Any]) -> str:
    return bytes_to_base64url(canonicalize_json(value).encode("utf-8"))


def _is_integer_seconds(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and 0 <= value <= 2**53 - 1


def _integer_seconds(value: object) -> object:
    """A JSON number that is an integer (``1.0`` or ``1e9`` as ECMAScript reads them) as an ``int``."""
    if isinstance(value, float) and value.is_integer():
        return int(value)
    return value


def _reject_constant(name: str) -> object:
    raise ValueError(f"{name} is not JSON")


async def create_client_assertion(
    *,
    client_id: str,
    issuer: str,
    verification_method_id: str,
    signer: AgentSigner | None = None,
    agent_private_key: str | None = None,
    lifetime_seconds: int = DEFAULT_CLIENT_ASSERTION_LIFETIME_SECONDS,
    jws_alg: JwsEd25519Alg = "EdDSA",
    issued_at: int | None = None,
    jti: str | None = None,
) -> str:
    """A JWT client assertion signed with the agent's DID key (RFC-001 §6.8).

    *issuer* is the authorization server's issuer identifier (RFC 8414), never its token endpoint.
    *verification_method_id* must be an Ed25519 ``authentication`` key of the agent DID:
    ``AgentDidClient.verify_client_assertion`` rejects any other key. Send it as ``client_assertion`` with
    ``client_assertion_type`` = ``CLIENT_ASSERTION_TYPE_JWT_BEARER``. *issued_at* and *jti* are for tests and vectors.
    """
    if not isinstance(client_id, str) or not client_id:
        raise TypeError("client_id is required")
    if not isinstance(issuer, str) or not issuer:
        raise TypeError("issuer (the authorization server issuer identifier) is required")
    if did_of_key_id(verification_method_id) is None:
        raise TypeError(f"verification_method_id must be a DID URL with a fragment: {verification_method_id!r}")
    if jws_alg not in _JWS_ALGS:
        raise TypeError(f"jws_alg must be one of {', '.join(_JWS_ALGS)}")
    if (
        not isinstance(lifetime_seconds, int)
        or isinstance(lifetime_seconds, bool)
        or not 1 <= lifetime_seconds <= MAX_CLIENT_ASSERTION_LIFETIME_SECONDS
    ):
        raise ValueError(f"lifetime_seconds must be an integer from 1 to {MAX_CLIENT_ASSERTION_LIFETIME_SECONDS}")
    iat = issued_at if issued_at is not None else int(time.time())
    if not _is_integer_seconds(iat):
        raise TypeError("issued_at must be a non-negative integer number of seconds")
    token_id = jti if jti is not None else secrets.token_hex(16)
    if not isinstance(token_id, str) or not _JTI_PATTERN.fullmatch(token_id):
        raise TypeError("jti must be 1 to 256 printable ASCII characters")
    key_signer: AgentSigner | None = signer
    if key_signer is None and agent_private_key:
        key_signer = LocalKeySigner(agent_private_key)
    if key_signer is None:
        raise ValueError("Either signer or agent_private_key must be provided")
    header = {"alg": jws_alg, "kid": verification_method_id, "typ": CLIENT_ASSERTION_TYPE}
    claims = {
        "iss": client_id,
        "sub": client_id,
        "aud": issuer,
        "jti": token_id,
        "iat": iat,
        "exp": iat + lifetime_seconds,
    }
    signing_input = f"{_encode_segment(header)}.{_encode_segment(claims)}"
    signature = bytes.fromhex(await key_signer.sign(signing_input.encode("ascii")))
    if len(signature) != 64:
        raise ValueError("An Ed25519 signature is 64 bytes")
    return f"{signing_input}.{bytes_to_base64url(signature)}"


@dataclass(frozen=True)
class ParsedClientAssertion:
    """A client assertion that passed the checks needing no resolution."""

    alg: JwsEd25519Alg
    key_id: str
    did: str
    jti: str
    issued_at: int
    expires_at: int
    signing_input: str
    signature: bytes


def _decode_json_segment(segment: str) -> dict[str, Any] | None:
    raw = base64url_to_bytes(segment)
    if raw is None:
        return None
    try:
        value = json.loads(raw.decode("utf-8"), parse_constant=_reject_constant)
    except (UnicodeDecodeError, ValueError):
        return None
    return value if isinstance(value, dict) else None


def _type_accepted(typ: object) -> bool:
    if typ is None:
        return True  # draft-ietf-oauth-rfc7523bis: servers should not reject an untyped assertion
    if not isinstance(typ, str):
        return False
    lowered = typ.lower()
    return lowered in (CLIENT_ASSERTION_TYPE, f"application/{CLIENT_ASSERTION_TYPE}")


def parse_client_assertion(
    assertion: object,
    *,
    client_id: str,
    issuer: str,
    did: str,
    now_seconds: int,
    max_clock_skew_seconds: int,
) -> ParsedClientAssertion | ClientAssertionRejection:
    """The checks of RFC-001 §6.8 that need no resolution, in order.

    Compact JWS form (``malformed_assertion``), ``alg`` (``alg_unsupported``), ``typ`` (``type_invalid``), ``kid`` a
    DID URL of the expected DID (``kid_not_bound``), ``iss`` and ``sub`` (``client_id_mismatch``), ``aud``
    (``audience_invalid``), times (``lifetime_exceeded``, ``not_yet_valid``, ``expired``). Never raises.
    """
    if not isinstance(assertion, str) or len(assertion) > MAX_CLIENT_ASSERTION_LENGTH:
        return "malformed_assertion"
    parts = assertion.split(".")
    if len(parts) != 3:
        return "malformed_assertion"
    header = _decode_json_segment(parts[0])
    claims = _decode_json_segment(parts[1])
    signature = base64url_to_bytes(parts[2])
    if header is None or claims is None or signature is None or len(signature) != 64:
        return "malformed_assertion"
    if "crit" in header or "b64" in header:
        return "malformed_assertion"
    alg = header.get("alg")
    if alg not in _JWS_ALGS:
        return "alg_unsupported"
    if not _type_accepted(header.get("typ")):
        return "type_invalid"
    key_id = header.get("kid")
    if did_of_key_id(key_id) != did:
        return "kid_not_bound"
    if claims.get("iss") != client_id or claims.get("sub") != client_id:
        return "client_id_mismatch"
    aud = claims.get("aud")
    if not isinstance(aud, str) or aud != issuer:
        return "audience_invalid"
    iat, exp = _integer_seconds(claims.get("iat")), _integer_seconds(claims.get("exp"))
    nbf, jti = _integer_seconds(claims.get("nbf")), claims.get("jti")
    nbf_invalid = "nbf" in claims and not _is_integer_seconds(nbf)
    if not _is_integer_seconds(iat) or not _is_integer_seconds(exp) or nbf_invalid:
        return "malformed_assertion"
    if not isinstance(jti, str) or not _JTI_PATTERN.fullmatch(jti):
        return "malformed_assertion"
    assert isinstance(iat, int) and isinstance(exp, int) and isinstance(key_id, str)
    if exp <= iat or exp - iat > MAX_CLIENT_ASSERTION_LIFETIME_SECONDS:
        return "lifetime_exceeded"
    skew = max_clock_skew_seconds
    if iat > now_seconds + skew or (isinstance(nbf, int) and nbf > now_seconds + skew):
        return "not_yet_valid"
    if now_seconds > exp + skew:
        return "expired"
    return ParsedClientAssertion(
        alg=alg,
        key_id=key_id,
        did=did,
        jti=jti,
        issued_at=iat,
        expires_at=exp,
        signing_input=f"{parts[0]}.{parts[1]}",
        signature=signature,
    )


def build_client_jwks(document: AnyDidDocument, *, alg: JwsEd25519Alg | None = None) -> dict[str, list[dict[str, str]]]:
    """The JWKS of the active Ed25519 ``authentication`` keys of *document*, ``kid`` = the key's DID URL.

    For a Client ID Metadata Document (``jwks`` or ``jwks_uri``) or a pre-registration. Republish it when the agent
    rotates a key: an authorization server caches it.
    """
    keys: list[dict[str, str]] = []
    seen: set[str] = set()
    for method in relationship_methods(document, "authentication"):
        public_key = active_ed25519_public_key(method)
        if public_key is None or method.id in seen:
            continue
        seen.add(method.id)
        jwk = {"kty": "OKP", "crv": "Ed25519", "x": bytes_to_base64url(public_key), "kid": method.id, "use": "sig"}
        if alg is not None:
            jwk["alg"] = alg
        keys.append(jwk)
    return {"keys": keys}


def build_client_metadata_document(
    *,
    client_id: str,
    client_name: str,
    did_document: AnyDidDocument,
    grant_types: Sequence[str] = ("client_credentials",),
    redirect_uris: Sequence[str] | None = None,
    client_uri: str | None = None,
    jwks_uri: str | None = None,
    jws_alg: JwsEd25519Alg = "EdDSA",
) -> dict[str, Any]:
    """An OAuth Client ID Metadata Document (draft-ietf-oauth-client-id-metadata-document) for an agent that
    authenticates with ``private_key_jwt`` and its DID key.

    *client_id* is the ``https`` URL the document is served at. ``agent_did`` names the DID; an authorization server
    that does not know it ignores it.
    """
    try:
        parts = urlsplit(client_id)
    except ValueError:
        raise TypeError("client_id must be an https URL") from None
    if (
        parts.scheme != "https"
        or not parts.netloc
        or parts.path in ("", "/")
        or parts.fragment
        or "#" in client_id
        or parts.netloc != parts.netloc.lower()
        or parts.netloc.endswith(":443")
    ):
        raise TypeError("client_id must be an https URL with a path, without a fragment, in normalized form")
    if not isinstance(client_name, str) or not client_name:
        raise TypeError("client_name is required")
    document: dict[str, Any] = {"client_id": client_id, "client_name": client_name}
    if client_uri is not None:
        document["client_uri"] = client_uri
    document["grant_types"] = list(grant_types)
    if redirect_uris is not None:
        document["redirect_uris"] = list(redirect_uris)
    document["token_endpoint_auth_method"] = "private_key_jwt"
    document["token_endpoint_auth_signing_alg"] = jws_alg
    document["agent_did"] = did_document.id
    if jwks_uri is not None:
        document["jwks_uri"] = jwks_uri
    else:
        jwks = build_client_jwks(did_document)
        if not jwks["keys"]:
            raise ValueError(f"{did_document.id} has no active Ed25519 authentication key")
        document["jwks"] = jwks
    return document
