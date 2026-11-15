"""Constants and helpers of the Agent-DID HTTP Message Signature profile (RFC 9421)."""

from __future__ import annotations

import base64
import hashlib

import http_sf

from .http_signatures import ComponentIdentifier, HttpSignatureError, KeyedComponent, _parse_dictionary

AGENT_DID_HTTP_HEADER = "Agent-DID"
"""Header field that carries the agent DID, as a Structured Field Dictionary keyed by signature label."""

AGENT_DID_HTTP_SIGNATURE_LABEL = "sig1"
"""Signature label the SDK signs with."""


def agent_did_http_signature_components(label: str) -> list[ComponentIdentifier]:
    """Components an Agent-DID HTTP Message Signature labelled *label* covers, in this order (RFC-001 §6.5 item 2).

    ``"@method" "@authority" "@path" "@query" "content-digest" "date" "agent-did";key="<label>"``.
    """
    return ["@method", "@authority", "@path", "@query", "content-digest", "date", KeyedComponent("agent-did", label)]


def serialize_agent_did_header(label: str, did: str) -> str:
    """Serialize an ``Agent-DID`` field value with one member: ``<label>="<did>"``."""
    try:
        return http_sf.ser({label: (did, {})})
    except (http_sf.StructuredFieldError, ValueError) as error:
        raise HttpSignatureError(f"Cannot serialize the Agent-DID field: {error}") from None


def parse_agent_did_header(value: str) -> dict[str, str | None]:
    """Parse an ``Agent-DID`` field value: label -> DID.

    A member that is not a String, or that has parameters, maps to ``None``. Raises ``HttpSignatureError`` when the
    field is not a Structured Field Dictionary.
    """
    result: dict[str, str | None] = {}
    for label, (bare, params) in _parse_dictionary(value).items():
        is_did = isinstance(bare, str) and not isinstance(bare, http_sf.Token) and not params
        result[label] = bare if is_did else None
    return result


AGENT_DID_HTTP_SIGNATURE_TAG = "agent-did"
"""RFC 9421 ``tag`` parameter of Agent-DID HTTP Message Signatures."""


def compute_content_digest(body: str | bytes | None) -> str:
    """RFC 9530 ``Content-Digest`` with SHA-256 of the body bytes (a string is hashed as UTF-8)."""
    raw = body.encode("utf-8") if isinstance(body, str) else (body or b"")
    digest = hashlib.sha256(raw).digest()
    b64 = base64.b64encode(digest).decode("ascii")
    return f"sha-256=:{b64}:"
