"""Signed A2A Agent Cards for the identity composition contract (``docs/RFC-001-A2A-Identity-Composition-Contract.md``).

A card is signed as A2A 1.0 §8.4 describes: each entry of ``signatures`` is a JWS (RFC 7515) whose payload is the
RFC 8785 (JCS) form of the card without ``signatures``. Agent-DID fixes the profile: protected header
``{"alg":"EdDSA","kid":"<DID URL>","typ":"JOSE"}``, an Ed25519 ``assertionMethod`` key of the agent DID as ``kid``.
The keys a card publishes are the ``kid`` values of its signatures and the ``keyIds`` of the Agent-DID extension in
``capabilities.extensions``. This is aligned with A2A 1.0, not verified against an independent implementation.

TypeScript parity: ``sdk/src/core/agent-card.ts``.
"""

from __future__ import annotations

import base64
import copy
import json
import re
from dataclasses import dataclass
from typing import Any

from ..crypto.hash import canonicalize_json
from .signer import AgentSigner

AGENT_DID_A2A_EXTENSION_URI = "https://agent-did.org/a2a/identity/v1"
"""``uri`` of the A2A extension through which a card names its agent DID and the keys it publishes."""

AGENT_CARD_SIGNATURE_ALG = "EdDSA"
"""The JWS ``alg`` of an Agent-DID card signature (RFC 8037)."""

MAX_AGENT_CARD_SIGNATURES = 16
"""Upper bound on ``signatures`` entries a verifier reads."""

_KEY_ID = re.compile(r"(did:[a-z0-9]+:[^#?/\x00-\x20\x7f]+)#[^#?\x00-\x20\x7f]+")
_BASE64URL = re.compile(r"[A-Za-z0-9_-]*")


@dataclass(frozen=True)
class AgentCardSignatureEntry:
    """One signature of a card whose format is right."""

    key_id: str
    signing_input: str
    signature: bytes


@dataclass(frozen=True)
class ParsedAgentCard:
    """The parts of a card a verifier checks, once its format is right."""

    did: str
    """The agent DID every signature ``kid`` and the extension name."""
    signatures: tuple[AgentCardSignatureEntry, ...]
    """One entry per signature, in order."""
    published_key_ids: tuple[str, ...]
    """Keys the card publishes: signature ``kid`` values, then extension ``keyIds``, without repeats."""


def bytes_to_base64url(data: bytes) -> str:
    """Base64url without padding (RFC 4648 §5), as JWS uses it (RFC 7515 §2)."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def base64url_to_bytes(value: str) -> bytes | None:
    """Decode unpadded base64url; ``None`` for anything that is not the canonical encoding of some bytes."""
    if not _BASE64URL.fullmatch(value) or len(value) % 4 == 1:
        return None
    try:
        data = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except ValueError:
        return None
    return data if bytes_to_base64url(data) == value else None


def did_of_key_id(key_id: object) -> str | None:
    """The DID of a DID URL with a non-empty fragment and nothing else (``did:method:id#fragment``), else ``None``."""
    if not isinstance(key_id, str):
        return None
    match = _KEY_ID.fullmatch(key_id)
    return match.group(1) if match else None


def _card_payload(card: dict[str, Any]) -> str:
    unsigned = {name: value for name, value in card.items() if name != "signatures"}
    return bytes_to_base64url(canonicalize_json(unsigned).encode("utf-8"))


async def sign_agent_card(card: dict[str, Any], signer: AgentSigner, key_id: str) -> dict[str, Any]:
    """Return a copy of *card* with one more ``signatures`` entry, signed by *signer* as *key_id* (a DID URL of an
    ``assertionMethod`` key of the agent). Signatures already on the card are kept and are not covered."""
    if not isinstance(card, dict):
        raise TypeError("An Agent Card must be a JSON object")
    if did_of_key_id(key_id) is None:
        raise TypeError(f"key_id must be a DID URL with a fragment: {key_id!r}")
    existing = card.get("signatures", [])
    if not isinstance(existing, list):
        raise TypeError("signatures must be a list")
    protected = bytes_to_base64url(
        canonicalize_json({"alg": AGENT_CARD_SIGNATURE_ALG, "kid": key_id, "typ": "JOSE"}).encode("utf-8")
    )
    signing_input = f"{protected}.{_card_payload(card)}"
    signature = bytes.fromhex(await signer.sign(signing_input.encode("utf-8")))
    signed = copy.deepcopy(card)
    entry = {"protected": protected, "signature": bytes_to_base64url(signature)}
    signed["signatures"] = [*copy.deepcopy(existing), entry]
    return signed


_MALFORMED = object()


def _reject_constant(name: str) -> object:
    # JSON has no NaN or Infinity; json.loads accepts them unless told otherwise (JSON.parse does not).
    raise ValueError(f"not JSON: {name}")


def _agent_did_extension(card: dict[str, Any]) -> tuple[str, list[str]] | None | object:
    """The Agent-DID extension of a card: ``None`` when absent, ``(did, key_ids)``, or ``_MALFORMED``."""
    if "capabilities" not in card:
        return None
    capabilities = card["capabilities"]
    if not isinstance(capabilities, dict):
        return _MALFORMED
    if "extensions" not in capabilities:
        return None
    extensions = capabilities["extensions"]
    if not isinstance(extensions, list):
        return _MALFORMED
    ours = [e for e in extensions if isinstance(e, dict) and e.get("uri") == AGENT_DID_A2A_EXTENSION_URI]
    if not ours:
        return None
    params = ours[0].get("params")
    if len(ours) > 1 or not isinstance(params, dict) or not isinstance(params.get("did"), str):
        return _MALFORMED
    key_ids = params.get("keyIds")
    if not isinstance(key_ids, list) or any(did_of_key_id(key_id) != params["did"] for key_id in key_ids):
        return _MALFORMED
    return params["did"], list(key_ids)


def parse_signed_agent_card(card: object) -> ParsedAgentCard | None:
    """Check the format of a signed card without resolving anything.

    Every ``signatures`` entry is an Agent-DID JWS (protected header with ``alg`` ``EdDSA``, a DID URL ``kid``,
    ``typ`` ``JOSE`` when present, no ``crit``; a 64-byte signature), every ``kid`` and the extension name one DID.
    Returns ``None`` when the card does not have that format (``format_drift``).
    """
    if not isinstance(card, dict):
        return None
    entries = card.get("signatures")
    if not isinstance(entries, list) or not entries or len(entries) > MAX_AGENT_CARD_SIGNATURES:
        return None
    try:
        payload = _card_payload(card)
    except (TypeError, ValueError, OverflowError):
        return None
    signatures: list[AgentCardSignatureEntry] = []
    dids: set[str] = set()
    for entry in entries:
        if not isinstance(entry, dict):
            return None
        protected, signature_text = entry.get("protected"), entry.get("signature")
        if not isinstance(protected, str) or not isinstance(signature_text, str):
            return None
        if any(name not in ("protected", "signature", "header") for name in entry):
            return None
        if "header" in entry and not isinstance(entry["header"], dict):
            return None
        header_bytes = base64url_to_bytes(protected)
        signature = base64url_to_bytes(signature_text)
        if header_bytes is None or signature is None or len(signature) != 64:
            return None
        try:
            header = json.loads(header_bytes.decode("utf-8"), parse_constant=_reject_constant)
        except (UnicodeDecodeError, ValueError):
            return None
        if (
            not isinstance(header, dict)
            or header.get("alg") != AGENT_CARD_SIGNATURE_ALG
            or ("typ" in header and header["typ"] != "JOSE")
            or "crit" in header
        ):
            return None
        did = did_of_key_id(header.get("kid"))
        if did is None:
            return None
        dids.add(did)
        signatures.append(AgentCardSignatureEntry(header["kid"], f"{protected}.{payload}", signature))
    extension = _agent_did_extension(card)
    if extension is _MALFORMED or len(dids) != 1:
        return None
    did = next(iter(dids))
    extension_key_ids: list[str] = []
    if isinstance(extension, tuple):
        if extension[0] != did:
            return None
        extension_key_ids = extension[1]
    published = tuple(dict.fromkeys([*(s.key_id for s in signatures), *extension_key_ids]))
    return ParsedAgentCard(did=did, signatures=tuple(signatures), published_key_ids=published)
