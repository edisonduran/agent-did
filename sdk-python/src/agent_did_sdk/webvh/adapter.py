"""did:webvh v1.0 adapter (ADR-002).

This module is the only place in the SDK that imports the DIF reference
implementation (``did-webvh``). It exposes Agent-DID operations over
``did.jsonl`` text and never leaks library types to callers, so the backing
implementation can be replaced without touching ``AgentIdentity`` or the
resolvers.

Transport stays with the SDK's own document sources (and their SSRF guards):
this module only creates, appends to and verifies log text that the caller
already holds.

TypeScript parity: ``sdk/src/webvh/adapter.ts``.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Literal

import jsoncanon
from did_webvh.core.file_utils import AsyncTextReader, AsyncTextReadError
from did_webvh.core.hash_utils import DEFAULT_HASH, HashInfo
from did_webvh.core.proof import di_jcs_canonicalize_input
from did_webvh.core.resolver import DidResolver, HistoryResolver, ResolutionError
from did_webvh.core.state import DocumentState, InvalidDocumentState
from did_webvh.history import did_base_url
from did_webvh.resolver import extend_document_services
from did_webvh.verify import WebvhVerifier

from ..core.signer import AgentSigner
from ..crypto.multibase import _base58_decode, _base58_encode, encode_public_key_multibase

DID_WEBVH_PLACEHOLDER = "{DID}"
"""Placeholder that :func:`create_did_webvh_log` replaces with the generated DID."""

DidWebvhErrorCode = Literal["invalidDid", "notFound", "invalidOptions", "invalidInput", "unauthorized"]

_SCID_PLACEHOLDER = "{SCID}"
_METHOD = "did:webvh:1.0"
_HOST_LABEL = re.compile(r"^[a-z](?:[a-z0-9-]{0,61}[a-z0-9])$")
_PATH_SEGMENT = re.compile(r"^[A-Za-z0-9._~-]+$")
_PORT = re.compile(r"^[1-9][0-9]{0,4}$")
_VERSION_TIME = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
_MAX_FUTURE_SKEW = timedelta(minutes=5)
_DEFAULT_TTL = "3600"


class DidWebvhError(ValueError):
    """A did:webvh operation or log verification failed."""

    def __init__(self, code: DidWebvhErrorCode, message: str) -> None:
        super().__init__(message)
        self.code: DidWebvhErrorCode = code


@dataclass
class DidWebvhMetadata:
    """Resolution metadata exposed by Agent-DID for a did:webvh log.

    Witness and watcher configuration are deliberately not exposed until the
    SDK supports them (ADR-002, condition 7).
    """

    version_id: str
    version_number: int
    version_time: str
    created: str
    updated: str
    scid: str
    update_keys: list[str] = field(default_factory=list)
    next_key_hashes: list[str] = field(default_factory=list)
    """Pre-rotation commitments (``nextKeyHashes``) in force after this version: while non-empty, the next
    entry must be signed by a key whose hash is listed here, and the current ``update_keys`` can no longer
    sign. Empty when pre-rotation is not active."""
    deactivated: bool = False
    ttl: str = _DEFAULT_TTL
    """Cache TTL in seconds; the did:webvh default (3600) when the log does not set one."""


@dataclass
class DidWebvhLogResult:
    did: str
    document: dict[str, Any]
    """Resolved DID document, including the implicit ``#files`` / ``#whois`` services."""
    state: dict[str, Any]
    """The resolved version's ``state`` exactly as signed in the log (no implicit services)."""
    metadata: DidWebvhMetadata
    log: str
    """The full ``did.jsonl`` text, one entry per line, newline-terminated."""


async def did_webvh_update_key_for(signer: AgentSigner) -> str:
    """Return the did:webvh ``updateKeys`` entry (an Ed25519 multikey) for *signer*."""
    return encode_public_key_multibase(await signer.get_public_key())


async def create_did_webvh_log(
    *,
    domain: str,
    document: dict[str, Any],
    signer: AgentSigner,
    path_segments: list[str] | None = None,
    next_update_keys: list[str] | None = None,
    created: str | None = None,
) -> DidWebvhLogResult:
    """Create a v1.0 log whose only update key is *signer*'s key.

    Every occurrence of ``{DID}`` in *document* is replaced with the generated DID.
    *domain* is a lowercase ASCII fully qualified host name, optionally with ``:port``.
    *next_update_keys* are public keys (Ed25519 multikeys) the next entry will be signed with: only their
    hashes are written to the log (``nextKeyHashes``, pre-rotation), so keep the private keys offline, away
    from *signer*. They must not include the current update key.
    """
    host, port = _validate_domain(domain)
    segments = list(path_segments or [])
    for segment in segments:
        _validate_path_segment(segment)
    if created is not None:
        _validate_version_time(created, "created", timedelta(0))

    update_key = await did_webvh_update_key_for(signer)
    next_key_hashes = _next_key_hashes_for(next_update_keys, [update_key]) or []
    domain_component = f"{host}%3A{port}" if port else host
    template_did = ":".join(["did:webvh", _SCID_PLACEHOLDER, domain_component, *segments])
    if not isinstance(document, dict):
        raise DidWebvhError("invalidInput", "did:webvh document must be an object")
    document_text = json.dumps(document).replace(DID_WEBVH_PLACEHOLDER, template_did)

    try:
        genesis = DocumentState.initial(
            params={
                "method": _METHOD,
                "scid": _SCID_PLACEHOLDER,
                "updateKeys": [update_key],
                "portable": False,
                "nextKeyHashes": next_key_hashes,
                "watchers": [],
                "witness": {},
                "deactivated": False,
            },
            document=document_text,
            timestamp=created,
        )
    except ValueError as err:
        raise DidWebvhError("invalidInput", f"did:webvh operation failed: {err}") from None
    if genesis.document_id != template_did.replace(_SCID_PLACEHOLDER, genesis.scid):
        raise DidWebvhError("invalidInput", "did:webvh document id must be the {DID} placeholder")

    await _sign_state(genesis, signer, update_key)
    return await resolve_did_webvh_log(_serialize([genesis.history_line()]))


async def update_did_webvh_log(
    *,
    log: str,
    signer: AgentSigner,
    document: dict[str, Any] | None = None,
    update_keys: list[str] | None = None,
    next_update_keys: list[str] | None = None,
    updated: str | None = None,
) -> DidWebvhLogResult:
    """Append a controller-signed entry.

    *document* is the complete next DID document; when omitted the current
    document is carried over. *update_keys* replaces the active update keys; while pre-rotation is active
    they must all be committed in ``nextKeyHashes`` and default to the signer's key. *next_update_keys* are
    the public keys for the pre-rotation commitment of the NEXT entry: omitted, the commitments in force stay
    as they are; an empty list ends pre-rotation. They must not include any of the update keys this entry sets.
    """
    entries = _parse_log(log)
    current = await resolve_did_webvh_log(log)
    if update_keys is not None:
        if not update_keys:
            raise DidWebvhError("invalidInput", "update_keys must not be empty; use deactivate_did_webvh_log instead")
        for key in update_keys:
            _validate_update_key(key)
    signer_key, effective_update_keys = await _authorize_signer(signer, current.metadata, update_keys)
    next_key_hashes = _next_key_hashes_for(
        next_update_keys, effective_update_keys if effective_update_keys is not None else current.metadata.update_keys
    )
    if updated is not None:
        _validate_version_time(updated, "updated", _MAX_FUTURE_SKEW)
    if document is not None and document.get("id") != current.did:
        raise DidWebvhError(
            "invalidInput",
            f"did:webvh operation failed: Updated DID document id must match expected DID '{current.did}'",
        )

    last_state = await _load_last_state(log)
    params_update: dict[str, Any] = {}
    if effective_update_keys is not None:
        params_update["updateKeys"] = list(effective_update_keys)
    if next_key_hashes is not None:
        params_update["nextKeyHashes"] = next_key_hashes
    params_update["watchers"] = last_state.watchers or []

    try:
        state = last_state.create_next(document=document, params_update=params_update, timestamp=updated)
    except ValueError as err:
        raise DidWebvhError("invalidInput", f"did:webvh operation failed: {err}") from None
    await _sign_state(state, signer, signer_key)
    return await resolve_did_webvh_log(_serialize([*entries, state.history_line()]))


async def deactivate_did_webvh_log(*, log: str, signer: AgentSigner) -> DidWebvhLogResult:
    """Append a controller-signed deactivation entry (``deactivated: true``)."""
    entries = _parse_log(log)
    current = await resolve_did_webvh_log(log)
    # While pre-rotation is active the deactivation is signed by a committed key, which becomes the update key.
    signer_key, effective_update_keys = await _authorize_signer(signer, current.metadata, None)

    last_state = await _load_last_state(log)
    try:
        state = last_state.create_next(
            params_update={
                "updateKeys": list(effective_update_keys or current.metadata.update_keys),
                "nextKeyHashes": [],
                "deactivated": True,
            }
        )
    except ValueError as err:
        raise DidWebvhError("invalidInput", f"did:webvh operation failed: {err}") from None
    await _sign_state(state, signer, signer_key)
    return await resolve_did_webvh_log(_serialize([*entries, state.history_line()]))


async def resolve_did_webvh_log(
    log: str,
    *,
    did: str | None = None,
    version_id: str | None = None,
    version_number: int | None = None,
    version_time: str | None = None,
) -> DidWebvhLogResult:
    """Verify a ``did.jsonl`` log and return the resolved document.

    Checks the SCID, entry hash chain, ``updateKeys`` proofs and version
    times. Raises :class:`DidWebvhError` on any verification failure; it never
    returns a partially verified result.
    """
    entries = _parse_log(log)
    serialized = _serialize(entries)

    if version_time is not None:
        try:
            datetime.fromisoformat(version_time.replace("Z", "+00:00"))
        except ValueError:
            raise DidWebvhError("invalidOptions", f"Invalid versionTime: {version_time}") from None

    try:
        state, meta = await DidResolver(WebvhVerifier()).resolve_state(
            None,
            _TextHistory(serialized),
            version_id=version_id,
            version_number=str(version_number) if version_number is not None else None,
            version_time=version_time,
        )
    except ResolutionError as err:
        raise DidWebvhError(_map_resolution_error(err.error), _resolution_message(err)) from None
    except InvalidDocumentState as err:
        raise DidWebvhError("invalidDid", f"did:webvh log verification failed: {err}") from None
    except AsyncTextReadError as err:
        raise DidWebvhError("notFound", f"did:webvh log verification failed: {err}") from None
    except Exception as err:  # noqa: BLE001 - fail closed on any library defect
        raise DidWebvhError("invalidDid", f"did:webvh log verification failed: {type(err).__name__}") from None

    document = state.document_copy()
    signed_state = state.document_copy()
    if not state.deactivated:
        # Implicit #files and #whois services, as didwebvh-ts adds them. A
        # deactivated DID resolves to the raw state of its last entry in both SDKs.
        extend_document_services(document, did_base_url(state.document_id, files=True))
    if did is not None and document.get("id") != did:
        raise DidWebvhError("invalidDid", f"did:webvh log belongs to {document.get('id')}, not {did}")

    serialized_meta = meta.serialize()
    ttl = state.params.get("ttl")
    metadata = DidWebvhMetadata(
        version_id=state.version_id,
        version_number=state.version_number,
        version_time=state.timestamp_raw,
        created=serialized_meta["created"],
        # DID Core: the last update of the *resolved* version, not of the log.
        updated=state.timestamp_raw,
        scid=state.scid,
        update_keys=list(state.update_keys),
        next_key_hashes=list(state.next_key_hashes or []),
        deactivated=state.deactivated,
        ttl=str(ttl) if ttl is not None else _DEFAULT_TTL,
    )
    return DidWebvhLogResult(
        did=str(document["id"]), document=document, state=signed_state, metadata=metadata, log=serialized
    )


class _TextHistory(HistoryResolver):  # type: ignore[misc]
    """Feeds already-fetched log text to the reference resolver; never does I/O."""

    def __init__(self, text: str) -> None:
        self._text = text

    def resolve_entry_log(self, _document_id: str | None) -> Any:
        return _read_text(self._text)

    def resolve_witness_log(self, _document_id: str | None) -> Any:
        return _no_witness_log()


@asynccontextmanager
async def _read_text(text: str) -> AsyncIterator[Any]:
    yield AsyncTextReader(init=text)


@asynccontextmanager
async def _no_witness_log() -> AsyncIterator[Any]:
    raise AsyncTextReadError("did:webvh witnesses are not supported by Agent-DID yet")
    yield  # pragma: no cover


async def _load_last_state(log: str) -> DocumentState:
    state, _meta = await DidResolver(WebvhVerifier()).resolve_state(None, _TextHistory(_serialize(_parse_log(log))))
    return state


async def _sign_state(state: DocumentState, signer: AgentSigner, update_key: str) -> None:
    """Append an ``eddsa-jcs-2022`` proof produced by an async :class:`AgentSigner`.

    The reference library only signs with synchronous keys, so the proof is
    assembled here exactly as ``di_jcs_sign`` does and checked against the
    library verifier before it is used.
    """
    options = {
        "type": "DataIntegrityProof",
        "cryptosuite": "eddsa-jcs-2022",
        "verificationMethod": f"did:key:{update_key}#{update_key}",
        "created": state.timestamp_raw,
        "proofPurpose": "assertionMethod",
    }
    data_hash = hashlib.sha256(di_jcs_canonicalize_input(state.history_line())).digest()
    options_hash = hashlib.sha256(jsoncanon.canonicalize(options)).digest()
    signature = bytes.fromhex(await signer.sign(options_hash + data_hash))
    # Same member order as didwebvh-ts, so both SDKs emit identical log lines.
    proof = {
        "type": options["type"],
        "cryptosuite": options["cryptosuite"],
        "verificationMethod": options["verificationMethod"],
        "created": options["created"],
        "proofValue": "z" + _base58_encode(signature),
        "proofPurpose": options["proofPurpose"],
    }
    try:
        state.verify_proof(proof, {"type": "Multikey", "publicKeyMultibase": update_key})
    except ValueError:
        raise DidWebvhError("unauthorized", "Signer produced a signature that does not match its public key") from None
    state.proofs.append(proof)


async def _authorize_signer(
    signer: AgentSigner, metadata: DidWebvhMetadata, requested_update_keys: list[str] | None
) -> tuple[str, list[str] | None]:
    """Decide whether *signer* may append the next entry, and with which ``updateKeys``.

    Without pre-rotation, the signer must be in the active ``updateKeys``. With pre-rotation active
    (``nextKeyHashes`` non-empty) the rule inverts, as in did:webvh v1.0: the entry must set ``updateKeys`` to
    keys whose hashes were committed, it is signed by one of them, and the keys that were active before can no
    longer sign. That is what makes the commitment a recovery path after a compromise of the active key.
    Returns the signer key and the ``updateKeys`` the entry must carry (None: the entry keeps the active ones).
    """
    if metadata.deactivated:
        raise DidWebvhError("invalidInput", "did:webvh DID is deactivated")
    signer_key = await did_webvh_update_key_for(signer)
    if not metadata.next_key_hashes:
        if signer_key not in metadata.update_keys:
            raise DidWebvhError("unauthorized", "Signer key is not in the active did:webvh updateKeys")
        return signer_key, requested_update_keys

    update_keys = requested_update_keys if requested_update_keys is not None else [signer_key]
    if signer_key not in update_keys:
        raise DidWebvhError("invalidInput", "While pre-rotation is active, updateKeys must include the signing key")
    for key in update_keys:
        if _next_key_hash(key) not in metadata.next_key_hashes:
            raise DidWebvhError(
                "unauthorized",
                "Pre-rotation is active: updateKeys may only contain keys committed in nextKeyHashes, "
                "and the active keys can no longer sign",
            )
    return signer_key, update_keys


def _next_key_hash(multikey: str) -> str:
    """``nextKeyHashes`` entry for an Ed25519 multikey: base58btc multihash of SHA-256 over the multikey text."""
    return str(HashInfo.from_name(DEFAULT_HASH).formatted_hash(multikey.encode("utf-8")))


def _next_key_hashes_for(next_update_keys: list[str] | None, active_keys: list[str]) -> list[str] | None:
    """Hash pre-rotation keys. None means "no change"; the keys must be new, never an active one."""
    if next_update_keys is None:
        return None
    for key in next_update_keys:
        _validate_update_key(key)
    if len(set(next_update_keys)) != len(next_update_keys):
        raise DidWebvhError("invalidInput", "next_update_keys must not repeat a key")
    if any(key in active_keys for key in next_update_keys):
        raise DidWebvhError(
            "invalidInput",
            "next_update_keys must not include a key that is active in the same entry: "
            "pre-rotation commits to NEW keys",
        )
    return [_next_key_hash(key) for key in next_update_keys]


def _parse_log(log: str) -> list[dict[str, Any]]:
    if not isinstance(log, str):
        raise DidWebvhError("invalidInput", "did:webvh log must be a string")
    lines = [line for line in re.split(r"\r?\n", log) if line.strip()]
    if not lines:
        raise DidWebvhError("notFound", "did:webvh log is empty")
    entries: list[dict[str, Any]] = []
    for index, line in enumerate(lines, start=1):
        try:
            entry = json.loads(line)
        except ValueError:
            raise DidWebvhError("invalidDid", f"did:webvh log line {index} is not valid JSON") from None
        if not isinstance(entry, dict):
            raise DidWebvhError("invalidDid", f"did:webvh log line {index} is not a JSON object")
        entries.append(entry)
    return entries


def _serialize(entries: list[dict[str, Any]]) -> str:
    return "".join(json.dumps(entry, separators=(",", ":"), ensure_ascii=False) + "\n" for entry in entries)


def _map_resolution_error(code: str) -> DidWebvhErrorCode:
    if code == "notFound":
        return "notFound"
    return "invalidDid"


def _resolution_message(err: ResolutionError) -> str:
    details = err.problem_details
    if isinstance(details, list):
        details = details[0] if details else None
    if details is not None:
        serialized = details.serialize()
        detail = serialized.get("detail") or serialized.get("title")
        if detail:
            return f"did:webvh log verification failed: {detail}"
    return f"did:webvh log verification failed: {err.error}"


_SCID = re.compile(r"^[1-9A-HJ-NP-Za-km-z]+$")
_HOST_SEGMENT = re.compile(r"^([^%]+)(?:%3A([0-9]+))?$")
_DID_URL_PARTS = re.compile(r"[/?#\s]")


def derive_did_webvh_log_url(did: str) -> str:
    """Derive the HTTPS URL of a did:webvh DID's ``did.jsonl`` (did:webvh v1.0).

    Applies the same host and path rules as :func:`create_did_webvh_log`:
    lowercase ASCII FQDN (no IP literals), optional port encoded as ``%3A``,
    unencoded path segments without ``.``/``..``, and no path, query or
    fragment in the DID. Raises ``DidWebvhError("invalidDid")`` otherwise.
    """

    def fail(reason: str) -> DidWebvhError:
        return DidWebvhError("invalidDid", f"Invalid did:webvh DID ({reason}): {did}")

    if not isinstance(did, str) or not did.startswith("did:webvh:"):
        raise fail("not a did:webvh DID")
    if _DID_URL_PARTS.search(did):
        raise fail("DID URLs with a path, query or fragment are not resolvable")

    scid, *rest = did[len("did:webvh:"):].split(":")
    if not scid or not _SCID.match(scid):
        raise fail("SCID must be base58btc")
    if not rest:
        raise fail("host")
    host_match = _HOST_SEGMENT.match(rest[0])
    if host_match is None:
        raise fail("host")
    host, port = host_match.group(1), host_match.group(2)
    domain = host if port is None else f"{host}:{port}"
    path_segments = rest[1:]
    try:
        _validate_domain(domain)
        for segment in path_segments:
            _validate_path_segment(segment)
    except DidWebvhError as err:
        raise fail(str(err)) from None

    if path_segments:
        return f"https://{domain}/{'/'.join(path_segments)}/did.jsonl"
    return f"https://{domain}/.well-known/did.jsonl"


def _validate_domain(domain: str) -> tuple[str, str | None]:
    if not isinstance(domain, str) or not domain:
        raise DidWebvhError("invalidInput", "did:webvh domain is required")
    host, separator, port = domain.rpartition(":")
    if not separator:
        host, port = domain, ""
    labels = host.split(".")
    if len(host) > 253 or len(labels) < 2 or not all(_HOST_LABEL.match(label) for label in labels):
        raise DidWebvhError("invalidInput", f"Invalid did:webvh domain: {domain}")
    if separator and (not _PORT.match(port) or int(port) > 65535):
        raise DidWebvhError("invalidInput", f"Invalid did:webvh port: {domain}")
    return host, port or None


def _validate_path_segment(segment: str) -> None:
    if not isinstance(segment, str) or not _PATH_SEGMENT.match(segment) or segment in (".", ".."):
        raise DidWebvhError("invalidInput", f"Invalid did:webvh path segment: {segment}")


def _validate_update_key(key: str) -> None:
    decoded: bytes | None = None
    if isinstance(key, str) and key.startswith("z"):
        try:
            decoded = _base58_decode(key[1:])
        except ValueError:
            decoded = None
    if decoded is None or len(decoded) != 34 or decoded[:2] != b"\xed\x01":
        raise DidWebvhError("invalidInput", f"updateKeys entries must be Ed25519 multikeys: {key}")


def _validate_version_time(value: str, name: str, max_future_skew: timedelta) -> None:
    if not isinstance(value, str) or not _VERSION_TIME.match(value):
        raise DidWebvhError("invalidInput", f"{name} must be a UTC timestamp like 2026-01-01T00:00:00Z")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise DidWebvhError("invalidInput", f"{name} must be a valid UTC timestamp") from None
    if parsed > datetime.now(timezone.utc) + max_future_skew:
        raise DidWebvhError("invalidInput", f"{name} must not be in the future")
