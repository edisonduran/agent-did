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
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Literal

from did_webvh.core.file_utils import AsyncTextReader, AsyncTextReadError
from did_webvh.core.hash_utils import DEFAULT_HASH, HashInfo
from did_webvh.core.proof import di_jcs_canonicalize_input
from did_webvh.core.resolver import DidResolver, HistoryResolver, ResolutionError
from did_webvh.core.state import DocumentState, InvalidDocumentState
from did_webvh.core.witness import verify_witness_proofs
from did_webvh.history import did_base_url
from did_webvh.resolver import extend_document_services
from did_webvh.verify import WebvhVerifier

from ..core.signer import AgentSigner
from ..crypto.hash import canonicalize_json
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
class DidWebvhWitnessConfig:
    """Witnesses of a did:webvh DID (did:webvh v1.0 ``witness`` parameter, ADR-007).

    *threshold* of the *witnesses* (``did:key`` DIDs with Ed25519 keys, no fragment, no repeats) must approve each
    entry the rule governs before it is published. *threshold* is an integer from 1 to ``len(witnesses)``.
    """

    threshold: int
    witnesses: list[str]


DidWebvhWitnessProofEntry = dict[str, Any]
"""One entry of ``did-witness.json``: ``{"versionId": ..., "proof": [...]}``, the witness proofs approving
``versionId`` (and every earlier entry)."""


@dataclass
class DidWebvhWitnessRequest:
    """What a witness approval collector is asked to approve: the last entry of *log*."""

    did: str
    version_id: str
    """``versionId`` of the entry to approve (the last entry of *log*)."""
    log: str
    """The candidate log, ending with the entry to approve. It is not published yet."""
    witness: DidWebvhWitnessConfig
    """The witness rule that governs the entry."""
    witness_file: str | None = None
    """The ``did-witness.json`` in force before this entry, if the log has one."""


DidWebvhWitnessCollector = Callable[[DidWebvhWitnessRequest], Awaitable[list[DidWebvhWitnessProofEntry]]]
"""Obtains the approvals of an entry from its witnesses (over the network, or in process with
:func:`create_did_webvh_witness_proof`). Returning fewer approvals than the threshold makes the operation fail."""


@dataclass
class DidWebvhMetadata:
    """Resolution metadata exposed by Agent-DID for a did:webvh log.

    Watcher configuration is deliberately not exposed (ADR-002, condition 7). Every value is a string, list or
    boolean, as DID Core section 7.3 requires of DID document metadata.
    """

    version_id: str
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
    witness_threshold: str = "0"
    """Witness threshold in force after this version (ADR-007); ``"0"`` when the DID has no witnesses."""
    witnesses: list[str] = field(default_factory=list)
    """Witness DIDs in force after this version; empty when the DID has no witnesses."""


@dataclass
class DidWebvhLogResult:
    did: str
    document: dict[str, Any]
    """Resolved DID document, including the implicit ``#files`` / ``#whois`` services."""
    state: dict[str, Any]
    """The resolved version's ``state`` exactly as signed in the log (no implicit services)."""
    metadata: DidWebvhMetadata
    version_number: int
    """Number of the resolved version: the integer prefix of ``metadata.version_id``."""
    log: str
    """The full ``did.jsonl`` text, one entry per line, newline-terminated."""
    witness_file: str | None = None
    """The ``did-witness.json`` text that approves the log, when any entry is governed by a witness rule. Publish it
    next to ``did.jsonl``, and before it: a resolver rejects a witnessed entry without its approvals."""


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
    witness: DidWebvhWitnessConfig | None = None,
    collect_witness_proofs: DidWebvhWitnessCollector | None = None,
) -> DidWebvhLogResult:
    """Create a v1.0 log whose only update key is *signer*'s key.

    Every occurrence of ``{DID}`` in *document* is replaced with the generated DID.
    *domain* is a lowercase ASCII fully qualified host name, optionally with ``:port``.
    *next_update_keys* are public keys (Ed25519 multikeys) the next entry will be signed with: only their
    hashes are written to the log (``nextKeyHashes``, pre-rotation), so keep the private keys offline, away
    from *signer*. They must not include the current update key.
    *witness* names the witnesses that must approve the genesis entry and every later one until the rule changes
    (ADR-007); *collect_witness_proofs* obtains their approvals and is required with it.
    """
    witness_param = _witness_parameter(witness) if witness is not None else {}
    host, port = _validate_domain(domain)
    segments = list(path_segments or [])
    for segment in segments:
        _validate_path_segment(segment)
    if created is not None:
        _validate_version_time(created, "created", timedelta(0))

    update_key = await did_webvh_update_key_for(signer)
    next_key_hashes = _next_key_hashes_for(next_update_keys, [update_key], [update_key]) or []
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
                "witness": witness_param,
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
    return await _finish_witnessed_entry(_serialize([genesis.history_line()]), None, collect_witness_proofs)


async def update_did_webvh_log(
    *,
    log: str,
    signer: AgentSigner,
    document: dict[str, Any] | None = None,
    update_keys: list[str] | None = None,
    next_update_keys: list[str] | None = None,
    updated: str | None = None,
    witness: DidWebvhWitnessConfig | None | _Unset = None,
    witness_file: str | None = None,
    collect_witness_proofs: DidWebvhWitnessCollector | None = None,
) -> DidWebvhLogResult:
    """Append a controller-signed entry.

    *document* is the complete next DID document; when omitted the current
    document is carried over. *update_keys* replaces the active update keys; while pre-rotation is active
    they must all be committed in ``nextKeyHashes`` and default to the signer's key. *next_update_keys* are
    the public keys for the pre-rotation commitment of the NEXT entry; an empty list ends pre-rotation. Omitted,
    the commitments in force stay as they are, which is only allowed while pre-rotation is not active: while it
    is, every entry consumes a committed key and must commit to new ones. They must not include a key that is,
    or has been, in the log's update keys.
    *witness* is the new witness rule for the entries after this one (ADR-007): :data:`REMOVE_WITNESSES` removes
    witnessing and ``None`` keeps the rule in force; the witnesses in force approve this entry. *witness_file* is the
    current ``did-witness.json`` (required when the log has witnessed entries) and *collect_witness_proofs* obtains
    the approvals when the new entry is governed by a witness rule.
    """
    entries = _parse_log(log)
    current = await resolve_did_webvh_log(log, witness_file=witness_file)
    witness_param: dict[str, Any] | None = None
    if isinstance(witness, _Unset):
        witness_param = {}
    elif witness is not None:
        witness_param = _witness_parameter(witness)
    if update_keys is not None:
        if not update_keys:
            raise DidWebvhError("invalidInput", "update_keys must not be empty; use deactivate_did_webvh_log instead")
        for key in update_keys:
            _validate_update_key(key)
    signer_key, effective_update_keys = await _authorize_signer(signer, current.metadata, update_keys)
    if current.metadata.next_key_hashes and next_update_keys is None:
        raise DidWebvhError(
            "invalidInput",
            "Pre-rotation is active: this entry is signed with a committed key, so it must commit to the next keys "
            "(next_update_keys; an empty list ends pre-rotation)",
        )
    next_key_hashes = _next_key_hashes_for(
        next_update_keys,
        effective_update_keys if effective_update_keys is not None else current.metadata.update_keys,
        _update_keys_used_in(entries),
    )
    if updated is not None:
        _validate_version_time(updated, "updated", _MAX_FUTURE_SKEW)
    if document is not None and document.get("id") != current.did:
        raise DidWebvhError(
            "invalidInput",
            f"did:webvh operation failed: Updated DID document id must match expected DID '{current.did}'",
        )

    last_state = await _load_last_state(log, current.witness_file)
    params_update: dict[str, Any] = {}
    if witness_param is not None:
        # Same member order as didwebvh-ts writes for a rule change.
        params_update["witness"] = (
            {"witnesses": witness_param["witnesses"], "threshold": witness_param["threshold"]} if witness_param else {}
        )
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
    return await _finish_witnessed_entry(
        _serialize([*entries, state.history_line()]), current.witness_file, collect_witness_proofs
    )


async def deactivate_did_webvh_log(
    *,
    log: str,
    signer: AgentSigner,
    witness_file: str | None = None,
    collect_witness_proofs: DidWebvhWitnessCollector | None = None,
) -> DidWebvhLogResult:
    """Append a controller-signed deactivation entry (``deactivated: true``, ``updateKeys: []``).

    While pre-rotation is active this appends two entries, as did:webvh v1.0 requires: an entry under
    pre-rotation must carry the committed keys, so it cannot also empty ``updateKeys``. A committed key first
    ends pre-rotation and then signs the deactivation. *witness_file* and *collect_witness_proofs* are needed when
    the DID has witnesses (ADR-007).
    """
    current = await resolve_did_webvh_log(log, witness_file=witness_file)
    if current.metadata.next_key_hashes:
        current = await update_did_webvh_log(
            log=log,
            signer=signer,
            next_update_keys=[],
            witness_file=witness_file,
            collect_witness_proofs=collect_witness_proofs,
        )
    signer_key, _ = await _authorize_signer(signer, current.metadata, None)

    entries = _parse_log(current.log)
    last_state = await _load_last_state(current.log, current.witness_file)
    try:
        # No key can authorize a later entry.
        state = last_state.create_next(params_update={"updateKeys": [], "nextKeyHashes": [], "deactivated": True})
    except ValueError as err:
        raise DidWebvhError("invalidInput", f"did:webvh operation failed: {err}") from None
    await _sign_state(state, signer, signer_key)
    return await _finish_witnessed_entry(
        _serialize([*entries, state.history_line()]), current.witness_file, collect_witness_proofs
    )


async def resolve_did_webvh_log(
    log: str,
    *,
    did: str | None = None,
    version_id: str | None = None,
    version_number: int | None = None,
    version_time: str | None = None,
    witness_file: str | None = None,
) -> DidWebvhLogResult:
    """Verify a ``did.jsonl`` log and return the resolved document.

    Checks the SCID, entry hash chain, ``updateKeys`` proofs and version
    times. Raises :class:`DidWebvhError` on any verification failure; it never
    returns a partially verified result.

    With *version_id*, *version_number* or *version_time* it returns that version of the log. The whole log
    is still verified, and ``metadata.deactivated`` describes the DID, not the selected version: it is true
    for every version of a deactivated DID (DID Core section 7.1.2).

    *witness_file* is the ``did-witness.json`` published next to the log (ADR-007). It is required when any entry is
    governed by a witness rule: without it, or when its approvals do not reach a threshold, resolution fails.
    """
    entries = _parse_log(log)
    serialized = _serialize(entries)
    requirements = _witness_requirements(entries)
    if requirements and witness_file is None:
        raise DidWebvhError(
            "invalidDid", "did:webvh log has witnessed entries and no witness proofs (did-witness.json) were supplied"
        )
    witness_proofs = _parse_witness_file(witness_file) if requirements else []
    witness_text = json.dumps(witness_proofs) if requirements else None

    if version_time is not None:
        try:
            datetime.fromisoformat(version_time.replace("Z", "+00:00"))
        except ValueError:
            raise DidWebvhError("invalidOptions", f"Invalid versionTime: {version_time}") from None

    # Resolving the latest version verifies every entry. The reference resolver returns a selected version
    # even when a later entry fails verification, so the selection below only runs on a fully verified log.
    latest, meta = await _resolve_verified_state(serialized, witness_text)
    await _check_witness_requirements(entries, requirements, witness_proofs)
    state = latest
    if version_id is not None or version_number is not None or version_time is not None:
        state, meta = await _resolve_verified_state(
            serialized,
            witness_text,
            version_id=version_id,
            version_number=str(version_number) if version_number is not None else None,
            version_time=version_time,
        )

    document = state.document_copy()
    signed_state = state.document_copy()
    if not state.deactivated:
        # Implicit #files and #whois services, as didwebvh-ts adds them. The entry that
        # deactivates the DID resolves to its raw state in both SDKs.
        extend_document_services(document, did_base_url(state.document_id, files=True))
    if did is not None and document.get("id") != did:
        raise DidWebvhError("invalidDid", f"did:webvh log belongs to {document.get('id')}, not {did}")

    serialized_meta = meta.serialize()
    ttl = state.params.get("ttl")
    metadata = DidWebvhMetadata(
        version_id=state.version_id,
        version_time=state.timestamp_raw,
        created=serialized_meta["created"],
        # DID Core: the last update of the *resolved* version, not of the log.
        updated=state.timestamp_raw,
        scid=state.scid,
        update_keys=list(state.update_keys),
        next_key_hashes=list(state.next_key_hashes or []),
        deactivated=latest.deactivated,
        ttl=str(ttl) if ttl is not None else _DEFAULT_TTL,
        **_witness_metadata(state.params.get("witness")),
    )
    return DidWebvhLogResult(
        did=str(document["id"]),
        document=document,
        state=signed_state,
        metadata=metadata,
        version_number=state.version_number,
        log=serialized,
        witness_file=_serialize_witness_file(witness_proofs) if requirements else None,
    )


class _Unset:
    """Sentinel type of :data:`REMOVE_WITNESSES`."""

    def __repr__(self) -> str:
        return "REMOVE_WITNESSES"


REMOVE_WITNESSES = _Unset()
"""Pass as ``witness`` to :func:`update_did_webvh_log` to remove witnessing (``witness: {}``)."""


def did_webvh_log_requires_witnesses(log: str) -> bool:
    """Whether a did:webvh log has entries governed by a witness rule, so resolving it needs its ``did-witness.json``.

    Rule of did:webvh v1.0 (as ``didwebvh-ts`` applies it): an entry is governed by the rule in force before it, or,
    when there is none, by the rule the entry itself sets. Raises :class:`DidWebvhError` for a malformed log.
    """
    return bool(_witness_requirements(_parse_log(log)))


def derive_did_webvh_witness_url(did: str) -> str:
    """The URL of ``did-witness.json`` for a did:webvh DID: next to its ``did.jsonl`` (did:webvh v1.0)."""
    return derive_did_webvh_log_url(did).removesuffix("did.jsonl") + "did-witness.json"


async def create_did_webvh_witness_proof(
    *, log: str, signer: AgentSigner, witness_file: str | None = None
) -> DidWebvhWitnessProofEntry:
    """A witness's approval of the last entry of a candidate log (did:webvh v1.0).

    An ``eddsa-jcs-2022`` proof over ``{"versionId": ...}`` made with the witness's ``did:key``. The candidate log is
    verified first (every entry, and the approvals of the entries before the last one), so a witness never approves
    an entry that does not extend a valid log. *witness_file* is the ``did-witness.json`` in force before the entry.
    """
    entries = _parse_log(log)
    proofs = _parse_witness_file(witness_file)
    if len(entries) > 1:
        await resolve_did_webvh_log(_serialize(entries[:-1]), witness_file=_serialize_witness_file(proofs))
    await _resolve_verified_state(_serialize(entries), None, verify_witness=False)
    tip = entries[-1]
    rule = next((rule for version_id, rule in _witness_requirements(entries) if version_id == tip["versionId"]), None)
    if rule is None:
        raise DidWebvhError(
            "invalidInput",
            "did:webvh operation failed: Candidate entry is not governed by an active witness requirement",
        )
    witness_key = await did_webvh_update_key_for(signer)
    witness_did = f"did:key:{witness_key}"
    if witness_did not in rule.witnesses:
        raise DidWebvhError(
            "invalidInput",
            f"did:webvh operation failed: Witness signer is not a member of the governing witness list: {witness_did}",
        )
    options = {
        "type": "DataIntegrityProof",
        "cryptosuite": "eddsa-jcs-2022",
        "verificationMethod": f"{witness_did}#{witness_key}",
        "created": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "proofPurpose": "assertionMethod",
    }
    container: dict[str, Any] = {"versionId": tip["versionId"]}
    data_hash = hashlib.sha256(canonicalize_json(container).encode("utf-8")).digest()
    options_hash = hashlib.sha256(canonicalize_json(options).encode("utf-8")).digest()
    signature = bytes.fromhex(await signer.sign(options_hash + data_hash))
    proof = {**options, "proofValue": "z" + _base58_encode(signature)}
    entry: DidWebvhWitnessProofEntry = {"versionId": tip["versionId"], "proof": [proof]}
    validated, _errors = await verify_witness_proofs([entry])
    if witness_did not in validated:
        raise DidWebvhError("unauthorized", "Witness signer produced a signature that does not match its public key")
    return entry


@dataclass(frozen=True)
class _WitnessRule:
    threshold: int
    witnesses: tuple[str, ...]


def _witness_rule(value: Any) -> _WitnessRule | None:
    """The active rule of a ``witness`` parameter value, or None when it sets no active rule."""
    if not isinstance(value, dict):
        raise DidWebvhError("invalidDid", "did:webvh log verification failed: invalid 'witness' parameter")
    witnesses = value.get("witnesses")
    threshold = value.get("threshold", 0)
    if witnesses is None or witnesses == []:
        return None
    if (
        not isinstance(witnesses, list)
        or not all(isinstance(item, dict) and isinstance(item.get("id"), str) for item in witnesses)
        or not isinstance(threshold, int)
        or isinstance(threshold, bool)
    ):
        raise DidWebvhError("invalidDid", "did:webvh log verification failed: invalid 'witness' parameter")
    if threshold <= 0:
        return None
    return _WitnessRule(threshold, tuple(item["id"] for item in witnesses))


def _witness_requirements(entries: list[dict[str, Any]]) -> list[tuple[str, _WitnessRule]]:
    """``(versionId, rule)`` for every entry governed by a witness rule (did:webvh v1.0, as ``didwebvh-ts``)."""
    requirements: list[tuple[str, _WitnessRule]] = []
    previous: _WitnessRule | None = None
    for entry in entries:
        params = entry.get("parameters")
        if not isinstance(params, dict):
            raise DidWebvhError("invalidDid", "did:webvh log verification failed: entry without parameters")
        if "witness" in params:
            # Deprecated `witness: null` is tolerated as `{}`, as in didwebvh-ts.
            current = _witness_rule(params["witness"] if params["witness"] is not None else {})
        else:
            current = previous
        required = previous if previous is not None else (current if "witness" in params else None)
        if required is not None:
            requirements.append((str(entry.get("versionId")), required))
        previous = current
    return requirements


async def _check_witness_requirements(
    entries: list[dict[str, Any]], requirements: list[tuple[str, _WitnessRule]], proofs: list[DidWebvhWitnessProofEntry]
) -> None:
    """Counts the approvals of every governed entry with the rule ``didwebvh-ts`` applies.

    ``did-webvh`` checks each entry against the rule in force before it, so an entry that switches witnessing on is
    not checked against its own rule. This closes that gap, so both SDKs accept and reject the same logs. An approval
    of a later entry also approves the earlier ones (did:webvh v1.0).
    """
    if not requirements:
        return
    validated, _errors = await verify_witness_proofs(proofs)
    version_ids = [str(entry.get("versionId")) for entry in entries]
    for version_id, rule in requirements:
        number = version_ids.index(version_id) + 1
        approvals = 0
        for witness in dict.fromkeys(rule.witnesses):
            approved = validated.get(witness, {})
            if any(
                number <= check_number <= len(version_ids) and version_ids[check_number - 1] == check_id
                for check_number, check_id in approved.items()
            ):
                approvals += 1
        if approvals < rule.threshold:
            raise DidWebvhError(
                "invalidDid",
                f"did:webvh log verification failed: Witness threshold not met for version {version_id}: "
                f"got {approvals}, need {rule.threshold}",
            )


async def _finish_witnessed_entry(
    candidate: str, witness_file: str | None, collect: DidWebvhWitnessCollector | None
) -> DidWebvhLogResult:
    """Collect the approvals of the last entry of *candidate* when a witness rule governs it, and resolve with them.

    The candidate is never returned without its approvals reaching the threshold.
    """
    entries = _parse_log(candidate)
    tip = entries[-1]
    rule = next((rule for version_id, rule in _witness_requirements(entries) if version_id == tip["versionId"]), None)
    if rule is None:
        return await resolve_did_webvh_log(candidate, witness_file=witness_file)
    if collect is None:
        raise DidWebvhError(
            "invalidInput",
            f"did:webvh entry {tip['versionId']} needs approval from {rule.threshold} witness(es); "
            "pass collect_witness_proofs",
        )
    approvals = await collect(
        DidWebvhWitnessRequest(
            did=str(tip["state"]["id"]),
            version_id=str(tip["versionId"]),
            log=candidate,
            witness=DidWebvhWitnessConfig(threshold=rule.threshold, witnesses=list(rule.witnesses)),
            witness_file=witness_file,
        )
    )
    if not isinstance(approvals, list):
        raise DidWebvhError("invalidInput", "collect_witness_proofs must return a list of witness proof entries")
    new_entries = [_witness_entry(item) for item in approvals]
    merged = _serialize_witness_file([*_parse_witness_file(witness_file), *new_entries])
    return await resolve_did_webvh_log(candidate, witness_file=merged)


_WITNESS_DID = re.compile(r"^did:key:(z[1-9A-HJ-NP-Za-km-z]+)$")


def _witness_parameter(config: DidWebvhWitnessConfig) -> dict[str, Any]:
    if not isinstance(config, DidWebvhWitnessConfig) or not isinstance(config.witnesses, list):
        raise DidWebvhError("invalidInput", "witness must be DidWebvhWitnessConfig(threshold, witnesses)")
    threshold, witnesses = config.threshold, config.witnesses
    if not witnesses:
        raise DidWebvhError(
            "invalidInput", "witness.witnesses must not be empty; pass REMOVE_WITNESSES to remove witnessing"
        )
    if not isinstance(threshold, int) or isinstance(threshold, bool) or threshold < 1 or threshold > len(witnesses):
        raise DidWebvhError("invalidInput", "witness.threshold must be an integer from 1 to the number of witnesses")
    seen: set[str] = set()
    for witness in witnesses:
        match = _WITNESS_DID.match(witness) if isinstance(witness, str) else None
        if match is None:
            raise DidWebvhError("invalidInput", f"witness.witnesses entries must be did:key DIDs: {witness}")
        try:
            _validate_update_key(match.group(1))
        except DidWebvhError:
            raise DidWebvhError("invalidInput", f"witness DIDs must use Ed25519 keys: {witness}") from None
        if witness in seen:
            raise DidWebvhError("invalidInput", f"witness.witnesses must not repeat a DID: {witness}")
        seen.add(witness)
    return {"threshold": threshold, "witnesses": [{"id": witness} for witness in witnesses]}


def _witness_metadata(value: Any) -> dict[str, Any]:
    witness = value if isinstance(value, dict) else {}
    items = witness.get("witnesses")
    ids = (
        [item["id"] for item in items if isinstance(item, dict) and isinstance(item.get("id"), str)]
        if isinstance(items, list)
        else []
    )
    try:
        threshold = int(witness.get("threshold", 0))
    except (TypeError, ValueError):
        threshold = 0
    active = bool(ids) and threshold > 0
    return {"witness_threshold": str(threshold) if active else "0", "witnesses": ids if active else []}


def _parse_witness_file(witness_file: str | None) -> list[DidWebvhWitnessProofEntry]:
    if witness_file is None:
        return []
    if not isinstance(witness_file, str):
        raise DidWebvhError("invalidInput", "did:webvh witness file must be a string")
    try:
        parsed = json.loads(witness_file)
    except ValueError:
        raise DidWebvhError("invalidDid", "did:webvh witness file is not valid JSON") from None
    if not isinstance(parsed, list):
        raise DidWebvhError("invalidDid", "did:webvh witness file must be a JSON array")
    return [_witness_entry(item) for item in parsed]


def _witness_entry(entry: Any) -> DidWebvhWitnessProofEntry:
    if (
        not isinstance(entry, dict)
        or not isinstance(entry.get("versionId"), str)
        or not isinstance(entry.get("proof"), list)
        or not all(isinstance(proof, dict) for proof in entry["proof"])
    ):
        raise DidWebvhError("invalidDid", "did:webvh witness file entries must be { versionId, proof: [ ... ] }")
    return {"versionId": entry["versionId"], "proof": entry["proof"]}


def _compact(value: Any) -> str:
    return json.dumps(value, separators=(",", ":"), ensure_ascii=False)


def _serialize_witness_file(entries: list[DidWebvhWitnessProofEntry]) -> str:
    """Serialize witness proof entries as ``didwebvh-ts`` does, merging the proofs of entries with the same
    ``versionId`` in first-seen order."""
    merged: list[DidWebvhWitnessProofEntry] = []
    for entry in entries:
        proofs = [json.loads(_compact(proof)) for proof in entry["proof"]]
        existing = next((item for item in merged if item["versionId"] == entry["versionId"]), None)
        if existing is None:
            merged.append({"versionId": entry["versionId"], "proof": proofs})
            continue
        known = {_compact(proof) for proof in existing["proof"]}
        for proof in proofs:
            if _compact(proof) not in known:
                existing["proof"].append(proof)
                known.add(_compact(proof))
    return _compact(merged)


class _TextHistory(HistoryResolver):  # type: ignore[misc]
    """Feeds already-fetched log text (and ``did-witness.json``) to the reference resolver; never does I/O."""

    def __init__(self, text: str, witness_text: str | None = None) -> None:
        self._text = text
        self._witness_text = witness_text

    def resolve_entry_log(self, _document_id: str | None) -> Any:
        return _read_text(self._text)

    def resolve_witness_log(self, _document_id: str | None) -> Any:
        if self._witness_text is not None:
            return _read_text(self._witness_text)
        return _no_witness_log()


@asynccontextmanager
async def _read_text(text: str) -> AsyncIterator[Any]:
    yield AsyncTextReader(init=text)


@asynccontextmanager
async def _no_witness_log() -> AsyncIterator[Any]:
    raise AsyncTextReadError("did:webvh witness proofs (did-witness.json) must be supplied by the caller")
    yield  # pragma: no cover


async def _resolve_verified_state(
    serialized: str, witness_text: str | None, *, verify_witness: bool = True, **selection: str | None
) -> tuple[DocumentState, Any]:
    """Run the reference resolver over log text and map its failures to :class:`DidWebvhError`."""
    try:
        state, meta = await DidResolver(WebvhVerifier()).resolve_state(
            None, _TextHistory(serialized, witness_text), verify_witness=verify_witness, **selection
        )
    except ResolutionError as err:
        raise DidWebvhError(_map_resolution_error(err.error), _resolution_message(err)) from None
    except InvalidDocumentState as err:
        raise DidWebvhError("invalidDid", f"did:webvh log verification failed: {err}") from None
    except AsyncTextReadError as err:
        raise DidWebvhError("notFound", f"did:webvh log verification failed: {err}") from None
    except Exception as err:  # noqa: BLE001 - fail closed on any library defect
        raise DidWebvhError("invalidDid", f"did:webvh log verification failed: {type(err).__name__}") from None
    return state, meta


async def _load_last_state(log: str, witness_file: str | None) -> DocumentState:
    state, _meta = await DidResolver(WebvhVerifier()).resolve_state(
        None, _TextHistory(_serialize(_parse_log(log)), witness_file)
    )
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
    options_hash = hashlib.sha256(canonicalize_json(options).encode("utf-8")).digest()
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


def _update_keys_used_in(entries: list[dict[str, Any]]) -> list[str]:
    """Every key that any entry of the log sets in ``updateKeys``."""
    used: list[str] = []
    for entry in entries:
        parameters = entry.get("parameters")
        keys = parameters.get("updateKeys") if isinstance(parameters, dict) else None
        if isinstance(keys, list):
            used.extend(key for key in keys if isinstance(key, str) and key not in used)
    return used


def _next_key_hashes_for(
    next_update_keys: list[str] | None, active_keys: list[str], used_keys: list[str]
) -> list[str] | None:
    """Hash pre-rotation keys. None means "no change". The keys must be new: never one active in the entry
    being written, and never one the log has already set in ``updateKeys``."""
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
    if any(key in used_keys for key in next_update_keys):
        raise DidWebvhError(
            "invalidInput",
            "next_update_keys must not include a key that the log has already used in updateKeys: "
            "pre-rotation commits to NEW keys",
        )
    return [_next_key_hash(key) for key in next_update_keys]


def did_webvh_last_entry_signers(log: str) -> list[str]:
    """The multikeys (``z6Mk...``) that made the proofs of the LAST entry of a log: the keys that endorsed the current
    document. The log must already be verified (:func:`resolve_did_webvh_log`), which guarantees each proof is valid
    and was made by a key authorized by the ``updateKeys`` in force; this only reads which keys they were."""
    proofs = _parse_log(log)[-1].get("proof")
    signers: list[str] = []
    if not isinstance(proofs, list):
        return signers
    for proof in proofs:
        method = proof.get("verificationMethod") if isinstance(proof, dict) else None
        match = re.fullmatch(r"did:key:(z[1-9A-HJ-NP-Za-km-z]+)(?:#.*)?", method) if isinstance(method, str) else None
        if match and match.group(1) not in signers:
            signers.append(match.group(1))
    return signers


DidWebvhLogRelation = Literal["equal", "extends", "prefix", "diverged"]
"""How a candidate log relates to a stored one: it equals it, extends it, is a strict prefix of it
(older) or diverges from it."""


def compare_did_webvh_logs(stored: str, candidate: str) -> DidWebvhLogRelation:
    """Compare two did:webvh logs entry by entry by ``versionId``.

    Each ``versionId`` hashes its entry and the previous ``versionId``, so equal ids mean equal
    prefixes. Callers verify both logs first; this only compares their shape.
    """
    stored_ids = [entry.get("versionId") for entry in _parse_log(stored)]
    candidate_ids = [entry.get("versionId") for entry in _parse_log(candidate)]
    shared = min(len(stored_ids), len(candidate_ids))
    if stored_ids[:shared] != candidate_ids[:shared]:
        return "diverged"
    if len(stored_ids) == len(candidate_ids):
        return "equal"
    return "extends" if len(candidate_ids) > len(stored_ids) else "prefix"


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
