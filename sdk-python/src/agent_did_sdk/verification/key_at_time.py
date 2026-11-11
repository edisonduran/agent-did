"""Key checks at a stated time against a verified did:webvh log (RFC-001 §6.2.2).

The time a signed artifact states is asserted by the signer. It locates the DID state the signer claims, but it
cannot prove the signature was made before a later change: whoever holds a retired key can state any earlier
time. So a key that was authorized at the stated time and retired later is ``indeterminate`` unless trusted time
evidence places the signature before the retirement.

TypeScript parity: ``sdk/src/verification/key-at-time.ts``.
"""

from __future__ import annotations

import calendar
import json
import re
from dataclasses import dataclass
from typing import Any

from nacl.exceptions import BadSignatureError
from nacl.signing import VerifyKey

from ..core.identity_composition import DID_VERIFICATION_RELATIONSHIPS, REQUIRED_RELATIONSHIP_BY_ARTIFACT
from ..core.types import (
    KeyAtTimeRejection,
    KeyAtTimeResult,
    VerificationRelationship,
    VerifySignatureAtTimeResult,
)
from ..crypto.multibase import decode_public_key_multibase
from ..webvh.adapter import resolve_did_webvh_log

_RFC3339 = re.compile(
    r"^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,9}))?(Z|[+-]\d{2}:\d{2})$", re.IGNORECASE | re.ASCII
)


def parse_rfc3339_millis(value: object) -> int | None:
    """Parse an RFC 3339 date-time into milliseconds since the epoch, truncating sub-millisecond digits.

    Returns ``None`` for anything else (no other formats, no out-of-range fields).
    """
    if not isinstance(value, str):
        return None
    match = _RFC3339.match(value)
    if match is None:
        return None
    year, month, day, hour, minute, second = (int(group) for group in match.groups()[:6])
    fraction, offset = match.group(7), match.group(8)
    if year < 1 or not 1 <= month <= 12 or day < 1 or hour > 23 or minute > 59 or second > 59:
        return None
    if day > calendar.monthrange(year, month)[1]:
        return None
    millis = int(fraction.ljust(3, "0")[:3]) if fraction else 0
    offset_minutes = 0
    if offset.upper() != "Z":
        sign = -1 if offset.startswith("-") else 1
        offset_hours, offset_mins = int(offset[1:3]), int(offset[4:6])
        if offset_hours > 23 or offset_mins > 59:
            return None
        offset_minutes = sign * (offset_hours * 60 + offset_mins)
    seconds = calendar.timegm((year, month, day, hour, minute, second, 0, 0, 0))
    return seconds * 1000 + millis - offset_minutes * 60_000


@dataclass(frozen=True)
class _LogEntry:
    version_id: str
    version_time: str
    version_millis: int
    deactivated: bool
    state: dict[str, Any]


@dataclass(frozen=True)
class _KeyInState:
    ok: bool
    reason: KeyAtTimeRejection | None = None
    found_in: tuple[VerificationRelationship, ...] = ()
    public_key_multibase: str | None = None


def _string_list(value: object) -> list[str]:
    return [item for item in value if isinstance(item, str)] if isinstance(value, list) else []


def _relationships_of(state: dict[str, Any], key_id: str) -> tuple[VerificationRelationship, ...]:
    return tuple(r for r in DID_VERIFICATION_RELATIONSHIPS if key_id in _string_list(state.get(r)))


def _key_in_state(state: dict[str, Any], key_id: str, required_purpose: VerificationRelationship) -> _KeyInState:
    """Whether ``key_id`` is an authorized ``required_purpose`` key in ``state``."""
    found_in = _relationships_of(state, key_id)
    methods = state.get("verificationMethod")
    method = next(
        (m for m in (methods if isinstance(methods, list) else []) if isinstance(m, dict) and m.get("id") == key_id),
        None,
    )
    public_key = method.get("publicKeyMultibase") if method is not None else None
    if method is None or not isinstance(public_key, str) or not public_key:
        return _KeyInState(ok=False, reason="key_not_found", found_in=found_in)
    # The log entry that gives a key a ``deactivated`` time retires it from that entry's versionTime. The time
    # itself is not compared with anything: the SDK's rotation writes the document clock, with milliseconds, next
    # to a versionTime in seconds, so the time can be later than the entry that carries it.
    if method.get("deactivated") is not None:
        return _KeyInState(ok=False, reason="key_deactivated", found_in=found_in)
    if required_purpose == "keyAgreement" or required_purpose not in found_in:
        return _KeyInState(ok=False, reason="key_purpose_violation", found_in=found_in)
    return _KeyInState(ok=True, public_key_multibase=public_key)


async def check_did_webvh_key_at_time(
    log: str,
    *,
    key_id: str,
    stated_time: str,
    required_purpose: VerificationRelationship = REQUIRED_RELATIONSHIP_BY_ARTIFACT["assertion"],
    did: str | None = None,
    trusted_time_not_after: str | None = None,
) -> KeyAtTimeResult:
    """Check whether ``key_id`` was authorized for ``required_purpose`` at ``stated_time``, per a did:webvh log.

    The whole log is verified first (``resolve_did_webvh_log``); a log that fails verification raises
    ``DidWebvhError``. Then the entry in effect at the stated time (the last one whose ``versionTime`` is not
    after it) decides ``authorized`` / ``not_authorized``, and any later entry that retires the key or deactivates
    the DID turns ``authorized`` into ``indeterminate``, unless ``trusted_time_not_after`` is earlier than that
    entry. A key is retired from the ``versionTime`` of the entry that gives it a ``deactivated`` time, whatever
    that time says. ``trusted_time_not_after`` is trusted evidence (for example a verified RFC 3161 timestamp) that the
    signature existed no later than that time; only the caller can vouch for it.
    """
    evidence_millis: int | None = None
    if trusted_time_not_after is not None:
        evidence_millis = parse_rfc3339_millis(trusted_time_not_after)
        if evidence_millis is None:
            raise ValueError(f"trusted_time_not_after is not an RFC 3339 date-time: {trusted_time_not_after!r}")

    resolved = await resolve_did_webvh_log(log, did=did)

    stated_millis = parse_rfc3339_millis(stated_time)
    if stated_millis is None:
        return KeyAtTimeResult(status="not_authorized", key_id=key_id, reason="invalid_stated_time")

    entries: list[_LogEntry] = []
    for line in resolved.log.split("\n"):
        if not line.strip():
            continue
        entry = json.loads(line)
        version_millis = parse_rfc3339_millis(entry["versionTime"])
        if version_millis is None:
            # resolve_did_webvh_log already rejects such logs; this keeps the type honest.
            raise ValueError(f"did:webvh entry {entry['versionId']} has an unreadable versionTime")
        parameters = entry.get("parameters") or {}
        entries.append(
            _LogEntry(
                version_id=entry["versionId"],
                version_time=entry["versionTime"],
                version_millis=version_millis,
                deactivated=parameters.get("deactivated") is True,
                state=entry["state"],
            )
        )

    index = -1
    for position, candidate in enumerate(entries):
        if candidate.version_millis <= stated_millis:
            index = position
    if index < 0:
        return KeyAtTimeResult(status="not_authorized", key_id=key_id, reason="did_not_yet_created")
    current = entries[index]
    if current.deactivated:
        return KeyAtTimeResult(
            status="not_authorized",
            key_id=key_id,
            reason="did_deactivated",
            found_in=_relationships_of(current.state, key_id),
        )
    at_stated_time = _key_in_state(current.state, key_id, required_purpose)
    if not at_stated_time.ok:
        return KeyAtTimeResult(
            status="not_authorized", key_id=key_id, reason=at_stated_time.reason, found_in=at_stated_time.found_in
        )

    # The first entry after the stated time that ends the key's authorization, if any.
    boundary: _LogEntry | None = None
    for later in entries[index + 1 :]:
        if later.deactivated or not _key_in_state(later.state, key_id, required_purpose).ok:
            boundary = later
            break

    if boundary is None or (evidence_millis is not None and evidence_millis < boundary.version_millis):
        return KeyAtTimeResult(
            status="authorized",
            key_id=key_id,
            public_key_multibase=at_stated_time.public_key_multibase,
            version_id=current.version_id,
            basis="no_later_change" if boundary is None else "time_evidence",
        )
    return KeyAtTimeResult(
        status="indeterminate",
        key_id=key_id,
        reason="did_deactivated_after_stated_time" if boundary.deactivated else "key_retired_after_stated_time",
        public_key_multibase=at_stated_time.public_key_multibase,
        boundary_version_id=boundary.version_id,
        boundary_time=boundary.version_time,
    )


def signature_result_for_key(key: KeyAtTimeResult, payload: str, signature: str) -> VerifySignatureAtTimeResult:
    """Combine a key check at a stated time with the Ed25519 check of ``signature`` (hex) over ``payload``."""
    if key.status == "not_authorized":
        return VerifySignatureAtTimeResult(status="invalid", reason="key_not_authorized", key=key)
    if key.public_key_multibase is None:
        # Only ``history_unavailable`` has no key to check the signature with.
        return VerifySignatureAtTimeResult(status="indeterminate", key=key)
    try:
        VerifyKey(decode_public_key_multibase(key.public_key_multibase)).verify(
            payload.encode("utf-8"), bytes.fromhex(signature)
        )
    except (BadSignatureError, ValueError, TypeError):
        return VerifySignatureAtTimeResult(status="invalid", reason="signature_invalid", key=key)
    if key.status == "authorized":
        return VerifySignatureAtTimeResult(status="valid", key=key)
    return VerifySignatureAtTimeResult(status="indeterminate", key=key)
