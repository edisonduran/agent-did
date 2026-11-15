"""Agent-DID RFC 9421 request verification (profile checks, signature base, replay).

The cryptographic check is injected so this module never resolves DIDs itself.
TypeScript parity: ``sdk/src/http-signatures/verify-request.ts``.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable, Sequence
from dataclasses import dataclass
from datetime import datetime
from typing import Literal

from ..core.http_profile import (
    AGENT_DID_HTTP_SIGNATURE_TAG,
    agent_did_http_signature_components,
    compute_content_digest,
    parse_agent_did_header,
)
from ..core.http_signatures import (
    ComponentIdentifier,
    HttpRequestLike,
    HttpSignatureError,
    build_signature_base,
    parse_signature_header,
    parse_signature_input_header,
    request_url_form_problem,
    serialize_component_identifier,
)
from ..core.identity_composition import REQUIRED_RELATIONSHIP_BY_ARTIFACT
from ..core.nonce_store import NONCE_PATTERN, NonceStore
from ..core.types import (
    HttpSignatureRejection,
    VerificationRelationship,
    VerifyHttpRequestSignatureParams,
    VerifyHttpRequestSignatureResult,
)

SignatureCheckOutcome = Literal[
    "valid", "invalid", "key_not_authorized", "did_resolution_failed", "controller_not_bound"
]
"""What the injected cryptographic check found."""



@dataclass(frozen=True)
class SignatureCheck:
    """What the injected check found and, for a valid signature, the controller chain of the DID (nearest first)."""

    outcome: SignatureCheckOutcome
    controllers: tuple[str, ...] = ()


# (did, payload, signature_hex, key_id, purpose) -> check
VerifySignatureFn = Callable[[str, str, str, str, VerificationRelationship], Awaitable[SignatureCheck]]


def _reject(reason: HttpSignatureRejection) -> VerifyHttpRequestSignatureResult:
    return VerifyHttpRequestSignatureResult(ok=False, reason=reason)


def _starts_with_components(
    components: Sequence[ComponentIdentifier], required: Sequence[ComponentIdentifier]
) -> bool:
    """RFC-001 §6.5 item 2: the required components, in this order; additional ones may follow."""
    return len(components) >= len(required) and all(
        serialize_component_identifier(c) == serialize_component_identifier(r) for c, r in zip(components, required)
    )


def _covers_all(components: Sequence[ComponentIdentifier], required: Sequence[ComponentIdentifier]) -> bool:
    covered = {serialize_component_identifier(c) for c in components}
    return all(serialize_component_identifier(r) in covered for r in required)


async def verify_agent_did_http_request(
    params: VerifyHttpRequestSignatureParams,
    *,
    verify_signature: VerifySignatureFn,
    nonce_store: NonceStore,
    now: datetime,
) -> VerifyHttpRequestSignatureResult:
    headers = {key.lower(): value for key, value in params.headers.items()}
    if not headers.get("signature") or not headers.get("signature-input") or not headers.get("agent-did"):
        return _reject("missing_headers")
    if request_url_form_problem(params.url) is not None:
        return _reject("url_not_normalized")
    if headers.get("content-digest") != compute_content_digest(params.body):
        return _reject("digest_mismatch")

    try:
        inputs = parse_signature_input_header(headers["signature-input"])
        signatures = parse_signature_header(headers["signature"])
        agent_dids = parse_agent_did_header(headers["agent-did"])
    except HttpSignatureError:
        return _reject("malformed_headers")

    now_seconds = int(now.timestamp())
    max_skew = params.max_created_skew_seconds if params.max_created_skew_seconds is not None else 300
    max_lifetime = (
        params.max_signature_lifetime_seconds if params.max_signature_lifetime_seconds is not None else 300
    )
    store = params.nonce_store if params.nonce_store is not None else nonce_store
    request = HttpRequestLike(method=params.method.upper(), url=params.url, headers=headers)

    # The reason reported is the first one of a signature with the Agent-DID tag, else the first one.
    failures: list[tuple[HttpSignatureRejection, bool]] = []

    for label, signature_input in inputs.items():
        signature = signatures.get(label)
        if signature is None:
            failures.append(("malformed_headers", False))
            continue
        if signature_input.get("tag") != AGENT_DID_HTTP_SIGNATURE_TAG:
            failures.append(("tag_mismatch", False))
            continue

        created = signature_input.get("created")
        expires = signature_input.get("expires")
        nonce = signature_input.get("nonce")
        key_id = signature_input.get("keyid")
        if signature_input.get("alg") != "ed25519":
            failures.append(("alg_unsupported", True))
            continue
        if (
            not isinstance(created, int)
            or isinstance(created, bool)
            or not isinstance(expires, int)
            or isinstance(expires, bool)
            or not isinstance(nonce, str)
            or not NONCE_PATTERN.fullmatch(nonce)
            or not isinstance(key_id, str)
        ):
            failures.append(("params_missing", True))
            continue
        required = agent_did_http_signature_components(label)
        if not _starts_with_components(signature_input.components, required):
            all_covered = _covers_all(signature_input.components, required)
            failures.append(("components_order" if all_covered else "components_missing", True))
            continue
        # The agent DID is the Agent-DID member keyed by this signature's label: a String without parameters
        if label not in agent_dids:
            failures.append(("signed_component_missing", True))
            continue
        agent_did = agent_dids[label]
        if agent_did is None:
            failures.append(("malformed_headers", True))
            continue
        # Before any resolution: a DID outside the list costs no network call
        if params.allowed_dids is not None and agent_did not in params.allowed_dids:
            failures.append(("did_not_allowed", True))
            continue
        if not key_id.startswith(f"{agent_did}#"):
            failures.append(("keyid_not_bound", True))
            continue
        if abs(now_seconds - created) > max_skew:
            failures.append(("created_skew", True))
            continue
        if expires < created:
            failures.append(("expires_before_created", True))
            continue
        if expires - created > max_lifetime:
            failures.append(("lifetime_exceeded", True))
            continue
        if now_seconds > expires:
            failures.append(("expired", True))
            continue

        try:
            signature_base = build_signature_base(request, signature_input)
        except HttpSignatureError:
            failures.append(("signed_component_missing", True))
            continue

        check = await verify_signature(
            agent_did, signature_base, signature.hex(), key_id, REQUIRED_RELATIONSHIP_BY_ARTIFACT["http_request"]
        )
        outcome = check.outcome
        if outcome != "valid":
            if outcome == "did_resolution_failed":
                failures.append(("did_resolution_failed", True))
            elif outcome == "controller_not_bound":
                failures.append(("controller_not_bound", True))
            elif outcome == "key_not_authorized":
                failures.append(("keyid_not_authorized", True))
            else:
                failures.append(("signature_invalid", True))
            continue

        controllers = list(check.controllers)
        allowed_controllers = params.allowed_controllers
        if allowed_controllers is not None and not any(c in allowed_controllers for c in controllers):
            failures.append(("controller_not_allowed", True))
            continue

        # Record the nonce only for an accepted signature, so forged or refused requests cannot burn nonces.
        if await store.check_and_store(f"{key_id} {nonce}", expires):
            return VerifyHttpRequestSignatureResult(
                ok=True, did=agent_did, key_id=key_id, controllers=controllers
            )
        return _reject("nonce_replayed")

    tagged = [reason for reason, is_tagged in failures if is_tagged]
    if tagged:
        return _reject(tagged[0])
    return _reject(failures[0][0] if failures else "malformed_headers")
