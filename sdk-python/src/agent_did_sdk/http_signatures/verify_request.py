"""Agent-DID RFC 9421 request verification (profile checks, signature base, replay).

The cryptographic check is injected so this module never resolves DIDs itself.
TypeScript parity: ``sdk/src/http-signatures/verify-request.ts``.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable, Sequence
from datetime import datetime

from ..core.http_profile import (
    AGENT_DID_HTTP_SIGNATURE_COMPONENTS,
    AGENT_DID_HTTP_SIGNATURE_TAG,
    compute_content_digest,
)
from ..core.http_signatures import (
    HttpRequestLike,
    HttpSignatureError,
    build_signature_base,
    parse_signature_header,
    parse_signature_input_header,
)
from ..core.identity_composition import IdentityCompositionError
from ..core.nonce_store import NonceStore
from ..core.types import VerificationRelationship, VerifyHttpRequestSignatureParams

# (did, payload, signature_hex, key_id, purpose) -> valid?
VerifySignatureFn = Callable[[str, str, str, str, VerificationRelationship], Awaitable[bool]]


def _starts_with_components(components: Sequence[str], required: Sequence[str]) -> bool:
    """RFC-001 §6.5 item 2: the required components, in this order; additional ones may follow."""
    return len(components) >= len(required) and all(c == r for c, r in zip(components, required))


async def verify_agent_did_http_request(
    params: VerifyHttpRequestSignatureParams,
    *,
    verify_signature: VerifySignatureFn,
    nonce_store: NonceStore,
    now: datetime,
) -> bool:
    headers = {key.lower(): value for key, value in params.headers.items()}
    signature_agent = headers.get("signature-agent")
    if not headers.get("signature") or not headers.get("signature-input") or not signature_agent:
        return False
    if headers.get("content-digest") != compute_content_digest(params.body):
        return False

    try:
        inputs = parse_signature_input_header(headers["signature-input"])
        signatures = parse_signature_header(headers["signature"])
    except HttpSignatureError:
        return False

    now_seconds = int(now.timestamp())
    max_skew = params.max_created_skew_seconds if params.max_created_skew_seconds is not None else 300
    max_lifetime = (
        params.max_signature_lifetime_seconds if params.max_signature_lifetime_seconds is not None else 300
    )
    store = params.nonce_store if params.nonce_store is not None else nonce_store
    request = HttpRequestLike(method=params.method.upper(), url=params.url, headers=headers)

    for label, signature_input in inputs.items():
        signature = signatures.get(label)
        if signature is None:
            continue

        created = signature_input.get("created")
        expires = signature_input.get("expires")
        nonce = signature_input.get("nonce")
        key_id = signature_input.get("keyid")
        if (
            signature_input.get("tag") != AGENT_DID_HTTP_SIGNATURE_TAG
            or signature_input.get("alg") != "ed25519"
            or not isinstance(created, int)
            or isinstance(created, bool)
            or not isinstance(expires, int)
            or isinstance(expires, bool)
            or not isinstance(nonce, str)
            or not nonce
            or not isinstance(key_id, str)
            or not key_id.startswith(f"{signature_agent}#")
            or not _starts_with_components(signature_input.components, AGENT_DID_HTTP_SIGNATURE_COMPONENTS)
            or abs(now_seconds - created) > max_skew
            or expires < created
            or expires - created > max_lifetime
            or now_seconds > expires
        ):
            continue

        try:
            signature_base = build_signature_base(request, signature_input)
        except HttpSignatureError:
            continue

        # A `keyid` that is not an `assertionMethod` of the DID is an untrusted input, so it is a
        # rejection (`False`), not an exception.
        try:
            signature_valid = await verify_signature(
                signature_agent, signature_base, signature.hex(), key_id, "assertionMethod"
            )
        except IdentityCompositionError:
            continue
        if not signature_valid:
            continue

        # Record the nonce only for a valid signature, so forged requests cannot burn nonces.
        return await store.check_and_store(f"{key_id} {nonce}", expires)

    return False
