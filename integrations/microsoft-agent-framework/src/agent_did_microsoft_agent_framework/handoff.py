"""Verified-handoff helper for Microsoft Agent Framework workflows.

Implements the `add_verified_handoff(...)` design locked with @haroldmalikfrimpong-ops
in https://github.com/edisonduran/agent-did/issues/26 and the originating thread
`microsoft/agent-framework#4842`.

Design contract (locked):
- Hard gate, fail-closed at the handoff boundary.
- `action_class` first-class parameter drives TTL semantics.
- Default behavior on a blocked handoff is to raise ``VerificationBlockedError``;
  callers may opt in via ``on_verification_blocked`` callback to either halt the
  workflow gracefully (return ``None``) or route to a custom executor result
  (return any value, which becomes the verifier executor's output).
- Cross-domain hops always force a fresh verification (TTL collapses to 0).
- ``action_class="irreversible"`` always forces a fresh verification regardless of
  any larger TTL the caller may try to override.
- Key-rotation race: inside the action-class TTL window, a signature that does not
  verify against the current key set is checked against the DID's did:webvh log at
  ``signed_at`` (RFC-001 §6.2.2). ``signed_at`` is asserted by the signer, so a key
  retired after it gives ``indeterminate`` and the handoff is blocked with
  ``key_lifecycle``: the signer must re-sign with a current key. Once the TTL
  elapses, the next handoff MUST verify against the agent's current key set.

- Signed envelope: the signature covers a canonical (RFC 8785) JSON envelope with the payload, the sender DID and
  key id, ``signed_at``, the destination executor id and a nonce, never ``str(payload)``. The verifier rebuilds the
  envelope from the message, so ``signed_at`` (and with it the TTL), the sender and the destination are what the
  signer signed. A message signed for another edge does not verify here, a ``(did, nonce)`` pair is accepted once
  (``nonce_store``; the default is per verifier and per process: pass a shared store when several instances verify)
  and ``signed_at`` cannot lie in the future beyond a small skew. ``allowed_dids`` is required for
  ``action_class="irreversible"`` and a warning is logged when a handoff accepts any DID.

This module deliberately delegates ALL key-lifecycle logic to the central SDK
primitives (``AgentDidClient.verify_signature`` and
``AgentDidClient.verify_signature_at_time``). It must not re-implement the
key rotation state machine — when the spec converges with `aeoess/agent-passport-system`
the SDK is the single source of truth and this helper inherits any change for free.
"""

from __future__ import annotations

import logging
import math
import secrets
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Literal

from agent_did_sdk import (
    AgentDidClient,
    AgentIdentity,
    IdentityCompositionError,
    InMemoryNonceStore,
    NonceStore,
    VerificationRelationship,
    VerifySignatureAtTimeResult,
    canonicalize_json,
)
from agent_framework import FunctionExecutor, WorkflowContext

from .observability import AgentDidObserver
from .snapshot import RuntimeIdentity, get_active_authentication_key_id, runtime_signing_key

_LOGGER = logging.getLogger(__name__)

ActionClass = Literal["irreversible", "compensable", "reversible"]

HANDOFF_TTL_DEFAULTS: dict[ActionClass, int] = {
    "irreversible": 30,
    "compensable": 120,
    "reversible": 300,
}

HANDOFF_ENVELOPE_TYPE = "agent-did/handoff/v1"
"""``type`` member of the signed handoff envelope."""

HANDOFF_MAX_AGE_SECONDS = 3600
"""A handoff signed longer ago than this is refused. It is also how long its nonce is remembered, so a captured
message cannot be replayed once the nonce store has forgotten it."""

HANDOFF_MAX_FUTURE_SKEW_SECONDS = 30
"""``signed_at`` is asserted by the signer: a value further in the future than this is refused."""

VerificationBlockedCallback = Callable[["VerificationBlockedError"], Any]


def build_handoff_envelope(
    *,
    did: str,
    key_id: str | None,
    signed_at: float,
    destination: str,
    nonce: str,
    payload: Any,
) -> str:
    """The canonical (RFC 8785) JSON text a handoff signature covers.

    ``payload`` must be JSON-serializable; anything else raises ``TypeError`` or ``ValueError``. The text is signed
    with ``AgentIdentity.sign_message`` (so it also carries that method's domain prefix).
    """
    return canonicalize_json(
        {
            "type": HANDOFF_ENVELOPE_TYPE,
            "did": did,
            "keyId": key_id,
            "signedAtMs": int(round(signed_at * 1000)),
            "destination": destination,
            "nonce": nonce,
            "payload": payload,
        }
    )


async def _default_verify_signature_at_time(
    did: str,
    payload: str,
    signature: str,
    key_id: str,
    *,
    stated_time: str,
    required_purpose: VerificationRelationship,
) -> VerifySignatureAtTimeResult:
    # Looked up at call time so that ``AgentIdentity.set_default_client`` is honoured.
    return await AgentIdentity.get_default_client().verify_signature_at_time(
        did, payload, signature, key_id, stated_time=stated_time, required_purpose=required_purpose
    )


@dataclass(slots=True)
class SignedHandoffMessage:
    """Wrapper carrying the signature metadata required at a handoff boundary.

    Upstream executors MUST emit a ``SignedHandoffMessage`` when handing off across
    a verified edge. The verifier extracts ``payload`` after a successful check and
    forwards it to the downstream executor unchanged.
    """

    payload: Any
    did: str
    signature: str
    signed_at: float
    key_id: str | None = None
    trust_domain: str | None = None
    nonce: str | None = None
    """Random single-use value covered by the signature. Required: a message without one is refused."""
    destination: str | None = None
    """Id of the executor this message is signed for (the verifier's downstream executor). Required."""


async def sign_handoff(
    *,
    agent_identity: AgentIdentity,
    runtime_identity: RuntimeIdentity,
    payload: Any,
    destination: str,
    trust_domain: str | None = None,
    signed_at: float | None = None,
    nonce: str | None = None,
) -> SignedHandoffMessage:
    """Sign ``payload`` for the handoff edge whose downstream executor id is ``destination``.

    The signature covers :func:`build_handoff_envelope` (payload, DID, key id, ``signed_at``, destination, nonce).
    ``payload`` must be JSON-serializable.
    """
    key_id = get_active_authentication_key_id(runtime_identity)
    document = runtime_identity.document
    moment = time.time() if signed_at is None else signed_at
    single_use = nonce if nonce is not None else secrets.token_hex(16)
    envelope = build_handoff_envelope(
        did=document.id, key_id=key_id, signed_at=moment, destination=destination, nonce=single_use, payload=payload
    )
    signature = await agent_identity.sign_message(envelope, runtime_signing_key(runtime_identity))
    return SignedHandoffMessage(
        payload=payload,
        did=document.id,
        signature=signature,
        signed_at=moment,
        key_id=key_id,
        trust_domain=trust_domain,
        nonce=single_use,
        destination=destination,
    )


class VerificationBlockedError(Exception):
    """Raised by ``add_verified_handoff`` when a handoff fails verification.

    Attributes match the shape locked in
    https://github.com/microsoft/agent-framework/issues/4842#issuecomment-4327716940.
    """

    def __init__(
        self,
        *,
        result: dict[str, Any],
        failing_gates: Sequence[str],
        enforcement_note: str,
        checked_did: str | None,
        action_class: ActionClass,
    ) -> None:
        super().__init__(enforcement_note)
        self.result = result
        self.failing_gates = list(failing_gates)
        self.enforcement_note = enforcement_note
        self.checked_did = checked_did
        self.action_class = action_class


@dataclass(slots=True)
class _VerifierContext:
    from_executor_id: str
    to_executor_id: str
    action_class: ActionClass
    ttl_seconds: int
    allowed_dids: tuple[str, ...] | None
    require_signature: bool
    cross_domain: bool
    on_verification_blocked: VerificationBlockedCallback | None
    observer: AgentDidObserver
    verify_signature: Callable[..., Any] = field(default=AgentIdentity.verify_signature)
    verify_signature_at_time: Callable[..., Any] = field(default=_default_verify_signature_at_time)
    now: Callable[[], float] = field(default=time.time)
    nonce_store: NonceStore = field(default_factory=InMemoryNonceStore)
    max_age_seconds: int = HANDOFF_MAX_AGE_SECONDS


def _resolve_executor_id(executor: Any) -> str:
    return getattr(executor, "id", None) or getattr(executor, "name", None) or type(executor).__name__


def _resolve_effective_ttl(
    action_class: ActionClass,
    ttl_seconds: int | None,
    cross_domain: bool,
) -> int:
    if cross_domain:
        return 0
    if action_class == "irreversible":
        # Irreversible always uses the (small) action-class default; callers cannot widen it.
        return HANDOFF_TTL_DEFAULTS["irreversible"]
    if ttl_seconds is not None:
        return max(0, int(ttl_seconds))
    return HANDOFF_TTL_DEFAULTS[action_class]


def _build_block_error(
    *,
    failing_gates: Sequence[str],
    checked_did: str | None,
    action_class: ActionClass,
    enforcement_note: str,
) -> VerificationBlockedError:
    return VerificationBlockedError(
        result={
            "valid": False,
            "did": checked_did,
            "failing_gates": list(failing_gates),
            "action_class": action_class,
        },
        failing_gates=failing_gates,
        enforcement_note=enforcement_note,
        checked_did=checked_did,
        action_class=action_class,
    )


def _emit_blocked(observer: AgentDidObserver, ctx: _VerifierContext, error: VerificationBlockedError) -> None:
    observer.emit(
        "agent_did.workflow.handoff_blocked",
        attributes={
            "from_executor": ctx.from_executor_id,
            "to_executor": ctx.to_executor_id,
            "from_did": error.checked_did,
            "action_class": ctx.action_class,
            "ttl_seconds": ctx.ttl_seconds,
            "failing_gates": error.failing_gates,
            "decision_reason": error.enforcement_note,
        },
        level="error",
    )


def _emit_verified(
    observer: AgentDidObserver,
    ctx: _VerifierContext,
    *,
    from_did: str,
    used_historical: bool,
    staleness_seconds: float,
) -> None:
    observer.emit(
        "agent_did.workflow.handoff_verified",
        attributes={
            "from_executor": ctx.from_executor_id,
            "to_executor": ctx.to_executor_id,
            "from_did": from_did,
            "to_did": None,
            "action_class": ctx.action_class,
            "ttl_seconds": ctx.ttl_seconds,
            "decision_reason": "ok",
            "used_historical_signature": used_historical,
            "staleness_seconds": staleness_seconds,
        },
    )


def _handle_block(ctx: _VerifierContext, error: VerificationBlockedError) -> Any:
    """Legacy synchronous block handler.

    Retained for callers that exercise the verifier directly without a workflow
    context (returns the callback value or raises). The async path used inside
    ``build_handoff_verifier_function`` calls ``_emit_block_outcome`` instead.
    """

    _emit_blocked(ctx.observer, ctx, error)
    if ctx.on_verification_blocked is None:
        raise error
    return ctx.on_verification_blocked(error)


def build_handoff_verifier_function(ctx: _VerifierContext) -> Callable[..., Any]:
    """Build the async function that backs the verifier ``FunctionExecutor``.

    The returned coroutine accepts ``(message, wf_ctx)`` where ``wf_ctx`` is the
    Microsoft Agent Framework ``WorkflowContext``. On success the inner payload
    is forwarded via ``await wf_ctx.send_message(payload)``. On failure the
    behaviour follows the locked design contract:

    - If no ``on_verification_blocked`` callback is registered, raise
      ``VerificationBlockedError``.
    - If a callback is registered and returns ``None``, halt gracefully (no
      message is sent downstream).
    - If a callback is registered and returns any other value, forward that value
      via ``await wf_ctx.send_message(value)``.
    """

    async def _verifier(message: Any, wf_ctx: WorkflowContext[Any]) -> None:
        if not isinstance(message, SignedHandoffMessage):
            await _emit_unsigned_outcome(ctx, wf_ctx, message)
            return

        if ctx.allowed_dids is not None and message.did not in ctx.allowed_dids:
            error = _build_block_error(
                failing_gates=["did_allowlist"],
                checked_did=message.did,
                action_class=ctx.action_class,
                enforcement_note=f"DID {message.did!r} not in allowed_dids",
            )
            await _emit_block_outcome(ctx, wf_ctx, error)
            return

        envelope_problem = _check_envelope_fields(ctx, message)
        if envelope_problem is not None:
            gate, note = envelope_problem
            error = _build_block_error(
                failing_gates=[gate], checked_did=message.did, action_class=ctx.action_class, enforcement_note=note
            )
            await _emit_block_outcome(ctx, wf_ctx, error)
            return

        outcome = await _run_signature_verification(ctx, message)
        if not outcome.valid:
            error = _build_block_error(
                failing_gates=[outcome.gate],
                checked_did=message.did,
                action_class=ctx.action_class,
                enforcement_note=_block_note(outcome, ctx.ttl_seconds, message.did),
            )
            await _emit_block_outcome(ctx, wf_ctx, error)
            return

        # The nonce is recorded only for a message whose signature verified, so garbage cannot burn nonces.
        remembered_until = int(message.signed_at + ctx.max_age_seconds) + 1
        if not await ctx.nonce_store.check_and_store(f"{message.did}|{message.nonce}", remembered_until):
            error = _build_block_error(
                failing_gates=["replay"],
                checked_did=message.did,
                action_class=ctx.action_class,
                enforcement_note=f"Handoff nonce already used for {message.did} (replay), or the nonce store is full",
            )
            await _emit_block_outcome(ctx, wf_ctx, error)
            return

        _emit_verified(
            ctx.observer, ctx,
            from_did=message.did, used_historical=outcome.used_key_at_time, staleness_seconds=outcome.staleness,
        )
        await wf_ctx.send_message(message.payload)

    return _verifier


def _check_envelope_fields(ctx: _VerifierContext, message: SignedHandoffMessage) -> tuple[str, str] | None:
    """Checks that need no cryptography: ``(gate, note)`` for the first one that fails, else ``None``."""
    if message.destination != ctx.to_executor_id:
        return (
            "destination",
            f"Handoff is signed for {message.destination!r}, not for this edge's executor {ctx.to_executor_id!r}",
        )
    if not isinstance(message.nonce, str) or not message.nonce:
        return "nonce", "Handoff message carries no nonce"
    now = ctx.now()
    if not math.isfinite(message.signed_at) or not math.isfinite(now):
        return "signed_at", "Handoff signed_at is not a finite time"
    if message.signed_at > now + HANDOFF_MAX_FUTURE_SKEW_SECONDS:
        return "signed_at", "Handoff signed_at lies in the future beyond the allowed skew"
    if now - message.signed_at > ctx.max_age_seconds:
        return "signed_at", f"Handoff is older than {ctx.max_age_seconds}s and is refused"
    return None


async def _emit_unsigned_outcome(ctx: _VerifierContext, wf_ctx: Any, message: Any) -> None:
    if not ctx.require_signature:
        await wf_ctx.send_message(message)
        return
    error = _build_block_error(
        failing_gates=["signature"],
        checked_did=None,
        action_class=ctx.action_class,
        enforcement_note="Handoff message is not a SignedHandoffMessage and require_signature=True",
    )
    await _emit_block_outcome(ctx, wf_ctx, error)


async def _emit_block_outcome(ctx: _VerifierContext, wf_ctx: Any, error: VerificationBlockedError) -> None:
    _emit_blocked(ctx.observer, ctx, error)
    if ctx.on_verification_blocked is None:
        raise error
    callback_result = ctx.on_verification_blocked(error)
    if callback_result is None:
        return  # halt gracefully
    await wf_ctx.send_message(callback_result)


@dataclass(frozen=True, slots=True)
class _SignatureOutcome:
    valid: bool
    staleness: float
    gate: str = "signature"
    """Meaningful only when ``valid`` is ``False``."""
    used_key_at_time: bool = False
    past_ttl: bool = False
    key_at_time: VerifySignatureAtTimeResult | None = None


def _block_note(outcome: _SignatureOutcome, ttl_seconds: int, did: str) -> str:
    if outcome.gate == "payload":
        return "Handoff payload is not JSON-serializable, so it cannot match a signed envelope"
    if outcome.past_ttl:
        return (
            f"Signature past action-class TTL ({ttl_seconds}s) and the previous key "
            "no longer verifies against the current key set"
        )
    at_time = outcome.key_at_time
    if at_time is not None and at_time.status == "indeterminate":
        reason = at_time.key.reason if at_time.key is not None else None
        return (
            f"Signature does not verify against the current key set for {did}, and its key was retired "
            f"after the signer-asserted signed_at or its history is unavailable ({reason}); "
            "re-sign with a current key"
        )
    return f"Signature did not verify against the current key set, or against the key at signed_at, for {did}"


def _signed_at_rfc3339(signed_at: float) -> str:
    moment = datetime.fromtimestamp(signed_at, tz=timezone.utc)
    return moment.isoformat(timespec="milliseconds").replace("+00:00", "Z")


async def _run_signature_verification(ctx: _VerifierContext, message: SignedHandoffMessage) -> _SignatureOutcome:
    try:
        payload_str = build_handoff_envelope(
            did=message.did,
            key_id=message.key_id,
            signed_at=message.signed_at,
            destination=str(message.destination),
            nonce=str(message.nonce),
            payload=message.payload,
        )
    except (TypeError, ValueError, OverflowError):
        # A payload that is not JSON-serializable cannot have been signed: there is no str(obj) fallback.
        return _SignatureOutcome(valid=False, staleness=0.0, gate="payload")
    staleness = max(0.0, ctx.now() - message.signed_at)

    if staleness > ctx.ttl_seconds:
        valid = await _verify_signature_with_purpose(ctx, message, payload_str)
        return _SignatureOutcome(valid=valid, staleness=staleness, gate="key_lifecycle", past_ttl=True)

    if await _verify_signature_with_purpose(ctx, message, payload_str):
        return _SignatureOutcome(valid=True, staleness=staleness)
    if not message.key_id:
        return _SignatureOutcome(valid=False, staleness=staleness)

    # Within the TTL, a key the signer has since rotated away from is checked at signed_at.
    at_time = await _verify_signature_at_signed_at(ctx, message, payload_str)
    if at_time is not None and at_time.status == "valid":
        return _SignatureOutcome(valid=True, staleness=staleness, used_key_at_time=True, key_at_time=at_time)
    gate = "key_lifecycle" if at_time is not None and at_time.status == "indeterminate" else "signature"
    return _SignatureOutcome(valid=False, staleness=staleness, gate=gate, key_at_time=at_time)


async def _verify_signature_with_purpose(
    ctx: _VerifierContext,
    message: SignedHandoffMessage,
    payload_str: str,
) -> bool:
    try:
        valid = await ctx.verify_signature(
            message.did,
            payload_str,
            message.signature,
            message.key_id,
            required_purpose="assertionMethod",
        )
        return bool(valid)
    except IdentityCompositionError:
        return False


async def _verify_signature_at_signed_at(
    ctx: _VerifierContext,
    message: SignedHandoffMessage,
    payload_str: str,
) -> VerifySignatureAtTimeResult | None:
    """Check the signature against the DID's key state at ``signed_at`` (RFC-001 §6.2.2).

    Returns ``None`` when the check cannot run (unreadable ``signed_at`` or a composition
    error); the caller treats that as not accepted.
    """

    try:
        stated_time = _signed_at_rfc3339(message.signed_at)
        result = await ctx.verify_signature_at_time(
            message.did,
            payload_str,
            message.signature,
            message.key_id,
            stated_time=stated_time,
            required_purpose="assertionMethod",
        )
    except (IdentityCompositionError, ValueError, OverflowError, OSError):
        return None
    return result if isinstance(result, VerifySignatureAtTimeResult) else None


def build_handoff_verifier_executor(
    *,
    from_executor: Any,
    to_executor: Any,
    action_class: ActionClass,
    ttl_seconds: int | None,
    allowed_dids: Sequence[str] | None,
    require_signature: bool,
    cross_domain: bool | None,
    on_verification_blocked: VerificationBlockedCallback | None,
    observer: AgentDidObserver,
    client: AgentDidClient | None = None,
    executor_id: str | None = None,
    output_type: Any = object,
    nonce_store: NonceStore | None = None,
) -> FunctionExecutor:
    """Build the ``FunctionExecutor`` that enforces verification at a handoff edge.

    ``allowed_dids`` is required for ``action_class="irreversible"``; for the other classes a warning is logged when
    it is ``None`` because the handoff then accepts any DID that resolves and signs. ``nonce_store`` records the
    ``(did, nonce)`` pairs accepted: the default is an in-memory store of this verifier in this process, so pass a
    shared store when several workflow instances verify the same edge.
    """

    if action_class == "irreversible" and allowed_dids is None and require_signature:
        raise ValueError("allowed_dids is required when action_class is 'irreversible'")
    if allowed_dids is None and require_signature:
        _LOGGER.warning(
            "add_verified_handoff accepts any DID that resolves and signs (allowed_dids is None); "
            "pass allowed_dids to restrict the senders of this edge"
        )

    from_id = _resolve_executor_id(from_executor)
    to_id = _resolve_executor_id(to_executor)
    from_domain = getattr(from_executor, "trust_domain", None)
    to_domain = getattr(to_executor, "trust_domain", None)
    if cross_domain is None:
        cross_domain = bool(from_domain and to_domain and from_domain != to_domain)

    effective_ttl = _resolve_effective_ttl(action_class, ttl_seconds, cross_domain)

    verify_signature: Callable[..., Any] = (
        client.verify_signature if client is not None else AgentIdentity.verify_signature
    )
    verify_signature_at_time: Callable[..., Any] = (
        client.verify_signature_at_time if client is not None else _default_verify_signature_at_time
    )
    ctx = _VerifierContext(
        from_executor_id=from_id,
        to_executor_id=to_id,
        action_class=action_class,
        ttl_seconds=effective_ttl,
        allowed_dids=tuple(allowed_dids) if allowed_dids is not None else None,
        require_signature=require_signature,
        cross_domain=cross_domain,
        on_verification_blocked=on_verification_blocked,
        observer=observer,
        nonce_store=nonce_store if nonce_store is not None else InMemoryNonceStore(),
        verify_signature=verify_signature,
        verify_signature_at_time=verify_signature_at_time,
    )

    verifier_func = build_handoff_verifier_function(ctx)
    resolved_executor_id = executor_id or f"agent_did_verified_handoff__{from_id}__{to_id}"
    # Declare explicit IO types so the workflow validator doesn't skip edge checks
    # for this implicit executor we inserted on the user's behalf. Inputs are
    # SignedHandoffMessage when require_signature=True; outputs are deliberately
    # ``object`` to keep the inner payload type-agnostic (the downstream executor
    # supplies the concrete annotation).
    executor = FunctionExecutor(
        verifier_func,
        id=resolved_executor_id,
        input=SignedHandoffMessage if require_signature else object,
        output=output_type,
    )
    observer.emit(
        "agent_did.workflow.verifier_created",
        attributes={
            "executor_id": resolved_executor_id,
            "from_executor": from_id,
            "to_executor": to_id,
            "action_class": action_class,
            "ttl_seconds": effective_ttl,
            "cross_domain": cross_domain,
            "allowed_did_count": len(ctx.allowed_dids) if ctx.allowed_dids else 0,
            "require_signature": require_signature,
        },
    )
    return executor


__all__ = [
    "ActionClass",
    "HANDOFF_TTL_DEFAULTS",
    "SignedHandoffMessage",
    "VerificationBlockedCallback",
    "VerificationBlockedError",
    "HANDOFF_ENVELOPE_TYPE",
    "HANDOFF_MAX_AGE_SECONDS",
    "HANDOFF_MAX_FUTURE_SKEW_SECONDS",
    "build_handoff_envelope",
    "build_handoff_verifier_executor",
    "build_handoff_verifier_function",
    "sign_handoff",
]
