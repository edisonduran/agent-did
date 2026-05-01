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
- Key-rotation race: signatures issued under a previous key remain accepted while
  inside the action-class TTL window via the SDK's historical signature path.
  Once the TTL elapses, the next handoff MUST re-verify against the agent's
  current key set.

This module deliberately delegates ALL key-lifecycle logic to the central SDK
primitives (``AgentIdentity.verify_signature`` and
``AgentIdentity.verify_historical_signature``). It must not re-implement the
key rotation state machine — when the spec converges with `aeoess/agent-passport-system`
the SDK is the single source of truth and this helper inherits any change for free.
"""

from __future__ import annotations

import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from typing import Any, Literal

from agent_did_sdk import AgentIdentity
from agent_framework import FunctionExecutor, WorkflowContext

from .observability import AgentDidObserver

ActionClass = Literal["irreversible", "compensable", "reversible"]

HANDOFF_TTL_DEFAULTS: dict[ActionClass, int] = {
    "irreversible": 30,
    "compensable": 120,
    "reversible": 300,
}

VerificationBlockedCallback = Callable[["VerificationBlockedError"], Any]


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
    verify_historical_signature: Callable[..., Any] = field(
        default=AgentIdentity.verify_historical_signature
    )
    now: Callable[[], float] = field(default=time.time)


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

        valid, used_historical, staleness, gate = await _run_signature_verification(ctx, message)
        if not valid:
            error = _build_block_error(
                failing_gates=[gate],
                checked_did=message.did,
                action_class=ctx.action_class,
                enforcement_note=_block_note_for_gate(gate, ctx.ttl_seconds, message.did),
            )
            await _emit_block_outcome(ctx, wf_ctx, error)
            return

        _emit_verified(
            ctx.observer, ctx,
            from_did=message.did, used_historical=used_historical, staleness_seconds=staleness,
        )
        await wf_ctx.send_message(message.payload)

    return _verifier


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


def _block_note_for_gate(gate: str, ttl_seconds: int, did: str) -> str:
    if gate == "key_lifecycle":
        return (
            f"Signature past action-class TTL ({ttl_seconds}s) and the previous key "
            "no longer verifies against the current key set"
        )
    return f"Signature did not verify against the current or historical key set for {did}"


async def _run_signature_verification(
    ctx: _VerifierContext, message: SignedHandoffMessage
) -> tuple[bool, bool, float, str]:
    """Return ``(valid, used_historical, staleness_seconds, failing_gate)``.

    ``failing_gate`` is meaningful only when ``valid`` is ``False``.
    """

    payload_str = message.payload if isinstance(message.payload, str) else str(message.payload)
    staleness = max(0.0, ctx.now() - message.signed_at)

    if staleness > ctx.ttl_seconds:
        valid = await ctx.verify_signature(
            message.did, payload_str, message.signature, message.key_id
        )
        return bool(valid), False, staleness, "key_lifecycle"

    valid = await ctx.verify_signature(
        message.did, payload_str, message.signature, message.key_id
    )
    used_historical = False
    if not valid and message.key_id:
        valid = await ctx.verify_historical_signature(
            message.did, payload_str, message.signature, message.key_id
        )
        used_historical = bool(valid)
    return bool(valid), used_historical, staleness, "signature"


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
    executor_id: str | None = None,
    output_type: Any = object,
) -> FunctionExecutor:
    """Build the ``FunctionExecutor`` that enforces verification at a handoff edge."""

    from_id = _resolve_executor_id(from_executor)
    to_id = _resolve_executor_id(to_executor)
    from_domain = getattr(from_executor, "trust_domain", None)
    to_domain = getattr(to_executor, "trust_domain", None)
    if cross_domain is None:
        cross_domain = bool(from_domain and to_domain and from_domain != to_domain)

    effective_ttl = _resolve_effective_ttl(action_class, ttl_seconds, cross_domain)

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
    "build_handoff_verifier_executor",
    "build_handoff_verifier_function",
]
