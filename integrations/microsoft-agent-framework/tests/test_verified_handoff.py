"""Tests for ``add_verified_handoff`` (issue #26).

Covers the acceptance criteria locked with @haroldmalikfrimpong-ops:

- Default API + parameter shape.
- Hard gate, fail-closed: missing signature, invalid signature, expired TTL,
  disallowed DID, cross-domain hop, irreversible action with stale verification.
- Key-rotation race: (a) inside TTL, a key valid at ``signed_at`` is accepted
  via ``verify_signature_at_time``, and a key retired after ``signed_at``
  (``indeterminate``) is blocked with ``key_lifecycle``, (b) after TTL
  re-verified against new key, (c) after TTL where re-verify fails because
  previous key was revoked = blocked via
  ``VerificationBlockedError(failing_gates=["key_lifecycle"])``.
- ``on_verification_blocked`` callback semantics: ``None`` halts gracefully,
  returning a value forwards it as the verifier executor's output.
- Observability events: ``agent_did.workflow.handoff_verified`` /
  ``agent_did.workflow.handoff_blocked`` emitted with required attributes.
"""

from __future__ import annotations

import asyncio
import json
import secrets
import time
from datetime import datetime

import pytest
from agent_did_sdk import (
    AgentIdentity,
    AgentIdentityConfig,
    CreateAgentParams,
    InMemoryAgentRegistry,
    KeyAtTimeResult,
    LocalKeySigner,
    VerifySignatureAtTimeResult,
)

from agent_did_microsoft_agent_framework import (
    HANDOFF_TTL_DEFAULTS,
    AgentDidWorkflowBuilder,
    SignedHandoffMessage,
    VerificationBlockedError,
    create_agent_did_microsoft_agent_framework_integration,
    sign_handoff,
)
from agent_did_microsoft_agent_framework.handoff import (
    _resolve_effective_ttl,
    _VerifierContext,
    build_handoff_envelope,
    build_handoff_verifier_executor,
    build_handoff_verifier_function,
)
from agent_did_microsoft_agent_framework.observability import AgentDidObserver


def _signed(**kwargs):
    """A signed handoff message with the envelope fields a verifier requires (the signature itself is stubbed)."""
    kwargs.setdefault("nonce", secrets.token_hex(8))
    kwargs.setdefault("destination", "downstream")
    return SignedHandoffMessage(**kwargs)


class _FakeWorkflowContext:
    """Minimal stand-in for ``agent_framework.WorkflowContext`` used in unit tests."""

    def __init__(self) -> None:
        self.sent: list[object] = []

    async def send_message(self, value: object) -> None:
        self.sent.append(value)


def _run_verifier(verifier, message):
    """Drive the verifier with a fake context and return ``(sent, fake_ctx)``."""
    fake = _FakeWorkflowContext()
    asyncio.run(verifier(message, fake))
    return fake.sent, fake


@pytest.fixture
def integration():
    AgentIdentity.set_registry(InMemoryAgentRegistry())
    identity = AgentIdentity(
        AgentIdentityConfig(controller_signer=LocalKeySigner.generate()[0])
    )
    runtime_identity = asyncio.run(
        identity.create(
            CreateAgentParams(
                name="HandoffTestBot",
                core_model="gpt-4.1-mini",
                system_prompt="Verified handoff under test.",
            )
        )
    )
    return (
        identity,
        runtime_identity,
        create_agent_did_microsoft_agent_framework_integration(
            agent_identity=identity, runtime_identity=runtime_identity
        ),
    )


def _make_observer() -> tuple[AgentDidObserver, list[dict]]:
    events: list[dict] = []

    def handler(event):
        events.append({"event_type": event.event_type, **event.attributes})

    return AgentDidObserver(event_handler=handler), events


def _ctx(
    *,
    observer,
    action_class="reversible",
    ttl_seconds=300,
    allowed_dids=None,
    require_signature=True,
    cross_domain=False,
    on_verification_blocked=None,
    verify_signature=None,
    verify_signature_at_time=None,
    now=None,
):
    return _VerifierContext(
        from_executor_id="upstream",
        to_executor_id="downstream",
        action_class=action_class,
        ttl_seconds=ttl_seconds,
        allowed_dids=tuple(allowed_dids) if allowed_dids is not None else None,
        require_signature=require_signature,
        cross_domain=cross_domain,
        on_verification_blocked=on_verification_blocked,
        observer=observer,
        verify_signature=verify_signature or _stub_async(True),
        verify_signature_at_time=verify_signature_at_time or _stub_async(_at_time("invalid")),
        now=now or time.time,
    )


def _stub_async(return_value):
    async def _stub(*_args, **_kwargs):
        return return_value

    return _stub


def _at_time(status, key_reason=None):
    key_status = {"valid": "authorized", "invalid": "not_authorized", "indeterminate": "indeterminate"}[status]
    return VerifySignatureAtTimeResult(
        status=status,
        reason="key_not_authorized" if status == "invalid" else None,
        key=KeyAtTimeResult(status=key_status, key_id="did:wba:agent#key-1", reason=key_reason),
    )


# --- Defaults & parameter shape ---------------------------------------------------------


def test_defaults_match_locked_design() -> None:
    assert HANDOFF_TTL_DEFAULTS == {"irreversible": 30, "compensable": 120, "reversible": 300}


def test_resolve_effective_ttl_irreversible_cannot_be_widened() -> None:
    assert _resolve_effective_ttl("irreversible", ttl_seconds=9999, cross_domain=False) == 30


def test_resolve_effective_ttl_cross_domain_collapses_to_zero() -> None:
    assert _resolve_effective_ttl("reversible", ttl_seconds=600, cross_domain=True) == 0


def test_create_workflow_builder_returns_subclass(integration) -> None:
    _, _, integ = integration

    def _identity(message: object) -> object:
        return message

    start = integ.create_function_executor(_identity, executor_id="start")
    builder = integ.create_workflow_builder(start)
    assert isinstance(builder, AgentDidWorkflowBuilder)
    assert hasattr(builder, "add_verified_handoff")


# --- Hard gate, fail-closed -------------------------------------------------------------


def test_unsigned_message_blocked_when_signature_required() -> None:
    observer, events = _make_observer()
    verifier = build_handoff_verifier_function(_ctx(observer=observer))
    with pytest.raises(VerificationBlockedError) as exc:
        _run_verifier(verifier, "plain string")
    assert exc.value.failing_gates == ["signature"]
    assert any(event["event_type"] == "agent_did.workflow.handoff_blocked" for event in events)


def test_unsigned_message_passthrough_when_signature_not_required() -> None:
    observer, _events = _make_observer()
    verifier = build_handoff_verifier_function(_ctx(observer=observer, require_signature=False))
    sent, _ = _run_verifier(verifier, "plain string")
    assert sent == ["plain string"]


def test_disallowed_did_blocked() -> None:
    observer, _events = _make_observer()
    verifier = build_handoff_verifier_function(
        _ctx(observer=observer, allowed_dids=["did:wba:allowed"])
    )
    msg = _signed(
        payload="x", did="did:wba:other", signature="00", signed_at=time.time()
    )
    with pytest.raises(VerificationBlockedError) as exc:
        _run_verifier(verifier, msg)
    assert exc.value.failing_gates == ["did_allowlist"]


def test_invalid_signature_blocked() -> None:
    observer, _events = _make_observer()
    verifier = build_handoff_verifier_function(
        _ctx(observer=observer, verify_signature=_stub_async(False))
    )
    msg = _signed(
        payload="x", did="did:wba:agent", signature="00", signed_at=time.time()
    )
    with pytest.raises(VerificationBlockedError) as exc:
        _run_verifier(verifier, msg)
    assert exc.value.failing_gates == ["signature"]


def test_signature_verification_requests_assertion_method_purpose() -> None:
    observer, _events = _make_observer()
    calls: list[tuple[str, dict]] = []

    async def verify_signature(*_args, **kwargs):
        calls.append(("current", kwargs))
        return False

    async def verify_signature_at_time(*_args, **kwargs):
        calls.append(("at_time", kwargs))
        return _at_time("invalid")

    verifier = build_handoff_verifier_function(
        _ctx(
            observer=observer,
            verify_signature=verify_signature,
            verify_signature_at_time=verify_signature_at_time,
            now=lambda: 1767398400.5,
        )
    )
    msg = _signed(
        payload="x",
        did="did:wba:agent",
        signature="00",
        signed_at=1767398400.123,
        key_id="did:wba:agent#key-1",
    )

    with pytest.raises(VerificationBlockedError):
        _run_verifier(verifier, msg)

    assert calls == [
        ("current", {"required_purpose": "assertionMethod"}),
        ("at_time", {"stated_time": "2026-01-03T00:00:00.123Z", "required_purpose": "assertionMethod"}),
    ]


def test_expired_ttl_with_failing_reverify_blocked_as_key_lifecycle() -> None:
    observer, _events = _make_observer()
    verifier = build_handoff_verifier_function(
        _ctx(
            observer=observer,
            ttl_seconds=10,
            verify_signature=_stub_async(False),
            now=lambda: 100.0,
        )
    )
    msg = _signed(
        payload="x", did="did:wba:agent", signature="00", signed_at=50.0
    )
    with pytest.raises(VerificationBlockedError) as exc:
        _run_verifier(verifier, msg)
    assert exc.value.failing_gates == ["key_lifecycle"]


def test_irreversible_action_with_stale_signature_forces_reverify() -> None:
    observer, _events = _make_observer()
    verifier = build_handoff_verifier_function(
        _ctx(
            observer=observer,
            action_class="irreversible",
            ttl_seconds=_resolve_effective_ttl("irreversible", ttl_seconds=3600, cross_domain=False),
            verify_signature=_stub_async(False),
            now=lambda: 1000.0,
        )
    )
    msg = _signed(
        payload="x", did="did:wba:agent", signature="00", signed_at=900.0
    )  # 100s old > 30s TTL
    with pytest.raises(VerificationBlockedError) as exc:
        _run_verifier(verifier, msg)
    assert exc.value.failing_gates == ["key_lifecycle"]


def test_cross_domain_hop_collapses_ttl_to_zero() -> None:
    observer, _events = _make_observer()
    verifier = build_handoff_verifier_function(
        _ctx(
            observer=observer,
            cross_domain=True,
            ttl_seconds=0,
            verify_signature=_stub_async(False),
            now=lambda: 100.0,
        )
    )
    msg = _signed(
        payload="x", did="did:wba:agent", signature="00", signed_at=99.5
    )
    with pytest.raises(VerificationBlockedError) as exc:
        _run_verifier(verifier, msg)
    assert exc.value.failing_gates == ["key_lifecycle"]


# --- Success path -----------------------------------------------------------------------


def test_valid_signature_inside_ttl_forwards_inner_payload() -> None:
    observer, events = _make_observer()
    verifier = build_handoff_verifier_function(
        _ctx(observer=observer, verify_signature=_stub_async(True))
    )
    msg = _signed(
        payload={"approved": True}, did="did:wba:agent", signature="aa", signed_at=time.time()
    )
    sent, _ = _run_verifier(verifier, msg)
    assert sent == [{"approved": True}]
    verified = [e for e in events if e["event_type"] == "agent_did.workflow.handoff_verified"]
    assert verified and verified[0]["from_did"] == "did:wba:agent"


# --- Key-rotation race (AC tests a/b/c) -------------------------------------------------


def test_key_rotation_race_inside_ttl_accepted_when_key_valid_at_signed_at() -> None:
    """AC (a): inside TTL, the current key set rejects but the key checks valid at signed_at."""

    observer, events = _make_observer()
    verifier = build_handoff_verifier_function(
        _ctx(
            observer=observer,
            ttl_seconds=120,
            verify_signature=_stub_async(False),
            verify_signature_at_time=_stub_async(_at_time("valid")),
            now=lambda: 100.0,
        )
    )
    msg = _signed(
        payload="approve",
        did="did:wba:agent",
        signature="aa",
        signed_at=50.0,
        key_id="did:wba:agent#key-1",
    )
    sent, _ = _run_verifier(verifier, msg)
    assert sent == ["approve"]
    verified = next(e for e in events if e["event_type"] == "agent_did.workflow.handoff_verified")
    assert verified["used_historical_signature"] is True


def test_key_rotation_race_inside_ttl_key_retired_after_signed_at_is_blocked() -> None:
    """AC (a'): signed_at is signer-asserted, so a key retired after it is indeterminate = blocked."""

    observer, _events = _make_observer()
    verifier = build_handoff_verifier_function(
        _ctx(
            observer=observer,
            ttl_seconds=120,
            verify_signature=_stub_async(False),
            verify_signature_at_time=_stub_async(_at_time("indeterminate", "key_retired_after_stated_time")),
            now=lambda: 100.0,
        )
    )
    msg = _signed(
        payload="approve",
        did="did:wba:agent",
        signature="aa",
        signed_at=50.0,
        key_id="did:wba:agent#key-1",
    )
    with pytest.raises(VerificationBlockedError) as exc:
        _run_verifier(verifier, msg)
    assert exc.value.failing_gates == ["key_lifecycle"]
    assert "key_retired_after_stated_time" in exc.value.enforcement_note


def test_key_rotation_race_inside_ttl_unreadable_signed_at_is_blocked() -> None:
    observer, _events = _make_observer()
    verifier = build_handoff_verifier_function(
        _ctx(
            observer=observer,
            verify_signature=_stub_async(False),
            verify_signature_at_time=_stub_async(_at_time("valid")),
            now=lambda: float("nan"),
        )
    )
    msg = _signed(
        payload="approve",
        did="did:wba:agent",
        signature="aa",
        signed_at=float("nan"),
        key_id="did:wba:agent#key-1",
    )
    with pytest.raises(VerificationBlockedError) as exc:
        _run_verifier(verifier, msg)
    assert exc.value.failing_gates == ["signed_at"]


def test_key_rotation_race_after_ttl_reverified_against_current_key() -> None:
    """AC (b): after TTL with rotation = re-verified against new key."""

    observer, _events = _make_observer()
    verifier = build_handoff_verifier_function(
        _ctx(
            observer=observer,
            ttl_seconds=10,
            # Current key set accepts (re-signed by upstream after rotation).
            verify_signature=_stub_async(True),
            verify_signature_at_time=_stub_async(_at_time("invalid")),
            now=lambda: 100.0,
        )
    )
    msg = _signed(
        payload="approve",
        did="did:wba:agent",
        signature="aa",
        signed_at=50.0,
        key_id="did:wba:agent#key-2",
    )
    sent, _ = _run_verifier(verifier, msg)
    assert sent == ["approve"]


def test_key_rotation_race_after_ttl_revoked_key_blocked_with_key_lifecycle_gate() -> None:
    """AC (c): after TTL where re-verify fails because previous key was revoked."""

    observer, _events = _make_observer()
    verifier = build_handoff_verifier_function(
        _ctx(
            observer=observer,
            ttl_seconds=10,
            verify_signature=_stub_async(False),
            verify_signature_at_time=_stub_async(_at_time("valid")),  # would succeed but TTL is past
            now=lambda: 100.0,
        )
    )
    msg = _signed(
        payload="approve",
        did="did:wba:agent",
        signature="aa",
        signed_at=50.0,
        key_id="did:wba:agent#key-1",
    )
    with pytest.raises(VerificationBlockedError) as exc:
        _run_verifier(verifier, msg)
    assert exc.value.failing_gates == ["key_lifecycle"]


# --- Real SDK key-rotation race (integration check, no mocks) ---------------------------


def _version_epochs(did: str) -> list[float]:
    log = AgentIdentity.get_default_client().export_did_webvh_history(did)
    return [
        datetime.fromisoformat(json.loads(line)["versionTime"].replace("Z", "+00:00")).timestamp()
        for line in log.splitlines()
        if line.strip()
    ]


def _real_sdk_ctx(observer, now):
    return _VerifierContext(
        from_executor_id="upstream",
        to_executor_id="downstream",
        action_class="reversible",
        ttl_seconds=300,
        allowed_dids=None,
        require_signature=True,
        cross_domain=False,
        on_verification_blocked=None,
        observer=observer,
        now=now,
    )  # SDK verifiers left at their defaults


def test_key_rotation_race_against_real_sdk_inside_ttl(integration) -> None:
    """End-to-end: a signature by a key retired after signed_at is blocked, not accepted."""

    identity, runtime_identity, _ = integration
    did = runtime_identity.document.id
    payload = "real:rotation:inside_ttl"

    asyncio.run(AgentIdentity.rotate_verification_method(did))
    created_at, rotated_at = _version_epochs(did)
    assert created_at < rotated_at

    observer, _events = _make_observer()
    verifier = build_handoff_verifier_function(_real_sdk_ctx(observer, now=lambda: rotated_at + 1))
    # key-1 was authorized at created_at; the rotation retires it later. The runtime identity still names key-1.
    msg = asyncio.run(
        sign_handoff(
            agent_identity=identity,
            runtime_identity=runtime_identity,
            payload=payload,
            destination="downstream",
            signed_at=created_at,
        )
    )
    with pytest.raises(VerificationBlockedError) as exc:
        _run_verifier(verifier, msg)
    assert exc.value.failing_gates == ["key_lifecycle"]
    assert "key_retired_after_stated_time" in exc.value.enforcement_note


def test_real_sdk_inside_ttl_accepts_the_current_key(integration) -> None:
    identity, runtime_identity, _ = integration
    payload = "real:no_rotation"

    observer, events = _make_observer()
    verifier = build_handoff_verifier_function(_real_sdk_ctx(observer, now=time.time))
    msg = asyncio.run(
        sign_handoff(
            agent_identity=identity, runtime_identity=runtime_identity, payload=payload, destination="downstream"
        )
    )
    sent, _ = _run_verifier(verifier, msg)
    assert sent == [payload]
    verified = next(e for e in events if e["event_type"] == "agent_did.workflow.handoff_verified")
    assert verified["used_historical_signature"] is False


# --- Callback semantics -----------------------------------------------------------------


def test_callback_returning_none_halts_gracefully() -> None:
    observer, _events = _make_observer()
    captured: list[VerificationBlockedError] = []

    def on_blocked(error):
        captured.append(error)
        return None

    verifier = build_handoff_verifier_function(
        _ctx(observer=observer, on_verification_blocked=on_blocked)
    )
    sent, _ = _run_verifier(verifier, "unsigned")
    assert sent == []  # halt: nothing forwarded
    assert captured and captured[0].failing_gates == ["signature"]


def test_callback_returning_value_forwards_it_as_verifier_output() -> None:
    observer, _events = _make_observer()

    def on_blocked(_error):
        return {"routed_to": "human_review"}

    verifier = build_handoff_verifier_function(
        _ctx(observer=observer, on_verification_blocked=on_blocked)
    )
    sent, _ = _run_verifier(verifier, "unsigned")
    assert sent == [{"routed_to": "human_review"}]


# --- Observability ----------------------------------------------------------------------


def test_handoff_verified_event_includes_required_attributes() -> None:
    observer, events = _make_observer()
    verifier = build_handoff_verifier_function(
        _ctx(observer=observer, verify_signature=_stub_async(True))
    )
    msg = _signed(
        payload="x", did="did:wba:agent", signature="aa", signed_at=time.time()
    )
    _run_verifier(verifier, msg)
    verified = next(e for e in events if e["event_type"] == "agent_did.workflow.handoff_verified")
    for required in ("from_executor", "to_executor", "from_did", "action_class", "ttl_seconds", "decision_reason"):
        assert required in verified


def test_handoff_blocked_event_includes_required_attributes() -> None:
    observer, events = _make_observer()
    verifier = build_handoff_verifier_function(
        _ctx(observer=observer, verify_signature=_stub_async(False))
    )
    msg = _signed(
        payload="x", did="did:wba:agent", signature="00", signed_at=time.time()
    )
    with pytest.raises(VerificationBlockedError):
        _run_verifier(verifier, msg)
    blocked = next(e for e in events if e["event_type"] == "agent_did.workflow.handoff_blocked")
    required_attrs = (
        "from_executor",
        "to_executor",
        "from_did",
        "action_class",
        "ttl_seconds",
        "failing_gates",
        "decision_reason",
    )
    for required in required_attrs:
        assert required in blocked


# --- Builder integration ----------------------------------------------------------------


def test_add_verified_handoff_wires_two_edges_into_builder(integration) -> None:
    _, _, integ = integration

    def _identity(message: object) -> object:
        return message

    start = integ.create_function_executor(_identity, executor_id="start")
    middle = integ.create_function_executor(_identity, executor_id="middle")
    builder = integ.create_workflow_builder(start)
    returned = builder.add_verified_handoff(
        from_executor=start,
        to_executor=middle,
        action_class="compensable",
        allowed_dids=["did:wba:trusted"],
    )
    assert returned is builder  # fluent


# --- Signed envelope (payload, signer, destination, nonce, signed_at) ----------------------


def _real_ctx(observer, **overrides):
    ctx = _real_sdk_ctx(observer, now=overrides.pop("now", time.time))
    for name, value in overrides.items():
        setattr(ctx, name, value)
    return ctx


def _sign(integration, payload="approve", **kwargs):
    identity, runtime_identity, _ = integration
    kwargs.setdefault("destination", "downstream")
    return asyncio.run(
        sign_handoff(agent_identity=identity, runtime_identity=runtime_identity, payload=payload, **kwargs)
    )


def test_a_structured_payload_is_signed_canonically_and_verifies(integration) -> None:
    observer, _events = _make_observer()
    payload = {"b": [1, 2, {"z": True}], "a": "x"}
    msg = _sign(integration, payload)
    sent, _ = _run_verifier(build_handoff_verifier_function(_real_ctx(observer)), msg)
    assert sent == [payload]


def test_a_changed_payload_is_blocked(integration) -> None:
    observer, _events = _make_observer()
    msg = _sign(integration, {"amount": 1})
    msg.payload = {"amount": 1000}
    with pytest.raises(VerificationBlockedError) as exc:
        _run_verifier(build_handoff_verifier_function(_real_ctx(observer)), msg)
    assert exc.value.failing_gates == ["signature"]


def test_a_payload_that_is_not_json_serializable_is_blocked_not_stringified(integration) -> None:
    observer, _events = _make_observer()

    class Opaque:
        def __str__(self) -> str:
            return "approve"

    msg = _sign(integration, "approve")
    msg.payload = Opaque()
    with pytest.raises(VerificationBlockedError) as exc:
        _run_verifier(build_handoff_verifier_function(_real_ctx(observer)), msg)
    assert exc.value.failing_gates == ["payload"]


def test_signing_a_payload_that_is_not_json_serializable_raises(integration) -> None:
    with pytest.raises((TypeError, ValueError)):
        _sign(integration, object())


def test_a_handoff_signed_for_another_edge_is_blocked(integration) -> None:
    observer, _events = _make_observer()
    msg = _sign(integration, "approve", destination="some-other-executor")
    with pytest.raises(VerificationBlockedError) as exc:
        _run_verifier(build_handoff_verifier_function(_real_ctx(observer)), msg)
    assert exc.value.failing_gates == ["destination"]


def test_changing_the_destination_field_breaks_the_signature(integration) -> None:
    observer, _events = _make_observer()
    msg = _sign(integration, "approve", destination="some-other-executor")
    msg.destination = "downstream"  # the verifier's edge, but the signature covers the other one
    with pytest.raises(VerificationBlockedError) as exc:
        _run_verifier(build_handoff_verifier_function(_real_ctx(observer)), msg)
    assert exc.value.failing_gates == ["signature"]


def test_a_captured_handoff_cannot_be_replayed(integration) -> None:
    observer, _events = _make_observer()
    msg = _sign(integration, "pay:invoice-7")
    verifier = build_handoff_verifier_function(_real_ctx(observer))
    sent, _ = _run_verifier(verifier, msg)
    assert sent == ["pay:invoice-7"]
    with pytest.raises(VerificationBlockedError) as exc:
        _run_verifier(verifier, msg)
    assert exc.value.failing_gates == ["replay"]


def test_a_message_without_a_nonce_is_blocked(integration) -> None:
    observer, _events = _make_observer()
    msg = _sign(integration, "approve")
    msg.nonce = None
    with pytest.raises(VerificationBlockedError) as exc:
        _run_verifier(build_handoff_verifier_function(_real_ctx(observer)), msg)
    assert exc.value.failing_gates == ["nonce"]


def test_a_signed_at_in_the_future_is_blocked_so_the_ttl_cannot_be_stretched(integration) -> None:
    observer, _events = _make_observer()
    msg = _sign(integration, "approve", signed_at=time.time() + 10_000)
    with pytest.raises(VerificationBlockedError) as exc:
        _run_verifier(build_handoff_verifier_function(_real_ctx(observer)), msg)
    assert exc.value.failing_gates == ["signed_at"]


def test_changing_signed_at_breaks_the_signature(integration) -> None:
    observer, _events = _make_observer()
    msg = _sign(integration, "approve", signed_at=time.time() - 1000)
    msg.signed_at = time.time()  # claims to be fresh to dodge the TTL
    with pytest.raises(VerificationBlockedError) as exc:
        _run_verifier(build_handoff_verifier_function(_real_ctx(observer)), msg)
    assert exc.value.failing_gates == ["signature"]


def test_a_very_old_handoff_is_refused_even_with_a_valid_signature(integration) -> None:
    observer, _events = _make_observer()
    msg = _sign(integration, "approve", signed_at=time.time() - 10_000)
    with pytest.raises(VerificationBlockedError) as exc:
        _run_verifier(build_handoff_verifier_function(_real_ctx(observer)), msg)
    assert exc.value.failing_gates == ["signed_at"]


def test_irreversible_handoffs_require_allowed_dids() -> None:
    observer, _events = _make_observer()
    with pytest.raises(ValueError, match="allowed_dids is required"):
        build_handoff_verifier_executor(
            from_executor="a",
            to_executor="b",
            action_class="irreversible",
            ttl_seconds=None,
            allowed_dids=None,
            require_signature=True,
            cross_domain=None,
            on_verification_blocked=None,
            observer=observer,
        )


def test_a_reversible_handoff_without_allowed_dids_logs_a_warning(caplog) -> None:
    observer, _events = _make_observer()
    with caplog.at_level("WARNING"):
        build_handoff_verifier_executor(
            from_executor="a",
            to_executor="b",
            action_class="reversible",
            ttl_seconds=None,
            allowed_dids=None,
            require_signature=True,
            cross_domain=None,
            on_verification_blocked=None,
            observer=observer,
        )
    assert "accepts any DID" in caplog.text


def test_the_envelope_is_canonical_json_with_the_documented_members() -> None:
    envelope = build_handoff_envelope(
        did="did:example:a",
        key_id="did:example:a#key-1",
        signed_at=1.5,
        destination="d",
        nonce="n",
        payload={"b": 1, "a": 2},
    )
    assert envelope == (
        '{"destination":"d","did":"did:example:a","keyId":"did:example:a#key-1","nonce":"n",'
        '"payload":{"a":2,"b":1},"signedAtMs":1500,"type":"agent-did/handoff/v1"}'
    )
