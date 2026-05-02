"""Tests for ``add_verified_handoff`` (issue #26).

Covers the acceptance criteria locked with @haroldmalikfrimpong-ops:

- Default API + parameter shape.
- Hard gate, fail-closed: missing signature, invalid signature, expired TTL,
  disallowed DID, cross-domain hop, irreversible action with stale verification.
- Key-rotation race: (a) inside TTL with rotation accepted via historical sig
  path, (b) after TTL re-verified against new key, (c) after TTL where re-verify
  fails because previous key was revoked = blocked via
  ``VerificationBlockedError(failing_gates=["key_lifecycle"])``.
- ``on_verification_blocked`` callback semantics: ``None`` halts gracefully,
  returning a value forwards it as the verifier executor's output.
- Observability events: ``agent_did.workflow.handoff_verified`` /
  ``agent_did.workflow.handoff_blocked`` emitted with required attributes.
"""

from __future__ import annotations

import asyncio
import time

import pytest
from agent_did_sdk import (
    AgentIdentity,
    AgentIdentityConfig,
    CreateAgentParams,
    InMemoryAgentRegistry,
)

from agent_did_microsoft_agent_framework import (
    HANDOFF_TTL_DEFAULTS,
    AgentDidWorkflowBuilder,
    SignedHandoffMessage,
    VerificationBlockedError,
    create_agent_did_microsoft_agent_framework_integration,
)
from agent_did_microsoft_agent_framework.handoff import (
    _resolve_effective_ttl,
    _VerifierContext,
    build_handoff_verifier_function,
)
from agent_did_microsoft_agent_framework.observability import AgentDidObserver


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
        AgentIdentityConfig(signer_address="0x1010101010101010101010101010101010101010")
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
    verify_historical_signature=None,
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
        verify_historical_signature=verify_historical_signature or _stub_async(False),
        now=now or time.time,
    )


def _stub_async(return_value):
    async def _stub(*_args, **_kwargs):
        return return_value

    return _stub


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
    msg = SignedHandoffMessage(
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
    msg = SignedHandoffMessage(
        payload="x", did="did:wba:agent", signature="00", signed_at=time.time()
    )
    with pytest.raises(VerificationBlockedError) as exc:
        _run_verifier(verifier, msg)
    assert exc.value.failing_gates == ["signature"]


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
    msg = SignedHandoffMessage(
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
    msg = SignedHandoffMessage(
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
    msg = SignedHandoffMessage(
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
    msg = SignedHandoffMessage(
        payload={"approved": True}, did="did:wba:agent", signature="aa", signed_at=time.time()
    )
    sent, _ = _run_verifier(verifier, msg)
    assert sent == [{"approved": True}]
    verified = [e for e in events if e["event_type"] == "agent_did.workflow.handoff_verified"]
    assert verified and verified[0]["from_did"] == "did:wba:agent"


# --- Key-rotation race (AC tests a/b/c) -------------------------------------------------


def test_key_rotation_race_inside_ttl_accepted_via_historical_path() -> None:
    """AC (a): inside TTL with rotation = accepted via historical sig path."""

    observer, _events = _make_observer()
    verifier = build_handoff_verifier_function(
        _ctx(
            observer=observer,
            ttl_seconds=120,
            # Current key set rejects (rotation already happened) but historical accepts.
            verify_signature=_stub_async(False),
            verify_historical_signature=_stub_async(True),
            now=lambda: 100.0,
        )
    )
    msg = SignedHandoffMessage(
        payload="approve",
        did="did:wba:agent",
        signature="aa",
        signed_at=50.0,
        key_id="did:wba:agent#key-1",
    )
    sent, _ = _run_verifier(verifier, msg)
    assert sent == ["approve"]


def test_key_rotation_race_after_ttl_reverified_against_current_key() -> None:
    """AC (b): after TTL with rotation = re-verified against new key."""

    observer, _events = _make_observer()
    verifier = build_handoff_verifier_function(
        _ctx(
            observer=observer,
            ttl_seconds=10,
            # Current key set accepts (re-signed by upstream after rotation).
            verify_signature=_stub_async(True),
            verify_historical_signature=_stub_async(False),
            now=lambda: 100.0,
        )
    )
    msg = SignedHandoffMessage(
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
            verify_historical_signature=_stub_async(True),  # would succeed but TTL is past
            now=lambda: 100.0,
        )
    )
    msg = SignedHandoffMessage(
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


def test_key_rotation_race_against_real_sdk_inside_ttl(integration) -> None:
    """End-to-end check that the verifier wires the SDK's historical path correctly."""

    identity, runtime_identity, _ = integration
    payload = "real:rotation:inside_ttl"
    old_key_id = f"{runtime_identity.document.id}#key-1"
    old_sig = asyncio.run(identity.sign_message(payload, runtime_identity.agent_private_key))

    asyncio.run(AgentIdentity.rotate_verification_method(runtime_identity.document.id))

    observer, _events = _make_observer()
    verifier = build_handoff_verifier_function(
        _ctx(observer=observer, ttl_seconds=300)  # default reversible TTL
    )
    msg = SignedHandoffMessage(
        payload=payload,
        did=runtime_identity.document.id,
        signature=old_sig,
        signed_at=time.time(),  # fresh
        key_id=old_key_id,
    )
    sent, _ = _run_verifier(verifier, msg)
    assert sent == [payload]  # accepted via historical path


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
    msg = SignedHandoffMessage(
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
    msg = SignedHandoffMessage(
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
