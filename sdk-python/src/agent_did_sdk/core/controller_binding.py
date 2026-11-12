"""Controller binding of a did:webvh agent (RFC-001 §6.6 item 7).

An agent whose document names a ``controller`` other than itself is bound to it only if the proof of the LAST entry of
its did:webvh log was made by a key that is active now under ``capabilityInvocation`` of the controller's document. The
last entry carries the full current document, so that proof is the controller's endorsement of the current state.
Listing a controller key in ``updateKeys`` is not enough (a public key can be listed without holding its private key,
and ``updateKeys`` can be handed over after the document was written).

TypeScript parity: ``sdk/src/core/controller-binding.ts``.
"""

from __future__ import annotations

from collections.abc import Sequence

from ..crypto.multibase import decode_public_key_multibase
from .types import AgentDIDDocument


class ControllerBindingError(ValueError):
    """The agent is not bound to its controller (see :func:`assert_bound_to_controller`)."""

    def __init__(self, did: str, controller_did: str, detail: str) -> None:
        super().__init__(f"{did} is not bound to its controller {controller_did}: {detail}")
        self.did = did
        self.controller_did = controller_did


def _raw_key_hex(multikey: str) -> str | None:
    try:
        return decode_public_key_multibase(multikey).hex()
    except ValueError:
        return None


def active_capability_invocation_keys(controller: AgentDIDDocument) -> set[str]:
    """Raw public keys (hex) of the controller's keys that are active now under ``capabilityInvocation``."""
    listed = set(controller.capability_invocation or [])
    keys: set[str] = set()
    for method in controller.verification_method:
        if method.id not in listed or method.deactivated or not method.public_key_multibase:
            continue
        raw = _raw_key_hex(method.public_key_multibase)
        if raw is not None:
            keys.add(raw)
    return keys


def assert_bound_to_controller(
    agent: AgentDIDDocument, last_entry_signer_keys: Sequence[str], controller: AgentDIDDocument
) -> None:
    """Raise :class:`ControllerBindingError` unless one of *last_entry_signer_keys* (multikeys of the proofs of the
    agent's last log entry) is an active ``capabilityInvocation`` key of *controller*."""
    active = active_capability_invocation_keys(controller)
    if not active:
        raise ControllerBindingError(
            agent.id, controller.id, "the controller lists no active capabilityInvocation key"
        )
    if not any((raw := _raw_key_hex(multikey)) is not None and raw in active for multikey in last_entry_signer_keys):
        raise ControllerBindingError(
            agent.id,
            controller.id,
            "the last entry of its log was not signed by an active capabilityInvocation key of the controller",
        )
