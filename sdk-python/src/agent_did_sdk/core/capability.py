"""Agent-DID capabilities (RFC-001 §6.7, ADR-008 D-12a/b).

Delegations of authority shaped as Authorization Capabilities (ZCAP v0.4 data model) and secured with one
``eddsa-jcs-2022`` Data Integrity proof with ``proofPurpose: capabilityDelegation``. Aligned with the ZCAP data model;
no conformance with it is claimed.

This module holds the checks that need no resolution: form, chain structure, root, attenuation and validity period.
Key checks and proof verification are in ``AgentDidClient.verify_capability_chain``.

TypeScript parity: ``sdk/src/core/capability.ts``.
"""

from __future__ import annotations

import base64
import copy
import json
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any
from urllib.parse import quote, unquote

from ..crypto.data_integrity import (
    DATA_INTEGRITY_PROOF_TYPE,
    EDDSA_JCS_2022_CRYPTOSUITE,
    decode_eddsa_proof_value,
)
from ..crypto.hash import canonicalize_json
from ..verification.key_at_time import parse_rfc3339_millis
from .agent_card import did_of_key_id
from .http_signatures import HttpSignatureError, _parse_dictionary, request_url_form_problem
from .types import CapabilityRejection

ZCAP_CONTEXT = "https://w3id.org/zcap/v1"
"""The only ``@context`` of a delegated capability."""

ZCAP_ROOT_PREFIX = "urn:zcap:root:"
"""Prefix of a root capability ``id``; the rest is the percent-encoded ``invocationTarget``."""

CAPABILITY_DELEGATION_PURPOSE = "capabilityDelegation"
"""``proofPurpose`` of a delegation proof."""

DEFAULT_MAX_CAPABILITY_CHAIN_LENGTH = 5
"""Delegated capabilities after the root a verifier accepts by default."""

MAX_CAPABILITY_CHAIN_LENGTH = 10
"""Upper bound on ``max_chain_length``."""

AGENT_DID_CAPABILITY_HTTP_HEADER = "Agent-DID-Capability"
"""Header field that carries an invoked capability, a Structured Field Dictionary keyed by signature label."""

MAX_CAPABILITY_HEADER_BYTES = 8192
"""Upper bound, in bytes, on an ``Agent-DID-Capability`` field value a verifier parses."""

_CAPABILITY_MEMBERS = frozenset(
    ("@context", "id", "parentCapability", "invocationTarget", "controller", "allowedAction", "expires", "proof")
)
_PROOF_MEMBERS = frozenset(
    (
        "@context",
        "type",
        "cryptosuite",
        "created",
        "verificationMethod",
        "proofPurpose",
        "capabilityChain",
        "proofValue",
    )
)
_UUID_URN = re.compile(r"urn:uuid:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
_DID_PATTERN = re.compile(r"did:[a-z0-9]+:[A-Za-z0-9._%:-]+")
# ECMAScript encodeURIComponent leaves these unescaped
_URI_COMPONENT_SAFE = "-_.!~*'()"


def _encode_component(value: str) -> str:
    return quote(value, safe=_URI_COMPONENT_SAFE)


def root_capability_id(invocation_target: str) -> str:
    """The ``id`` of the root capability of *invocation_target*: ``urn:zcap:root:`` + its percent-encoded form."""
    return f"{ZCAP_ROOT_PREFIX}{_encode_component(invocation_target)}"


def invocation_target_problem(target: object) -> str | None:
    """``None`` when *target* is a valid ``invocationTarget``: an ``https`` URL in the normalized form of RFC-001
    §6.5 item 4, with no query."""
    if not isinstance(target, str) or not target.startswith("https://"):
        return "invocationTarget must be an https URL"
    if "?" in target:
        return "invocationTarget must not have a query"
    problem = request_url_form_problem(target)
    return None if problem is None else f"invocationTarget is not in normalized form: {problem}"


def target_within(target: str, parent_target: str) -> bool:
    """True when *target* is *parent_target* or extends its path after a ``/`` (``https://a.example/files`` covers
    ``https://a.example/files/reports``, not ``https://a.example/filesystem``)."""
    if target == parent_target:
        return True
    prefix = parent_target if parent_target.endswith("/") else f"{parent_target}/"
    return target.startswith(prefix) and len(target) > len(prefix)


def action_allowed(action: str, allowed: Sequence[str] | None) -> bool:
    """True when *action* is allowed by a capability whose ``allowedAction`` is *allowed* (``None`` = every action)."""
    return allowed is None or action in allowed


def _is_string_list(value: object) -> bool:
    return (
        isinstance(value, list)
        and len(value) > 0
        and all(isinstance(item, str) and len(item) > 0 for item in value)
    )


def _is_json_object(value: object) -> bool:
    return isinstance(value, dict)


def capability_form_problem(capability: object) -> CapabilityRejection | None:
    """The form checks of one delegated capability, without its chain (``None`` when it has the form)."""
    if not isinstance(capability, dict):
        return "malformed_capability"
    if any(member not in _CAPABILITY_MEMBERS for member in capability):
        return "malformed_capability"
    if canonicalize_json(capability.get("@context")) != canonicalize_json([ZCAP_CONTEXT]):
        return "malformed_capability"
    cap_id = capability.get("id")
    if not isinstance(cap_id, str) or not _UUID_URN.fullmatch(cap_id):
        return "malformed_capability"
    parent = capability.get("parentCapability")
    if not isinstance(parent, str) or not parent:
        return "malformed_capability"
    if invocation_target_problem(capability.get("invocationTarget")) is not None:
        return "malformed_capability"
    controller = capability.get("controller")
    if not isinstance(controller, str) or not _DID_PATTERN.fullmatch(controller):
        return "malformed_capability"
    if "allowedAction" in capability:
        actions = capability["allowedAction"]
        if not _is_string_list(actions) or len(set(actions)) != len(actions):
            return "malformed_capability"
    if parse_rfc3339_millis(capability.get("expires")) is None:
        return "malformed_capability"

    proof = capability.get("proof")
    if not isinstance(proof, dict) or any(member not in _PROOF_MEMBERS for member in proof):
        return "unsupported_proof"
    chain = proof.get("capabilityChain")
    if (
        proof.get("type") != DATA_INTEGRITY_PROOF_TYPE
        or proof.get("cryptosuite") != EDDSA_JCS_2022_CRYPTOSUITE
        or proof.get("proofPurpose") != CAPABILITY_DELEGATION_PURPOSE
        or did_of_key_id(proof.get("verificationMethod")) is None
        or parse_rfc3339_millis(proof.get("created")) is None
        or not isinstance(chain, list)
        or len(chain) == 0
        or decode_eddsa_proof_value(proof.get("proofValue")) is None
        or ("@context" in proof and canonicalize_json(proof["@context"]) != canonicalize_json([ZCAP_CONTEXT]))
    ):
        return "unsupported_proof"
    return None


@dataclass(frozen=True)
class CheckedCapabilityChain:
    """A capability chain that passed the checks needing no resolution."""

    root_id: str
    """The root capability ``id``."""
    root_target: str
    """The target the root names."""
    root_controllers: tuple[str, ...]
    """The root controllers the verifier configured for ``root_target``."""
    capabilities: tuple[dict[str, Any], ...]
    """Delegated capabilities from the one under the root to the leaf."""
    allowed_action: tuple[str, ...] | None
    """The actions the leaf allows: the last ``allowedAction`` in the chain (``None`` = every action)."""


@dataclass(frozen=True)
class CapabilityChainRejection:
    """Why ``check_capability_chain`` rejected a chain."""

    reason: CapabilityRejection
    capability_id: str | None = None


def _chain_ids(chain: Sequence[object]) -> list[str] | None:
    """The ids of a ``capabilityChain``, with an embedded parent replaced by its ``id``."""
    ids: list[str] = []
    for index, entry in enumerate(chain):
        if isinstance(entry, str):
            ids.append(entry)
        elif index == len(chain) - 1 and isinstance(entry, dict) and isinstance(entry.get("id"), str):
            ids.append(entry["id"])
        else:
            return None
    return ids


def check_capability_chain(
    capability: object,
    root_controllers: Mapping[str, Sequence[str]],
    now_millis: int,
    max_chain_length: int = DEFAULT_MAX_CAPABILITY_CHAIN_LENGTH,
) -> CheckedCapabilityChain | CapabilityChainRejection:
    """The checks of RFC-001 §6.7 that need no resolution, in order.

    Form of every capability in the chain (``malformed_capability``, ``unsupported_proof``), chain length
    (``chain_too_long``), chain structure (``malformed_capability``), root controller configured
    (``root_controller_unknown``), attenuation at every link (``attenuation_violation``) and validity at
    *now_millis* (``expired``). Never raises.
    """
    limit = min(max(1, int(max_chain_length)), MAX_CAPABILITY_CHAIN_LENGTH)
    try:
        leaf_problem = capability_form_problem(capability)
    except (TypeError, ValueError):
        return CapabilityChainRejection("malformed_capability")
    if leaf_problem is not None:
        return CapabilityChainRejection(leaf_problem)
    assert isinstance(capability, dict)
    leaf: dict[str, Any] = capability
    if len(leaf["proof"]["capabilityChain"]) > limit:
        return CapabilityChainRejection("chain_too_long", leaf["id"])

    # Walk up through the embedded parents
    capabilities: list[dict[str, Any]] = [leaf]
    current = leaf
    while len(current["proof"]["capabilityChain"]) > 1:
        chain = current["proof"]["capabilityChain"]
        parent = chain[-1]
        try:
            problem = capability_form_problem(parent)
        except (TypeError, ValueError):
            problem = "malformed_capability"
        if problem is not None:
            return CapabilityChainRejection(problem, current["id"])
        assert isinstance(parent, dict)
        if parent["id"] != current["parentCapability"]:
            return CapabilityChainRejection("malformed_capability", current["id"])
        # The parent's chain, with its embedded parent as an id, is this chain without its last entry
        parent_ids = _chain_ids(parent["proof"]["capabilityChain"])
        own_ids = _chain_ids(chain)
        if parent_ids is None or own_ids is None or parent_ids != own_ids[:-1]:
            return CapabilityChainRejection("malformed_capability", current["id"])
        capabilities.insert(0, parent)
        current = parent
    first = capabilities[0]
    root_id = first["proof"]["capabilityChain"][0]
    if not isinstance(root_id, str) or root_id != first["parentCapability"] or not root_id.startswith(ZCAP_ROOT_PREFIX):
        return CapabilityChainRejection("malformed_capability", first["id"])
    if len({item["id"] for item in capabilities}) != len(capabilities):
        return CapabilityChainRejection("malformed_capability", leaf["id"])
    try:
        root_target = unquote(root_id[len(ZCAP_ROOT_PREFIX) :], errors="strict")
    except UnicodeDecodeError:
        return CapabilityChainRejection("malformed_capability", first["id"])
    if invocation_target_problem(root_target) is not None or root_capability_id(root_target) != root_id:
        return CapabilityChainRejection("malformed_capability", first["id"])
    configured = root_controllers.get(root_target)
    if not configured:
        return CapabilityChainRejection("root_controller_unknown", first["id"])

    # Attenuation: target, actions and expiry never widen down the chain
    parent_target = root_target
    parent_actions: list[str] | None = None
    parent_expires: float = float("inf")
    for item in capabilities:
        expires = parse_rfc3339_millis(item["expires"])
        assert expires is not None
        actions = item.get("allowedAction")
        # An absent allowedAction inherits the parent's actions; a present one must be a subset of them
        if (
            not target_within(item["invocationTarget"], parent_target)
            or (parent_actions is not None and actions is not None and not all(a in parent_actions for a in actions))
            or expires > parent_expires
        ):
            return CapabilityChainRejection("attenuation_violation", item["id"])
        parent_target = item["invocationTarget"]
        parent_actions = actions if actions is not None else parent_actions
        parent_expires = expires
    for item in capabilities:
        expires = parse_rfc3339_millis(item["expires"])
        assert expires is not None
        if now_millis > expires:
            return CapabilityChainRejection("expired", item["id"])
    return CheckedCapabilityChain(
        root_id=root_id,
        root_target=root_target,
        root_controllers=tuple(configured),
        capabilities=tuple(capabilities),
        allowed_action=None if parent_actions is None else tuple(parent_actions),
    )


def build_unsigned_capability(
    *,
    capability_id: str,
    parent_capability: str,
    invocation_target: str,
    controller: str,
    expires: str,
    allowed_action: Sequence[str] | None = None,
) -> dict[str, Any]:
    """The capability without its proof, as ``create_capability`` signs it."""
    unsigned: dict[str, Any] = {
        "@context": [ZCAP_CONTEXT],
        "id": capability_id,
        "parentCapability": parent_capability,
        "invocationTarget": invocation_target,
        "controller": controller,
    }
    if allowed_action is not None:
        unsigned["allowedAction"] = list(allowed_action)
    unsigned["expires"] = expires
    return unsigned


def child_capability_chain(parent: dict[str, Any] | str) -> list[Any]:
    """The ``capabilityChain`` of a capability delegated from *parent* (or from the root ``parent`` id)."""
    if isinstance(parent, str):
        return [parent]
    parent_ids = _chain_ids(parent["proof"]["capabilityChain"])
    if parent_ids is None:
        raise TypeError("The parent capability has a malformed capabilityChain")
    return [*parent_ids, copy.deepcopy(parent)]


def serialize_capability_header(label: str, capability: dict[str, Any]) -> str:
    """The ``Agent-DID-Capability`` member value: the JCS bytes of *capability*, as a Structured Field Byte
    Sequence."""
    encoded = base64.b64encode(canonicalize_json(capability).encode("utf-8")).decode("ascii")
    value = f"{label}=:{encoded}:"
    if len(value) > MAX_CAPABILITY_HEADER_BYTES:
        raise ValueError(f"The Agent-DID-Capability field would exceed {MAX_CAPABILITY_HEADER_BYTES} bytes")
    return value


class _Missing:
    pass


CAPABILITY_HEADER_MISSING = _Missing()
"""Returned by ``parse_capability_header`` when the field has no member for the label."""


def parse_capability_header(value: str, label: str) -> dict[str, Any] | _Missing | None:
    """The capability in the ``Agent-DID-Capability`` member of *label*.

    ``CAPABILITY_HEADER_MISSING`` when the field has no member for it, ``None`` when the field or the member is
    malformed (not a Dictionary, not a Byte Sequence without parameters, not the JCS form of a JSON object). The form
    of the capability itself is checked by ``verify_capability_chain``.
    """
    try:
        dictionary = _parse_dictionary(value)
    except HttpSignatureError:
        return None
    if label not in dictionary:
        return CAPABILITY_HEADER_MISSING
    bare, params = dictionary[label]
    if not isinstance(bare, bytes) or params:
        return None
    try:
        text = bare.decode("utf-8")
        parsed = json.loads(text)
        if not isinstance(parsed, dict) or canonicalize_json(parsed) != text:
            return None
    except (UnicodeDecodeError, ValueError, TypeError):
        return None
    return parsed
