"""A2A AgentCard builder enriched with Agent-DID identity.

An AgentCard is the discovery document that A2A agents expose at
``/.well-known/agent.json``.  This module generates spec-compliant
AgentCards that embed the agent's DID, verification methods, and
DID-based HTTP Signature authentication scheme.
"""

from __future__ import annotations

import copy
from typing import Any

from agent_did_sdk import AGENT_DID_A2A_EXTENSION_URI, AgentSigner, LocalKeySigner, sign_agent_card
from pydantic import BaseModel, ConfigDict, Field

from .config import AgentDidA2AConfig
from .snapshot import (
    AgentDidIdentitySnapshot,
    RuntimeIdentity,
    get_active_signing_key_id,
    runtime_signing_key,
)


class A2ASkill(BaseModel):
    """An A2A skill declaration."""

    model_config = ConfigDict(extra="allow")

    id: str
    name: str
    description: str
    input_modes: list[str] = Field(default_factory=lambda: ["text/plain"])
    output_modes: list[str] = Field(default_factory=lambda: ["text/plain"])
    tags: list[str] = Field(default_factory=list)


class A2AAuthenticationInfo(BaseModel):
    """A2A authentication info block with Agent-DID extension."""

    model_config = ConfigDict(extra="allow")

    schemes: list[str] = Field(default_factory=list)
    credentials: str | None = None


class A2AAgentCard(BaseModel):
    """A2A-compliant AgentCard enriched with Agent-DID identity.

    Standard A2A fields:
      name, description, url, skills, capabilities, authentication

    Agent-DID extensions:
      did, controller, authentication_key_id, verification_endpoint
    """

    model_config = ConfigDict(extra="allow")

    # --- Standard A2A fields ---
    name: str
    description: str | None = None
    url: str
    version: str = "0.1.0"
    skills: list[A2ASkill] = Field(default_factory=list)
    capabilities: dict[str, bool] = Field(default_factory=dict)
    authentication: A2AAuthenticationInfo = Field(default_factory=A2AAuthenticationInfo)

    # --- Agent-DID identity extensions ---
    did: str
    controller: str
    authentication_key_id: str | None = None
    verification_endpoint: str | None = None


def build_agent_card(
    *,
    identity_snapshot: AgentDidIdentitySnapshot,
    agent_url: str,
    skills: list[A2ASkill] | None = None,
    capabilities: dict[str, bool] | None = None,
    config: AgentDidA2AConfig | None = None,
    verification_endpoint: str | None = None,
) -> A2AAgentCard:
    """Build an A2A AgentCard enriched with Agent-DID identity.

    The card declares ``http-signature-did`` as an authentication scheme
    so that consuming agents know they can verify the agent's identity
    via DID-based HTTP Message Signatures.
    """

    effective_config = config or AgentDidA2AConfig()

    schemes = ["http-signature-did"]
    for extra in effective_config.additional_auth_schemes:
        schemes.append(extra.scheme)

    return A2AAgentCard(
        name=identity_snapshot.name,
        description=identity_snapshot.description,
        url=agent_url,
        version=identity_snapshot.version,
        skills=skills or [],
        capabilities=capabilities or {"streaming": False, "pushNotifications": False},
        authentication=A2AAuthenticationInfo(schemes=schemes),
        did=identity_snapshot.did,
        controller=identity_snapshot.controller,
        authentication_key_id=identity_snapshot.authentication_key_id,
        verification_endpoint=verification_endpoint,
    )


def agent_card_to_json(card: A2AAgentCard) -> dict[str, Any]:
    """Serialize an AgentCard to a JSON-compatible dict for ``/.well-known/agent.json``."""
    return card.model_dump(exclude_none=True)


def published_key_ids(runtime_identity: RuntimeIdentity) -> list[str]:
    """The keys a card of this agent publishes: the signing key first, then the other active ``assertionMethod`` keys
    of its DID document (a planned overlap lists both the old and the new key)."""
    document = runtime_identity.document
    retired = {method.id for method in document.verification_method if method.deactivated}
    signing = get_active_signing_key_id(runtime_identity)
    active = [key_id for key_id in document.assertion_method or [] if key_id not in retired]
    return list(dict.fromkeys([*([signing] if signing else []), *active]))


async def sign_agent_card_json(card_json: dict[str, Any], runtime_identity: RuntimeIdentity) -> dict[str, Any]:
    """Return *card_json* with the Agent-DID extension in ``capabilities.extensions`` (the agent DID and
    :func:`published_key_ids`) and a ``signatures`` entry by the agent's active signing key: the signed card of the
    composition contract (A2A 1.0 §8.4 JWS over the JCS form of the card without ``signatures``). Any existing
    Agent-DID extension and signatures are replaced."""
    key_id = get_active_signing_key_id(runtime_identity)
    if key_id is None:
        raise ValueError("The runtime identity has no active assertionMethod key to sign with")
    key = runtime_signing_key(runtime_identity)
    signer: AgentSigner = LocalKeySigner(key) if isinstance(key, str) else key
    card = copy.deepcopy(card_json)
    card.pop("signatures", None)
    capabilities = card.setdefault("capabilities", {})
    if not isinstance(capabilities, dict):
        raise TypeError("capabilities must be an object")
    others = [
        extension
        for extension in capabilities.get("extensions", [])
        if not (isinstance(extension, dict) and extension.get("uri") == AGENT_DID_A2A_EXTENSION_URI)
    ]
    capabilities["extensions"] = [
        *others,
        {
            "uri": AGENT_DID_A2A_EXTENSION_URI,
            "params": {"did": runtime_identity.document.id, "keyIds": published_key_ids(runtime_identity)},
        },
    ]
    return await sign_agent_card(card, signer, key_id)
