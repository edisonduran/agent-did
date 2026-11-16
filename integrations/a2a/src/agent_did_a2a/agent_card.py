"""A2A 1.0 Agent Card builder with Agent-DID identity.

An Agent Card is the discovery document an A2A agent serves at ``/.well-known/agent-card.json`` (A2A 1.0 §8.2). This
module builds cards with the A2A 1.0 shape (``specification/a2a.proto`` v1.0.1, JSON names in lowerCamelCase) and
names the agent's identity through the Agent-DID extension in ``capabilities.extensions``: ``params.did`` is the agent
DID and ``params.keyIds`` the keys the card publishes. The card does not declare request signatures as a
``securitySchemes`` entry (none of the A2A scheme types describes HTTP Message Signatures); the extension does, and
``required`` says whether the agent expects them. A client activates it by sending ``A2A-Extensions: <uri>``.
"""

from __future__ import annotations

import copy
from typing import Any

from agent_did_sdk import AGENT_DID_A2A_EXTENSION_URI, AgentSigner, LocalKeySigner, sign_agent_card
from pydantic import BaseModel, ConfigDict, Field
from pydantic.alias_generators import to_camel

from .config import AgentDidA2AConfig
from .snapshot import (
    AgentDidIdentitySnapshot,
    RuntimeIdentity,
    get_active_signing_key_id,
    runtime_signing_key,
)

A2A_PROTOCOL_VERSION = "1.0"
"""The A2A protocol version the integration speaks (``A2A-Version``, ``AgentInterface.protocolVersion``)."""

AGENT_CARD_WELL_KNOWN_PATH = "/.well-known/agent-card.json"
"""The well-known path of an A2A 1.0 Agent Card (§8.2)."""

AGENT_DID_EXTENSION_DESCRIPTION = (
    "Agent-DID identity: requests are signed with HTTP Message Signatures (RFC 9421) by a key of params.did"
)


class _A2AModel(BaseModel):
    """A2A 1.0 JSON objects: lowerCamelCase names, members A2A does not define are rejected (they would be signed
    but dropped by A2A verifiers that rebuild the card from its Protocol Buffer form)."""

    model_config = ConfigDict(alias_generator=to_camel, populate_by_name=True, extra="forbid")

    def to_json(self) -> dict[str, Any]:
        return self.model_dump(by_alias=True, exclude_none=True)


class A2AAgentInterface(_A2AModel):
    """An ``AgentInterface``: where and how the agent is reached."""

    url: str
    protocol_binding: str = "JSONRPC"
    protocol_version: str = A2A_PROTOCOL_VERSION
    tenant: str | None = None


class A2AAgentProvider(_A2AModel):
    """An ``AgentProvider``."""

    url: str
    organization: str


class A2AAgentExtension(_A2AModel):
    """An ``AgentExtension`` of ``capabilities.extensions``."""

    uri: str
    description: str | None = None
    required: bool = False
    params: dict[str, Any] | None = None


class A2AAgentCapabilities(_A2AModel):
    """``AgentCapabilities``. The Agent-DID extension is added by the builder."""

    streaming: bool | None = None
    push_notifications: bool | None = None
    extended_agent_card: bool | None = None
    extensions: list[A2AAgentExtension] = Field(default_factory=list)


class A2ASkill(_A2AModel):
    """An ``AgentSkill``. A2A 1.0 requires a non-empty ``description`` and at least one tag."""

    id: str = Field(min_length=1)
    name: str = Field(min_length=1)
    description: str = Field(min_length=1)
    tags: list[str] = Field(min_length=1)
    examples: list[str] | None = None
    input_modes: list[str] | None = None
    output_modes: list[str] | None = None
    security_requirements: list[dict[str, Any]] | None = None


class A2AAgentCard(_A2AModel):
    """An A2A 1.0 ``AgentCard`` (without ``signatures``: see :func:`sign_agent_card_json`)."""

    name: str = Field(min_length=1)
    description: str = Field(min_length=1)
    supported_interfaces: list[A2AAgentInterface] = Field(min_length=1)
    provider: A2AAgentProvider | None = None
    version: str = Field(min_length=1)
    documentation_url: str | None = None
    capabilities: A2AAgentCapabilities = Field(default_factory=A2AAgentCapabilities)
    security_schemes: dict[str, dict[str, Any]] | None = None
    security_requirements: list[dict[str, Any]] | None = None
    default_input_modes: list[str] = Field(default_factory=lambda: ["text/plain"], min_length=1)
    default_output_modes: list[str] = Field(default_factory=lambda: ["text/plain"], min_length=1)
    skills: list[A2ASkill] = Field(min_length=1)
    icon_url: str | None = None

    def agent_did_extension(self) -> A2AAgentExtension | None:
        """The Agent-DID extension of the card, if any."""
        return next((e for e in self.capabilities.extensions if e.uri == AGENT_DID_A2A_EXTENSION_URI), None)


def _security(config: AgentDidA2AConfig) -> tuple[dict[str, dict[str, Any]] | None, list[dict[str, Any]] | None]:
    schemes: dict[str, dict[str, Any]] = dict(config.additional_security_schemes)
    requirements: list[dict[str, Any]] = list(config.additional_security_requirements)
    oauth = config.oauth_client_credentials
    if oauth is not None:
        schemes[oauth.scheme_name] = {
            "oauth2SecurityScheme": {
                "description": oauth.description,
                "flows": {"clientCredentials": {"tokenUrl": oauth.token_url, "scopes": dict(oauth.scopes)}},
            }
        }
        if oauth.required:
            requirements.append({"schemes": {oauth.scheme_name: {"list": list(oauth.scopes)}}})
    return schemes or None, requirements or None


def build_agent_card(
    *,
    identity_snapshot: AgentDidIdentitySnapshot,
    agent_url: str,
    skills: list[A2ASkill],
    key_ids: list[str] | None = None,
    capabilities: A2AAgentCapabilities | None = None,
    config: AgentDidA2AConfig | None = None,
    provider: A2AAgentProvider | None = None,
    documentation_url: str | None = None,
    icon_url: str | None = None,
    default_input_modes: list[str] | None = None,
    default_output_modes: list[str] | None = None,
) -> A2AAgentCard:
    """Build an A2A 1.0 Agent Card for the agent of *identity_snapshot*, reached over JSON-RPC at *agent_url*.

    The card carries the Agent-DID extension (``params.did``, and ``params.keyIds`` when *key_ids* is given;
    :func:`sign_agent_card_json` fills in the published keys) and, when configured, the OAuth client credentials
    scheme of ``config.oauth_client_credentials``.
    """
    effective_config = config or AgentDidA2AConfig()
    effective_capabilities = (capabilities or A2AAgentCapabilities()).model_copy(deep=True)
    effective_capabilities.extensions = [
        extension for extension in effective_capabilities.extensions if extension.uri != AGENT_DID_A2A_EXTENSION_URI
    ]
    params: dict[str, Any] = {"did": identity_snapshot.did}
    if key_ids:
        params["keyIds"] = list(key_ids)
    effective_capabilities.extensions.append(
        A2AAgentExtension(
            uri=AGENT_DID_A2A_EXTENSION_URI,
            description=AGENT_DID_EXTENSION_DESCRIPTION,
            required=effective_config.require_signed_requests,
            params=params,
        )
    )
    security_schemes, security_requirements = _security(effective_config)
    return A2AAgentCard(
        name=identity_snapshot.name,
        description=identity_snapshot.description or identity_snapshot.name,
        supported_interfaces=[A2AAgentInterface(url=agent_url)],
        provider=provider,
        version=identity_snapshot.version,
        documentation_url=documentation_url,
        capabilities=effective_capabilities,
        security_schemes=security_schemes,
        security_requirements=security_requirements,
        default_input_modes=default_input_modes or ["text/plain"],
        default_output_modes=default_output_modes or ["text/plain"],
        skills=skills,
        icon_url=icon_url,
    )


def agent_card_to_json(card: A2AAgentCard) -> dict[str, Any]:
    """Serialize an Agent Card to its A2A 1.0 JSON form (lowerCamelCase, unset members omitted)."""
    return card.to_json()


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
    composition contract (A2A 1.0 §8.4 JWS over the RFC 8785 form of the card without ``signatures`` and without
    default values). Existing signatures are replaced; the ``description`` and ``required`` of an existing Agent-DID
    extension are kept."""
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
    extensions = capabilities.get("extensions", [])
    if not isinstance(extensions, list):
        raise TypeError("capabilities.extensions must be a list")
    ours = [e for e in extensions if isinstance(e, dict) and e.get("uri") == AGENT_DID_A2A_EXTENSION_URI]
    others = [e for e in extensions if not (isinstance(e, dict) and e.get("uri") == AGENT_DID_A2A_EXTENSION_URI)]
    extension: dict[str, Any] = {"uri": AGENT_DID_A2A_EXTENSION_URI}
    if ours:
        extension.update({name: ours[0][name] for name in ("description", "required") if name in ours[0]})
    extension["params"] = {"did": runtime_identity.document.id, "keyIds": published_key_ids(runtime_identity)}
    capabilities["extensions"] = [*others, extension]
    return await sign_agent_card(card, signer, key_id)
