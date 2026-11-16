"""Configuration models for the Agent-DID A2A integration."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class AgentDidA2AExposureConfig(BaseModel):
    """Which operations of the integration are enabled. A disabled operation raises ``PermissionError``.

    ``sign_requests`` gates ``sign_request`` / ``send_message`` / ``get_task``, ``verify_requests`` gates
    ``verify_request`` / ``verify_request_against_card`` (which resolve the sender's DID: restrict them with
    ``allowed_dids`` and the resolver's ``allowed_hosts``), and ``enrich_agent_card`` gates ``build_agent_card`` /
    ``agent_card_json`` / ``signed_agent_card_json``.
    """

    model_config = ConfigDict(extra="forbid")

    sign_requests: bool = True
    verify_requests: bool = True
    enrich_agent_card: bool = True


class AgentDidA2AOAuthClientCredentials(BaseModel):
    """An OAuth 2.0 client credentials scheme the agent's server accepts, declared in the Agent Card as an A2A 1.0
    ``oauth2SecurityScheme``. Clients authenticate to ``token_url`` with a JWT client assertion signed by their DID
    key (``private_key_jwt``, RFC 7523; ``AgentIdentity.create_client_assertion``)."""

    model_config = ConfigDict(extra="forbid")

    token_url: str
    scopes: dict[str, str] = Field(min_length=1)
    """Scope name to description. A2A 1.0 requires at least one entry."""
    scheme_name: str = "agentDidClientCredentials"
    description: str = "OAuth 2.0 client credentials with a JWT client assertion signed by the client's DID key"
    required: bool = True
    """Add a ``securityRequirements`` entry for this scheme (all ``scopes``)."""


class AgentDidA2AConfig(BaseModel):
    """Top-level integration config consumed by the public factory."""

    model_config = ConfigDict(extra="forbid")

    expose: AgentDidA2AExposureConfig = Field(default_factory=AgentDidA2AExposureConfig)
    agent_card_url: str = "/.well-known/agent-card.json"
    """Where the Agent Card is served (A2A 1.0 §8.2 well-known URI)."""
    allow_private_network_targets: bool = False
    """Allow ``sign_request`` to sign for loopback, private and other non-global targets (development only)."""
    require_signed_requests: bool = False
    """Declare the Agent-DID extension ``required`` in the card: clients must sign their requests with Agent-DID
    (A2A 1.0 §4.6). The integration does not enforce it on incoming requests: call ``verify_request``."""
    oauth_client_credentials: AgentDidA2AOAuthClientCredentials | None = None
    additional_security_schemes: dict[str, dict[str, Any]] = Field(default_factory=dict)
    """Further A2A 1.0 ``SecurityScheme`` objects for ``securitySchemes``, as JSON (for example
    ``{"oidc": {"openIdConnectSecurityScheme": {"openIdConnectUrl": "..."}}}``)."""
    additional_security_requirements: list[dict[str, Any]] = Field(default_factory=list)
    """Further A2A 1.0 ``SecurityRequirement`` objects, as JSON (``{"schemes": {"oidc": {"list": ["openid"]}}}``)."""
