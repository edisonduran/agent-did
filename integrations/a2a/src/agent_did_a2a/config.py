"""Configuration models for the Agent-DID A2A integration."""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field


class AgentDidA2AAuthScheme(BaseModel):
    """A2A-compatible authentication scheme declaring DID-based HTTP Signatures."""

    model_config = ConfigDict(extra="forbid")

    scheme: str = "https"
    credentials: str | None = None


class AgentDidA2AExposureConfig(BaseModel):
    """Which operations of the integration are enabled. A disabled operation raises ``PermissionError``.

    ``sign_requests`` gates ``sign_request`` / ``send_task`` / ``get_task``, ``verify_requests`` gates
    ``verify_request`` (which resolves the sender's DID: restrict it with ``allowed_dids`` and the resolver's
    ``allowed_hosts``), and ``enrich_agent_card`` gates ``build_agent_card`` / ``agent_card_json``.
    """

    model_config = ConfigDict(extra="forbid")

    sign_requests: bool = True
    verify_requests: bool = True
    enrich_agent_card: bool = True


class AgentDidA2AConfig(BaseModel):
    """Top-level integration config consumed by the public factory."""

    model_config = ConfigDict(extra="forbid")

    expose: AgentDidA2AExposureConfig = Field(default_factory=AgentDidA2AExposureConfig)
    agent_card_url: str = "/.well-known/agent.json"
    allow_private_network_targets: bool = False
    """Allow ``sign_request`` to sign for loopback, private and other non-global targets (development only)."""
    additional_auth_schemes: list[AgentDidA2AAuthScheme] = Field(default_factory=list)
