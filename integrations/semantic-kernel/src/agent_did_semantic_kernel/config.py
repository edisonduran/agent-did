"""Public configuration models for the Agent-DID Semantic Kernel integration."""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field


class AgentDidExposureConfig(BaseModel):
    """Feature exposure flags with secure defaults."""

    model_config = ConfigDict(extra="forbid")

    current_identity: bool = True
    resolve_did: bool = True
    verify_signatures: bool = True
    sign_http: bool = False
    sign_payload: bool = False
    rotate_keys: bool = False
    document_history: bool = False


class AgentDidSemanticKernelConfig(BaseModel):
    """Top-level integration config consumed by the public factory."""

    model_config = ConfigDict(extra="forbid")

    expose: AgentDidExposureConfig = Field(default_factory=AgentDidExposureConfig)
    tool_prefix: str = "agent_did"
    additional_instructions: str | None = None
    allow_private_network_targets: bool = False
