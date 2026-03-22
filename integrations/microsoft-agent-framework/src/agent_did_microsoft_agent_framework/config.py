"""Public configuration models for the Agent-DID Microsoft Agent Framework integration."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class AgentDidExposureConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    current_identity: bool = True
    resolve_did: bool = True
    verify_signatures: bool = True
    sign_http: bool = False
    sign_payload: bool = False
    rotate_keys: bool = False
    document_history: bool = False


class AgentDidMicrosoftAgentFrameworkConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    expose: AgentDidExposureConfig = Field(default_factory=AgentDidExposureConfig)
    tool_prefix: str = "agent_did"
    additional_instructions: str | None = None
    allow_private_network_targets: bool = False
    tool_approval_mode: Literal["always_require", "never_require"] = "never_require"
