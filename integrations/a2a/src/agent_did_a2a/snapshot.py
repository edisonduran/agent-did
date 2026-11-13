"""Helpers for building a stable, secret-free Agent-DID identity snapshot for A2A."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, cast

from agent_did_sdk import AgentSigner, CreateAgentResult, RotateVerificationMethodResult
from pydantic import BaseModel, ConfigDict

RuntimeIdentity = CreateAgentResult | RotateVerificationMethodResult


@dataclass(slots=True)
class RuntimeIdentityHandle:
    """Mutable runtime identity reference shared by the integration and tools."""

    value: RuntimeIdentity


class AgentDidIdentitySnapshot(BaseModel):
    """Serializable identity view used in AgentCards and observability events."""

    model_config = ConfigDict(populate_by_name=True)

    did: str
    controller: str
    name: str
    description: str | None = None
    version: str
    capabilities: list[str]
    member_of: str | None = None
    authentication_key_id: str | None = None
    created: str
    updated: str


def get_active_authentication_key_id(runtime_identity: RuntimeIdentity) -> str | None:
    if isinstance(runtime_identity, RotateVerificationMethodResult):
        return runtime_identity.verification_method_id

    authentication = runtime_identity.document.authentication
    first_authentication_method: str | None = authentication[0] if authentication else None
    return first_authentication_method


def build_agent_did_identity_snapshot(runtime_identity: RuntimeIdentity) -> AgentDidIdentitySnapshot:
    document = runtime_identity.document
    metadata = document.agent_metadata

    return AgentDidIdentitySnapshot(
        did=document.id,
        controller=document.controller,
        name=metadata.name,
        description=metadata.description,
        version=metadata.version,
        capabilities=list(metadata.capabilities or []),
        member_of=metadata.member_of,
        authentication_key_id=get_active_authentication_key_id(runtime_identity),
        created=document.created,
        updated=document.updated,
    )


def runtime_signing_key(runtime_identity: RuntimeIdentity) -> str | AgentSigner:
    """What the runtime identity signs with: its external signer (KMS, HSM) when it has one, else its private key
    (hex). Raises when it has neither."""
    signer = getattr(runtime_identity, "signer", None)
    if signer is not None:
        return cast(AgentSigner, signer)
    if not runtime_identity.agent_private_key:
        raise ValueError("The runtime identity has no private key and no signer to sign with")
    return runtime_identity.agent_private_key


def runtime_signing_params(runtime_identity: RuntimeIdentity) -> dict[str, Any]:
    """``signer`` or ``agent_private_key`` for ``SignHttpRequestParams``, from :func:`runtime_signing_key`."""
    key = runtime_signing_key(runtime_identity)
    return {"agent_private_key": key} if isinstance(key, str) else {"signer": key}


def assert_rotatable_by_tool(runtime_identity: RuntimeIdentity) -> None:
    """A tool can only rotate to a key it generates locally. An agent whose key lives in an external signer is
    rotated by its operator with ``AgentDidClient.rotate_verification_method(did, signer=...)``."""
    if getattr(runtime_identity, "signer", None) is not None:
        raise ValueError(
            "This agent signs with an external signer: rotate its key with "
            "AgentDidClient.rotate_verification_method(did, signer=<new signer>), not with the rotate_key tool"
        )
