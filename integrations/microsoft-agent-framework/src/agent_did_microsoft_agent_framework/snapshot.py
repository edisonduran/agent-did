"""Helpers for building a stable, secret-free Agent-DID identity snapshot."""

from __future__ import annotations

from agent_did_sdk import CreateAgentResult, RotateVerificationMethodResult
from pydantic import BaseModel, ConfigDict

RuntimeIdentity = CreateAgentResult | RotateVerificationMethodResult


class AgentDidIdentitySnapshot(BaseModel):
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


def get_active_signing_key_id(runtime_identity: RuntimeIdentity) -> str | None:
    """The key the agent signs payloads and HTTP requests with: the key of the last rotation, else the first active
    key under ``assertionMethod``, the relationship verifiers require for both (RFC-001 §6.2.1.3)."""
    if isinstance(runtime_identity, RotateVerificationMethodResult):
        return runtime_identity.verification_method_id
    document = runtime_identity.document
    retired = {method.id for method in document.verification_method if method.deactivated}
    return next((key_id for key_id in document.assertion_method or [] if key_id not in retired), None)

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
