"""Registry protocol and record types."""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from pydantic import BaseModel, ConfigDict, Field


class AgentRegistryRecord(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    did: str
    controller: str
    created_at: str = Field(alias="createdAt")
    revoked_at: str | None = Field(default=None, alias="revokedAt")
    document_ref: str | None = Field(default=None, alias="documentRef")


@runtime_checkable
class AgentRegistry(Protocol):
    async def register(self, did: str, controller: str, document_ref: str | None = None) -> None: ...
    async def set_document_reference(self, did: str, document_ref: str) -> None: ...
    async def revoke(self, did: str) -> None: ...
    async def get_record(self, did: str) -> AgentRegistryRecord | None: ...
    async def is_revoked(self, did: str) -> bool: ...
