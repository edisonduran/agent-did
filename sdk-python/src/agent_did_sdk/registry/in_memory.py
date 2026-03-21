"""In-memory implementation of the AgentRegistry protocol."""

from __future__ import annotations

from datetime import datetime, timezone

from .types import AgentRegistryRecord


class InMemoryAgentRegistry:
    """Dict-backed agent registry for testing and local development."""

    def __init__(self) -> None:
        self._records: dict[str, AgentRegistryRecord] = {}

    async def register(self, did: str, controller: str, document_ref: str | None = None) -> None:
        if did in self._records:
            return
        self._records[did] = AgentRegistryRecord(
            did=did,
            controller=controller,
            created_at=datetime.now(timezone.utc).isoformat(),
            document_ref=document_ref,
        )

    async def set_document_reference(self, did: str, document_ref: str) -> None:
        existing = self._records.get(did)
        if existing is None:
            raise ValueError(f"DID not found in registry: {did}")
        self._records[did] = existing.model_copy(update={"document_ref": document_ref})

    async def revoke(self, did: str) -> None:
        existing = self._records.get(did)
        if existing is None:
            raise ValueError(f"DID not found in registry: {did}")
        self._records[did] = existing.model_copy(
            update={"revoked_at": datetime.now(timezone.utc).isoformat()}
        )

    async def get_record(self, did: str) -> AgentRegistryRecord | None:
        return self._records.get(did)

    async def is_revoked(self, did: str) -> bool:
        record = self._records.get(did)
        return bool(record and record.revoked_at)
