"""In-memory DID resolver for testing and local development."""

from __future__ import annotations

from ..core.types import AgentDIDDocument


class InMemoryDIDResolver:
    """Dict-backed DID resolver that stores deep copies of documents."""

    def __init__(self) -> None:
        self._store: dict[str, AgentDIDDocument] = {}

    def register_document(self, document: AgentDIDDocument) -> None:
        self._store[document.id] = document.model_copy(deep=True)

    async def resolve(self, did: str) -> AgentDIDDocument:
        doc = self._store.get(did)
        if doc is None:
            raise ValueError(f"DID not found: {did}")
        return doc.model_copy(deep=True)

    def remove(self, did: str) -> None:
        self._store.pop(did, None)
