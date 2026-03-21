"""Web3-based contract client for AgentRegistry.sol — equivalent to EthersAgentRegistryContractClient."""

from __future__ import annotations

from typing import Any

from ..core.time_utils import normalize_timestamp_to_iso
from .evm_types import EvmTxResponse
from .types import AgentRegistryRecord


def _safe_str(v: Any) -> str:  # noqa: ANN401
    if v is None:
        return ""
    if isinstance(v, str):
        return v
    if isinstance(v, (int, float)):
        return str(int(v))
    return ""


class Web3AgentRegistryContractClient:
    """Wraps a web3.py-style contract instance into the ``EvmAgentRegistryContract`` interface."""

    def __init__(self, contract: Any) -> None:  # noqa: ANN401
        self._contract = contract

    async def register_agent(self, did: str, controller: str, document_ref: str | None = None) -> EvmTxResponse | None:
        fn = getattr(self._contract, "register_agent", None) or getattr(self._contract.functions, "registerAgent", None)
        if fn is None:
            raise RuntimeError("Contract method not available: registerAgent(did, controller)")
        result = fn(did, controller)
        if hasattr(result, "transact"):
            result.transact()
            return EvmTxResponse(wait=None)
        return None

    async def set_document_ref(self, did: str, document_ref: str) -> EvmTxResponse | None:
        fn = (
            getattr(self._contract, "set_document_ref", None)
            or getattr(self._contract.functions, "setDocumentRef", None)
        )
        if fn is None:
            raise RuntimeError("Contract method not available: setDocumentRef(did, documentRef)")
        result = fn(did, document_ref)
        if hasattr(result, "transact"):
            result.transact()
        return None

    async def revoke_agent(self, did: str) -> EvmTxResponse | None:
        fn = getattr(self._contract, "revoke_agent", None) or getattr(self._contract.functions, "revokeAgent", None)
        if fn is None:
            raise RuntimeError("Contract method not available: revokeAgent(did)")
        result = fn(did)
        if hasattr(result, "transact"):
            result.transact()
        return None

    async def get_agent_record(self, did: str) -> AgentRegistryRecord | None:
        fn = (
            getattr(self._contract, "get_agent_record", None)
            or getattr(self._contract.functions, "getAgentRecord", None)
        )
        if fn is None:
            raise RuntimeError("Contract method not available: getAgentRecord(did)")

        raw = fn(did)
        if hasattr(raw, "call"):
            raw = raw.call()

        if raw is None:
            return None

        # Handle tuple/list response
        if isinstance(raw, (list, tuple)):
            record_did, controller, created_at, revoked_at, document_ref = raw
            return AgentRegistryRecord(
                did=_safe_str(record_did),
                controller=_safe_str(controller),
                created_at=normalize_timestamp_to_iso(_safe_str(created_at)) or _safe_str(created_at),
                revoked_at=normalize_timestamp_to_iso(_safe_str(revoked_at)),
                document_ref=_safe_str(document_ref) or None,
            )

        # Handle dict/object response
        if isinstance(raw, dict) and "did" in raw and "controller" in raw:
            return AgentRegistryRecord(
                did=raw["did"],
                controller=raw["controller"],
                created_at=(
                    normalize_timestamp_to_iso(_safe_str(raw.get("createdAt")))
                    or _safe_str(raw.get("createdAt"))
                ),
                revoked_at=normalize_timestamp_to_iso(_safe_str(raw.get("revokedAt"))),
                document_ref=raw.get("documentRef") or None,
            )

        raise ValueError("Invalid contract response format for getAgentRecord")

    async def is_revoked(self, did: str) -> bool:
        fn = getattr(self._contract, "is_revoked", None) or getattr(self._contract.functions, "isRevoked", None)
        if fn is None:
            record = await self.get_agent_record(did)
            return bool(record and record.revoked_at)
        result = fn(did)
        if hasattr(result, "call"):
            result = result.call()
        return bool(result)
