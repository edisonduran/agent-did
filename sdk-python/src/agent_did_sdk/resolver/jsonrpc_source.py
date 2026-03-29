"""JSON-RPC-based DID document source with SSRF protection and multi-endpoint failover."""

from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlparse

import httpx

from ..core.http_security import HttpTargetValidationOptions, validate_http_target
from ..core.types import AgentDIDDocument


@dataclass
class JsonRpcDIDDocumentSourceConfig:
    endpoint: str | None = None
    endpoints: list[str] | None = None
    method: str = "agent_resolveDocumentRef"
    build_params: Callable[[str], list[Any]] | None = None
    headers: dict[str, str] | None = None
    http_client: httpx.AsyncClient | None = None
    http_security: HttpTargetValidationOptions | None = None


class JsonRpcDIDDocumentSource:
    """Resolves DID documents via JSON-RPC 2.0 endpoints with SSRF protection."""

    def __init__(self, config: JsonRpcDIDDocumentSourceConfig | None = None) -> None:
        cfg = config or JsonRpcDIDDocumentSourceConfig()
        self._endpoints: list[str] = cfg.endpoints or ([cfg.endpoint] if cfg.endpoint else [])
        self._method = cfg.method
        self._build_params = cfg.build_params or (lambda ref: [ref])
        self._headers = {"content-type": "application/json", **(cfg.headers or {})}
        self._client = cfg.http_client
        self._http_security = cfg.http_security or HttpTargetValidationOptions()

        if not self._endpoints:
            raise ValueError("JsonRpcDIDDocumentSource requires at least one endpoint")

    async def get_by_reference(self, document_ref: str) -> AgentDIDDocument | None:
        import json

        payload = json.dumps({
            "jsonrpc": "2.0",
            "id": int(time.time() * 1000),
            "method": self._method,
            "params": self._build_params(document_ref),
        })

        errors: list[str] = []
        had_valid = False

        for endpoint in self._endpoints:
            try:
                validate_http_target(endpoint, self._http_security)
            except ValueError as ve:
                errors.append(f"{endpoint}: {ve}")
                continue

            had_valid = True

            try:
                client = self._client or httpx.AsyncClient()
                try:
                    response = await client.post(endpoint, content=payload, headers=self._headers)
                finally:
                    if self._client is None:
                        await client.aclose()

                if response.status_code < 200 or response.status_code >= 300:
                    errors.append(f"{endpoint}: HTTP {response.status_code}")
                    continue

                body = response.json()
                error = body.get("error")
                if error:
                    code = error.get("code")
                    if code in (404, -32004):
                        continue
                    msg = error.get("message", "")
                    errors.append(f"{endpoint}: RPC {code or 'unknown'} {msg}".strip())
                    continue

                result = body.get("result")
                if not result:
                    continue

                return AgentDIDDocument.model_validate(result)

            except Exception as exc:
                errors.append(f"{endpoint}: {exc}")

        if not errors or not had_valid:
            return None

        raise RuntimeError(f"Failed to resolve DID document via JSON-RPC endpoints. {' | '.join(errors)}")
