"""HTTP DID log source for did:webvh documents (did.jsonl)."""

from __future__ import annotations

import json
from dataclasses import dataclass

import httpx

from ..core.http_security import HttpTargetValidationOptions, validate_http_target
from ..core.types import AgentDIDDocument


@dataclass
class WebvhDIDDocumentSourceConfig:
    reference_to_url: callable | None = None
    reference_to_urls: callable | None = None
    http_client: httpx.AsyncClient | None = None
    http_security: HttpTargetValidationOptions | None = None


class WebvhDIDDocumentSource:
    """Fetches and parses did:webvh DID logs over HTTP(S)."""

    def __init__(self, config: WebvhDIDDocumentSourceConfig | None = None) -> None:
        cfg = config or WebvhDIDDocumentSourceConfig()
        self._reference_to_url = cfg.reference_to_url or (lambda ref: ref)
        self._reference_to_urls = cfg.reference_to_urls
        self._client = cfg.http_client
        self._http_security = cfg.http_security or HttpTargetValidationOptions()

    async def get_by_reference(self, document_ref: str) -> AgentDIDDocument | None:
        urls = self._resolve_candidate_urls(document_ref)
        errors: list[str] = []
        all_not_found = True

        for url in urls:
            try:
                validate_http_target(url, self._http_security)
            except ValueError as exc:
                errors.append(f"{url}: {exc}")
                continue

            client = self._client or httpx.AsyncClient()
            try:
                response = await client.get(url)
            except Exception as exc:  # noqa: BLE001
                all_not_found = False
                errors.append(f"{url}: {exc}")
                continue
            finally:
                if self._client is None:
                    await client.aclose()

            if response.status_code == 404:
                continue

            if not (200 <= response.status_code < 300):
                all_not_found = False
                errors.append(f"{url}: HTTP {response.status_code}")
                continue

            return self._extract_latest_state(response.text)

        if all_not_found:
            return None

        raise RuntimeError(f"Failed to fetch did:webvh DID log from all endpoints. {' | '.join(errors)}")

    def _resolve_candidate_urls(self, document_ref: str) -> list[str]:
        if self._reference_to_urls:
            return self._reference_to_urls(document_ref)

        return [self._reference_to_url(document_ref)]

    @staticmethod
    def _extract_latest_state(log_text: str) -> AgentDIDDocument:
        lines = [line.strip() for line in log_text.splitlines() if line.strip()]
        if not lines:
            raise RuntimeError("did:webvh DID log is empty")

        latest_state: dict[str, object] | None = None
        for line in lines:
            try:
                parsed = json.loads(line)
            except json.JSONDecodeError as exc:
                raise RuntimeError("did:webvh DID log contains invalid JSON Lines content") from exc

            state = parsed.get("state") if isinstance(parsed, dict) else None
            if isinstance(state, dict):
                latest_state = state

        if latest_state is None:
            raise RuntimeError("did:webvh DID log does not contain a resolvable state entry")

        return AgentDIDDocument.model_validate(latest_state)