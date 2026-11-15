"""HTTP DID log source for did:webvh documents (did.jsonl)."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

import httpx

from ..core.http_security import HttpTargetValidationOptions, validate_http_target
from ..core.safe_client import create_safe_client
from ..core.types import AgentDIDDocument
from ..webvh.adapter import DidWebvhError, did_webvh_log_requires_witnesses, resolve_did_webvh_log
from .types import DocumentIntegrityError


@dataclass
class WebvhDIDDocumentSourceConfig:
    reference_to_url: Callable[[str], str] | None = None
    reference_to_urls: Callable[[str], list[str]] | None = None
    http_client: httpx.AsyncClient | None = None
    http_security: HttpTargetValidationOptions | None = None


class WebvhDIDDocumentSource:
    """Fetches did:webvh DID logs over HTTP(S) and verifies them before use."""

    def __init__(self, config: WebvhDIDDocumentSourceConfig | None = None) -> None:
        cfg = config or WebvhDIDDocumentSourceConfig()
        self._reference_to_url = cfg.reference_to_url or (lambda ref: ref)
        self._reference_to_urls = cfg.reference_to_urls
        self._client = cfg.http_client
        self._http_security = cfg.http_security or HttpTargetValidationOptions()

    async def get_by_reference(self, document_ref: str) -> AgentDIDDocument | None:
        """Fetch the did:webvh log and return the latest state after verifying the whole log.

        A log with witnessed entries is verified with the ``did-witness.json`` next to it (ADR-007). Raises
        :class:`DocumentIntegrityError` when verification fails (or the state is not an Agent-DID document);
        returns ``None`` when no endpoint has the log.
        """
        log_text = await self.get_did_log_by_reference(document_ref)
        if log_text is None:
            return None
        try:
            witness_file: str | None = None
            if did_webvh_log_requires_witnesses(log_text):
                if not document_ref.endswith("did.jsonl"):
                    raise DocumentIntegrityError(
                        f"The did:webvh log at {document_ref} has witnessed entries and its did-witness.json "
                        "cannot be located"
                    )
                witness_file = await self.get_did_witness_file_by_reference(
                    document_ref.removesuffix("did.jsonl") + "did-witness.json"
                )
                if witness_file is None:
                    raise DocumentIntegrityError(
                        f"The did:webvh log at {document_ref} has witnessed entries and no did-witness.json"
                    )
            resolved = await resolve_did_webvh_log(log_text, witness_file=witness_file)
        except DidWebvhError as exc:
            raise DocumentIntegrityError(str(exc)) from None
        return _to_agent_document(resolved.state)

    async def get_did_log_by_reference(self, document_ref: str) -> str | None:
        """Fetch the raw ``did.jsonl`` text. The caller must verify it before trusting it."""
        return await self._fetch_text(document_ref, "did:webvh DID log")

    async def get_did_witness_file_by_reference(self, document_ref: str) -> str | None:
        """Fetch the raw ``did-witness.json`` text (ADR-007), with the same SSRF policy and limits as the log.

        The caller verifies the proofs (``resolve_did_webvh_log``)."""
        return await self._fetch_text(document_ref, "did:webvh witness file")

    async def _fetch_text(self, document_ref: str, what: str) -> str | None:
        urls = self._resolve_candidate_urls(document_ref)
        errors: list[str] = []
        all_not_found = True

        for url in urls:
            try:
                validate_http_target(url, self._http_security)
            except ValueError as exc:
                # Blocked by policy is not "not found": the log may well exist.
                all_not_found = False
                errors.append(f"{url}: {exc}")
                continue

            client = self._client or create_safe_client(self._http_security)
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

            return response.text

        if all_not_found:
            return None

        raise RuntimeError(f"Failed to fetch {what} from all endpoints. {' | '.join(errors)}")

    async def store_did_log_by_reference(self, document_ref: str, did_log: str) -> None:
        raise NotImplementedError("WebvhDIDDocumentSource is read-only")

    def _resolve_candidate_urls(self, document_ref: str) -> list[str]:
        if self._reference_to_urls:
            return self._reference_to_urls(document_ref)

        return [self._reference_to_url(document_ref)]


def _to_agent_document(state: dict[str, object]) -> AgentDIDDocument:
    try:
        return AgentDIDDocument.model_validate(state)
    except ValueError as exc:
        raise DocumentIntegrityError(f"did:webvh state is not an Agent-DID document: {exc}") from None
