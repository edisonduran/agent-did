"""Filesystem-backed DID document source for local storage adapters."""

from __future__ import annotations

import json
import re
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from ..core.types import AgentDIDDocument


@dataclass
class FilesystemDIDDocumentSourceConfig:
    root_directory: str | Path | None = None
    """Directory the default mapping writes to: a reference becomes
    ``<root_directory>/<reference with unsafe characters replaced by _>.json``."""
    reference_to_path: Callable[[str], str | Path] | None = None
    """Maps a reference to a path. Required unless ``root_directory`` or ``reference_to_paths`` is given: a reference
    is never used as a path as it is."""
    reference_to_paths: Callable[[str], list[str | Path]] | None = None


def _safe_file_name(document_ref: str) -> str:
    """The file name of a reference under ``root_directory``: path separators, ``..`` and anything outside
    ``[A-Za-z0-9._-]`` are replaced."""
    name = re.sub(r"^\.+", "_", re.sub(r"[^A-Za-z0-9._-]", "_", document_ref))
    return f"{name or '_'}.json"


class FilesystemDIDDocumentSource:
    """Reads and writes DID documents and did:webvh logs from filesystem paths."""

    def __init__(self, config: FilesystemDIDDocumentSourceConfig | None = None) -> None:
        cfg = config or FilesystemDIDDocumentSourceConfig()
        root = cfg.root_directory
        if cfg.reference_to_path is None and cfg.reference_to_paths is None and root is None:
            raise TypeError(
                "FilesystemDIDDocumentSource needs root_directory, reference_to_path or reference_to_paths: "
                "a reference is not used as a path as it is"
            )
        self._reference_to_path = cfg.reference_to_path or (lambda ref: Path(root or ".") / _safe_file_name(ref))
        self._reference_to_paths = cfg.reference_to_paths

    async def get_by_reference(self, document_ref: str) -> AgentDIDDocument | None:
        candidate_paths = self._resolve_candidate_paths(document_ref)
        errors: list[str] = []
        all_missing = True

        for candidate_path in candidate_paths:
            try:
                raw_document = candidate_path.read_text(encoding="utf-8")
                all_missing = False
                return AgentDIDDocument.model_validate(json.loads(raw_document))
            except FileNotFoundError:
                continue
            except Exception as exc:  # noqa: BLE001
                all_missing = False
                errors.append(f"{candidate_path}: {exc}")

        if all_missing:
            return None

        raise RuntimeError(f"Failed to read DID document from filesystem paths. {' | '.join(errors)}")

    async def store_by_reference(self, document_ref: str, document: AgentDIDDocument) -> None:
        target_path = self._resolve_primary_path(document_ref)
        target_path.parent.mkdir(parents=True, exist_ok=True)
        target_path.write_text(
            json.dumps(document.model_dump(by_alias=True, exclude_none=True), indent=2),
            encoding="utf-8",
        )

    async def get_did_log_by_reference(self, document_ref: str) -> str | None:
        candidate_paths = self._resolve_candidate_paths(document_ref)
        errors: list[str] = []
        all_missing = True

        for candidate_path in candidate_paths:
            try:
                did_log = candidate_path.read_text(encoding="utf-8")
                all_missing = False
                return did_log
            except FileNotFoundError:
                continue
            except Exception as exc:  # noqa: BLE001
                all_missing = False
                errors.append(f"{candidate_path}: {exc}")

        if all_missing:
            return None

        raise RuntimeError(f"Failed to read did:webvh DID log from filesystem paths. {' | '.join(errors)}")

    async def store_did_log_by_reference(self, document_ref: str, did_log: str) -> None:
        target_path = self._resolve_primary_path(document_ref)
        target_path.parent.mkdir(parents=True, exist_ok=True)
        target_path.write_text(did_log, encoding="utf-8")

    def _resolve_candidate_paths(self, document_ref: str) -> list[Path]:
        if self._reference_to_paths:
            return [Path(candidate_path) for candidate_path in self._reference_to_paths(document_ref)]

        return [Path(self._reference_to_path(document_ref))]

    def _resolve_primary_path(self, document_ref: str) -> Path:
        candidate_paths = self._resolve_candidate_paths(document_ref)
        if not candidate_paths:
            raise RuntimeError(f"No filesystem path candidates configured for reference: {document_ref}")
        return candidate_paths[0]
