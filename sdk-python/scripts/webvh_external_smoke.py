from __future__ import annotations

import asyncio
import json
import os
import sys
from pathlib import Path

import httpx

from agent_did_sdk import WebvhDIDDocumentSource, WebvhDIDDocumentSourceConfig
from agent_did_sdk.core.http_security import HttpTargetValidationOptions

REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_MANIFEST_PATH = REPO_ROOT / "fixtures" / "external-smoke" / "webvh-public-targets.json"


def _candidate_urls() -> list[str]:
    explicit_urls = os.environ.get("AGENTDID_WEBVH_EXTERNAL_URLS")
    if explicit_urls:
        return [url.strip() for url in explicit_urls.split(",") if url.strip()]

    single_url = os.environ.get("AGENTDID_WEBVH_EXTERNAL_URL")
    if single_url and single_url.strip():
        return [single_url.strip()]

    return []


def _is_truthy_env(name: str) -> bool:
    value = os.environ.get(name)
    if not value:
        return False
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _manifest_path() -> Path:
    explicit = os.environ.get("AGENTDID_WEBVH_EXTERNAL_MANIFEST")
    if not explicit:
        return DEFAULT_MANIFEST_PATH

    path = Path(explicit)
    if path.is_absolute():
        return path

    return REPO_ROOT / path


def _load_manifest_target() -> dict[str, object]:
    manifest_path = _manifest_path()

    try:
      manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except Exception as exc:  # noqa: BLE001
      raise RuntimeError(f"No se pudo leer el manifest de smoke externo ({manifest_path}): {exc}") from exc

    target_name = os.environ.get("AGENTDID_WEBVH_EXTERNAL_TARGET") or manifest.get("defaultTarget")
    targets = manifest.get("targets") if isinstance(manifest, dict) else None
    target = targets.get(target_name) if isinstance(targets, dict) else None

    if not isinstance(target, dict):
        raise RuntimeError(f"Target externo no encontrado en el manifest: {target_name}")

    candidate_urls = target.get("candidateUrls")
    if (
        not isinstance(candidate_urls, list)
        or not candidate_urls
        or not all(isinstance(url, str) for url in candidate_urls)
    ):
        raise RuntimeError(f"El target externo {target_name} no define candidateUrls.")

    expected_did = target.get("did")
    if not isinstance(expected_did, str) or not expected_did.strip():
        raise RuntimeError(f"El target externo {target_name} no define un did esperado.")

    return {
        "candidate_urls": candidate_urls,
        "expected_did": expected_did,
        "manifest_path": str(manifest_path),
        "target_name": target_name,
    }


def _resolve_external_target() -> dict[str, object]:
    candidate_urls = _candidate_urls()
    if candidate_urls:
        return {
            "candidate_urls": candidate_urls,
            "expected_did": os.environ.get("AGENTDID_WEBVH_EXTERNAL_DID"),
            "source_label": "env override",
        }

    manifest_target = _load_manifest_target()
    return {
        "candidate_urls": manifest_target["candidate_urls"],
        "expected_did": os.environ.get("AGENTDID_WEBVH_EXTERNAL_DID") or manifest_target["expected_did"],
        "source_label": f"manifest:{manifest_target['target_name']}",
        "manifest_path": manifest_target["manifest_path"],
    }


async def main() -> int:
    external_target = _resolve_external_target()
    timeout_ms = int(os.environ.get("AGENTDID_WEBVH_EXTERNAL_TIMEOUT_MS", "15000"))
    allow_private_targets = _is_truthy_env("AGENTDID_WEBVH_EXTERNAL_ALLOW_PRIVATE_TARGETS")

    async with httpx.AsyncClient(timeout=timeout_ms / 1000) as http_client:
        source = WebvhDIDDocumentSource(
            WebvhDIDDocumentSourceConfig(
                reference_to_urls=lambda _document_ref: external_target["candidate_urls"],
                http_client=http_client,
                http_security=HttpTargetValidationOptions(allow_private_targets=allow_private_targets),
            )
        )

        resolved = await source.get_by_reference(external_target["candidate_urls"][0])
        if resolved is None:
            raise RuntimeError(
                "No se pudo resolver did:webvh desde los endpoints externos: "
                f"{', '.join(external_target['candidate_urls'])}"
            )

    if not resolved.id.startswith("did:webvh:"):
        raise RuntimeError(f"El documento externo no resolvió un DID did:webvh: {resolved.id}")

    if external_target["expected_did"] and resolved.id != external_target["expected_did"]:
        raise RuntimeError(
            f"DID resuelto inesperado. Esperado={external_target['expected_did']} actual={resolved.id}"
        )

    if not resolved.verification_method:
        raise RuntimeError("El documento externo no expone verificationMethod.")

    if not resolved.assertion_method:
        raise RuntimeError("El documento externo no expone assertionMethod.")

    print("✅ External did:webvh smoke completed successfully")
    print(f"Resolved DID: {resolved.id}")
    print(f"Updated: {resolved.updated}")
    print(f"Source: {external_target['source_label']}")
    manifest_path = external_target.get("manifest_path")
    if isinstance(manifest_path, str):
        print(f"Manifest: {manifest_path}")
    print(f"Candidate URLs: {', '.join(external_target['candidate_urls'])}")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(asyncio.run(main()))
    except Exception as exc:  # noqa: BLE001
        print("❌ External did:webvh smoke failed", file=sys.stderr)
        print(str(exc), file=sys.stderr)
        sys.exit(1)
