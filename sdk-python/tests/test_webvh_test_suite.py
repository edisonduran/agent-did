"""DIF didwebvh-test-suite against the did:webvh adapter (ADR-002, condition 6).

Runs only when DIDWEBVH_TEST_SUITE_DIR points at a checkout of the suite at the
commit pinned in fixtures/didwebvh-test-suite.json (the CI workflow
``ci-didwebvh-test-suite.yml`` does this). TypeScript parity:
sdk/tests/WebvhTestSuite.test.ts.
"""

from __future__ import annotations

import json
import os
import pathlib
import re
import subprocess
from typing import Any

import pytest

from agent_did_sdk.webvh.adapter import DidWebvhError, derive_did_webvh_log_url, resolve_did_webvh_log

_EXPECTATIONS: dict[str, Any] = json.loads(
    (pathlib.Path(__file__).resolve().parents[2] / "fixtures" / "didwebvh-test-suite.json").read_text(encoding="utf-8")
)
_SUITE_DIR = os.environ.get("DIDWEBVH_TEST_SUITE_DIR")
_VECTORS = pathlib.Path(_SUITE_DIR) / "vectors" if _SUITE_DIR else None
_RESULT_FILE = re.compile(r"^resolutionResult(?:\.(\d+))?\.json$")
_IMPLICIT_SERVICE = re.compile(r"#(files|whois)$")
_SCRIPT_DID = re.compile(r'^\s+did:\s*"([^"]+)"', re.MULTILINE)
# A valid base58btc SCID, substituted to show the host/path rules (not the SCID) reject the DID.
_VALID_SCID = "QmUy89VrfryQ254CeHZzQfmcKqByPoKNGqYykP3SeXuegQ"

requires_suite = pytest.mark.skipif(_SUITE_DIR is None, reason="DIDWEBVH_TEST_SUITE_DIR is not set")


def _dirs(path: pathlib.Path) -> list[pathlib.Path]:
    return sorted(child for child in path.iterdir() if child.is_dir())


def _read_log(path: pathlib.Path) -> str | None:
    file = path / "did.jsonl"
    if not file.exists():
        return None
    text = file.read_text(encoding="utf-8")
    return text if text.strip() else None


def _read_witness_file(path: pathlib.Path) -> str | None:
    file = path / "did-witness.json"
    return file.read_text(encoding="utf-8") if file.exists() else None


def _collect() -> tuple[list[str], list[Any], list[Any], list[Any], list[Any]]:
    scenarios: list[str] = []
    positive: list[Any] = []
    witnessed: list[Any] = []
    negative: list[Any] = []
    did_url_negative: list[Any] = []
    if _VECTORS is None:
        return scenarios, positive, witnessed, negative, did_url_negative

    for scenario_dir in _dirs(_VECTORS):
        scenario = scenario_dir.name
        scenarios.append(scenario)
        if scenario in _EXPECTATIONS["didUrlNegative"]:
            script = (scenario_dir / "script.yaml").read_text(encoding="utf-8")
            for did in _SCRIPT_DID.findall(script):
                did_url_negative.append(pytest.param(did, id=f"{scenario} {did}"))
            continue
        for impl_dir in _dirs(scenario_dir):
            log = _read_log(impl_dir)
            if log is None:
                continue
            name = f"{scenario}/{impl_dir.name}"
            witness_file = _read_witness_file(impl_dir)
            if scenario.startswith("negative-"):
                negative.append(pytest.param(log, id=name))
            else:
                if scenario in _EXPECTATIONS["witnessed"]:
                    assert witness_file is not None, f"{name} has no did-witness.json"
                    witnessed.append(pytest.param(log, witness_file, id=name))
                for result in sorted(impl_dir.iterdir()):
                    match = _RESULT_FILE.match(result.name)
                    if not match:
                        continue
                    expected = json.loads(result.read_text(encoding="utf-8"))
                    version = int(match.group(1)) if match.group(1) else None
                    case_name = f"{name}/{result.name}"
                    positive.append(
                        pytest.param(case_name, log, witness_file, expected, version, id=case_name)
                    )
    return scenarios, positive, witnessed, negative, did_url_negative


_SCENARIOS, _POSITIVE, _WITNESSED, _NEGATIVE, _DID_URL_NEGATIVE = _collect()


def _without_implicit_services(document: dict[str, Any]) -> dict[str, Any]:
    """Drop the implicit #files / #whois services, whose serialization differs between resolvers."""
    copy = dict(document)
    services = copy.get("service")
    if isinstance(services, list):
        kept = [service for service in services if not _IMPLICIT_SERVICE.search(str(service.get("id", "")))]
        if kept:
            copy["service"] = kept
        else:
            del copy["service"]
    return copy


@requires_suite
def test_runs_against_pinned_commit_and_classifies_every_scenario() -> None:
    assert _SUITE_DIR is not None
    if (pathlib.Path(_SUITE_DIR) / ".git").exists():
        head = subprocess.run(
            ["git", "-C", _SUITE_DIR, "rev-parse", "HEAD"], check=True, capture_output=True, text=True
        ).stdout.strip()
        assert head == _EXPECTATIONS["commit"]

    for listed in [*_EXPECTATIONS["witnessed"], *_EXPECTATIONS["didUrlNegative"]]:
        assert listed in _SCENARIOS
    positive_names = {case.values[0] for case in _POSITIVE}
    for listed in _EXPECTATIONS["vectorDefects"]:
        assert listed in positive_names

    covered = {
        re.split(r"[/ ]", case.id)[0] for case in [*_POSITIVE, *_NEGATIVE, *_DID_URL_NEGATIVE]
    }
    unclassified = [s for s in _SCENARIOS if s not in covered]
    assert unclassified == []


@requires_suite
@pytest.mark.parametrize(("name", "log", "witness_file", "expected", "version_number"), _POSITIVE)
async def test_resolves(
    name: str, log: str, witness_file: str | None, expected: dict[str, Any], version_number: int | None
) -> None:
    resolved = await resolve_did_webvh_log(log, version_number=version_number, witness_file=witness_file)
    entries = [json.loads(line) for line in log.splitlines() if line.strip()]
    selected = entries[(version_number or len(entries)) - 1]

    # Valid DIDs from every implementation must map to a log URL.
    assert re.fullmatch(r"https://[a-z0-9.-]+(:\d+)?/.*did\.jsonl", derive_did_webvh_log_url(resolved.did))
    assert resolved.metadata.version_id == selected["versionId"]
    assert resolved.metadata.version_time == selected["versionTime"]
    assert resolved.metadata.updated == selected["versionTime"]
    assert resolved.metadata.created == entries[0]["versionTime"]
    assert resolved.metadata.scid == entries[0]["parameters"]["scid"]
    assert resolved.metadata.deactivated is ((expected.get("didDocumentMetadata") or {}).get("deactivated") is True)

    if name in _EXPECTATIONS["vectorDefects"]:
        # Keep the exception honest: it must be removed once upstream fixes the vector.
        assert expected["didDocumentMetadata"]["versionId"] != selected["versionId"]
    elif expected.get("didDocument") is not None:
        assert _without_implicit_services(resolved.document) == _without_implicit_services(expected["didDocument"])


@requires_suite
@pytest.mark.parametrize(("log", "witness_file"), _WITNESSED)
async def test_witness_logs_fail_closed_without_enough_approvals(log: str, witness_file: str) -> None:
    # No did-witness.json, an empty one, and each entry with one proof dropped.
    with pytest.raises(DidWebvhError):
        await resolve_did_webvh_log(log)
    with pytest.raises(DidWebvhError):
        await resolve_did_webvh_log(log, witness_file="[]")
    reduced = [{**entry, "proof": entry["proof"][1:]} for entry in json.loads(witness_file)]
    with pytest.raises(DidWebvhError):
        await resolve_did_webvh_log(log, witness_file=json.dumps(reduced))


@requires_suite
@pytest.mark.parametrize("log", _NEGATIVE)
async def test_rejects_negative_vector(log: str) -> None:
    with pytest.raises(DidWebvhError):
        await resolve_did_webvh_log(log)


@requires_suite
@pytest.mark.parametrize("did", _DID_URL_NEGATIVE)
def test_rejects_did_url_vector(did: str) -> None:
    with_valid_scid = re.sub(r"^did:webvh:[^:]+:", f"did:webvh:{_VALID_SCID}:", did)
    for candidate in (did, with_valid_scid):
        with pytest.raises(DidWebvhError):
            derive_did_webvh_log_url(candidate)


def test_expectations_pin_a_full_commit_with_reasons() -> None:
    assert re.fullmatch(r"[0-9a-f]{40}", _EXPECTATIONS["commit"])
    for section in ("witnessed", "didUrlNegative", "vectorDefects"):
        assert all(reason for reason in _EXPECTATIONS[section].values())
