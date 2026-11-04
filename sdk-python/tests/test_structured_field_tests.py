"""httpwg/structured-field-tests (RFC 8941) against the Signature-Input and Signature parsers.

Runs only when STRUCTURED_FIELD_TESTS_DIR points at a checkout of the suite at the
commit pinned in fixtures/structured-field-tests.json (the CI workflow
``ci-structured-field-tests.yml`` does this). TypeScript parity:
sdk/tests/StructuredFieldTests.test.ts.
"""

from __future__ import annotations

import base64
import json
import os
import pathlib
import subprocess
from typing import Any

import pytest

from agent_did_sdk.core.http_signatures import (
    HttpSignatureError,
    Token,
    parse_signature_header,
    parse_signature_input_header,
)

_PIN: dict[str, Any] = json.loads(
    (pathlib.Path(__file__).resolve().parents[2] / "fixtures" / "structured-field-tests.json").read_text(
        encoding="utf-8"
    )
)
_SUITE_DIR = os.environ.get("STRUCTURED_FIELD_TESTS_DIR")


def _is_typed(value: Any, type_name: str) -> bool:
    return isinstance(value, dict) and value.get("__type") == type_name


def _expected_signature(expected: list[Any]) -> list[tuple[str, bytes]] | None:
    """What the Signature parser must return, or None when the input is outside its subset."""
    result: list[tuple[str, bytes]] = []
    for label, (value, params) in expected:
        if not _is_typed(value, "binary") or params:
            return None
        result.append((label, base64.b32decode(value["value"])))
    return result


def _expected_signature_input(expected: list[Any]) -> list[tuple[str, list[str], list[tuple[str, Any]]]] | None:
    """What the Signature-Input parser must return, or None when outside its subset."""
    result: list[tuple[str, list[str], list[tuple[str, Any]]]] = []
    for label, (value, params) in expected:
        if not isinstance(value, list):
            return None
        components: list[str] = []
        for item, item_params in value:
            if not isinstance(item, str) or item_params:
                return None
            components.append(item)
        mapped: list[tuple[str, Any]] = []
        for name, param in params:
            if isinstance(param, bool | str | int):
                mapped.append((name, param))
            elif _is_typed(param, "token"):
                mapped.append((name, Token(param["value"])))
            else:
                return None
        result.append((label, components, mapped))
    return result


def _collect() -> list[Any]:
    if not _SUITE_DIR:
        return []
    cases = []
    for file in _PIN["files"]:
        for test in json.loads((pathlib.Path(_SUITE_DIR) / file).read_text(encoding="utf-8")):
            if test["header_type"] == "dictionary":
                cases.append(pytest.param(f"{file}: {test['name']}", test, id=f"{file}: {test['name']}"))
    return cases


_CASES = _collect()
pytestmark = pytest.mark.skipif(not _SUITE_DIR, reason="STRUCTURED_FIELD_TESTS_DIR is not set")


def test_runs_against_pinned_commit_and_exceptions_name_real_cases() -> None:
    assert _SUITE_DIR is not None
    if (pathlib.Path(_SUITE_DIR) / ".git").exists():
        head = subprocess.run(
            ["git", "-C", _SUITE_DIR, "rev-parse", "HEAD"], check=True, capture_output=True, text=True
        ).stdout.strip()
        assert head == _PIN["commit"]
    assert len(_CASES) > 400
    names = {case.values[0] for case in _CASES}
    for name, reason in _PIN["exceptions"].items():
        assert name in names
        assert len(reason) > 10


@pytest.mark.parametrize(("name", "test"), _CASES)
def test_dictionary_case(name: str, test: dict[str, Any]) -> None:
    if test.get("can_fail") or name in _PIN["exceptions"]:
        pytest.skip("optional or documented exception")
    raw = ",".join(test["raw"])
    if test.get("must_fail"):
        with pytest.raises(HttpSignatureError):
            parse_signature_header(raw)
        with pytest.raises(HttpSignatureError):
            parse_signature_input_header(raw)
        return

    expected = test["expected"]
    signature = _expected_signature(expected)
    if signature is None:
        with pytest.raises(HttpSignatureError):
            parse_signature_header(raw)
    else:
        assert list(parse_signature_header(raw).items()) == signature

    signature_input = _expected_signature_input(expected)
    if signature_input is None:
        with pytest.raises(HttpSignatureError):
            parse_signature_input_header(raw)
    else:
        members = parse_signature_input_header(raw).items()
        parsed = [(label, member.components, member.params) for label, member in members]
        assert parsed == signature_input
