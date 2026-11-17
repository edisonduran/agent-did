"""Edge cases of the RFC 9421 module that the protocol tests do not reach (C-QA-2).

TypeScript parity: sdk/tests/HttpSignatureEdgeCases.test.ts.
"""

from __future__ import annotations

from typing import Any

import pytest

from agent_did_sdk.core.http_signatures import (
    HttpRequestLike,
    HttpSignatureError,
    KeyedComponent,
    SignatureInput,
    Token,
    build_signature_base,
    parse_signature_input_header,
    request_url_form_problem,
    serialize_signature,
    serialize_signature_input,
)


def _input(params: list[tuple[str, Any]], components: list[Any] | None = None) -> str:
    return serialize_signature_input(SignatureInput(components=components or ["@method"], params=params))


def test_serializes_booleans_and_tokens_and_rejects_what_structured_fields_cannot_carry() -> None:
    assert _input([("flag", True), ("off", False), ("alg", Token("ed25519"))]) == '("@method");flag;off=?0;alg=ed25519'
    with pytest.raises(HttpSignatureError):
        _input([("nonce", "café")])
    with pytest.raises(HttpSignatureError, match="15 digits"):
        _input([("created", 10**16)])
    with pytest.raises(HttpSignatureError, match="token"):
        _input([("alg", Token("1bad"))])
    with pytest.raises(HttpSignatureError, match="key"):
        _input([("Bad", 1)])
    with pytest.raises(HttpSignatureError, match="label"):
        serialize_signature("Sig", bytes(64))


def test_parse_ignores_a_semicolon_inside_a_string_and_rejects_non_string_components() -> None:
    parsed = parse_signature_input_header('sig1=("@method");nonce="a;b";tag="agent-did"')
    assert parsed["sig1"].params == [("nonce", "a;b"), ("tag", "agent-did")]
    with pytest.raises(HttpSignatureError, match="must be strings"):
        parse_signature_input_header('sig1=(1 "@method")')
    with pytest.raises(HttpSignatureError, match="must be strings"):
        parse_signature_input_header("sig1=(tok)")


_REQUEST = HttpRequestLike(
    method="GET", url="https://example.com/a", headers={"date": "x", "agent-did": 'sig1="did:x"'}
)
_PARAMS: list[tuple[str, Any]] = [("tag", "agent-did")]


def test_build_signature_base_rejects_bad_headers_components_and_urls() -> None:
    with pytest.raises(HttpSignatureError, match="line breaks"):
        build_signature_base(
            HttpRequestLike(method="GET", url="https://example.com/a", headers={"date": "a\nb"}),
            SignatureInput(components=["date"], params=_PARAMS),
        )
    with pytest.raises(HttpSignatureError, match="only to header fields"):
        build_signature_base(_REQUEST, SignatureInput(components=[KeyedComponent("@method", "sig1")], params=_PARAMS))
    with pytest.raises(HttpSignatureError, match="member is missing"):
        build_signature_base(_REQUEST, SignatureInput(components=[KeyedComponent("agent-did", "sig2")], params=_PARAMS))
    with pytest.raises(HttpSignatureError, match="normalized form"):
        build_signature_base(
            HttpRequestLike(method="GET", url="https://example.com/./a", headers={}),
            SignatureInput(components=["@path"], params=_PARAMS),
        )


def test_authority_of_an_ipv6_host_keeps_its_brackets() -> None:
    base = build_signature_base(
        HttpRequestLike(method="GET", url="https://[1:2:3:4:5:6:7:8]/", headers={}),
        SignatureInput(components=["@authority"], params=_PARAMS),
    )
    assert base.startswith('"@authority": [1:2:3:4:5:6:7:8]\n')


def test_request_url_form_problems() -> None:
    assert request_url_form_problem("https://example.com:65536/") == "its port is out of range"
    assert request_url_form_problem("https://[1:2:3:4:5:6:7:8:9]/") == "its IPv6 host is not in canonical form"
    assert request_url_form_problem("https://[1:2:3:4:5:6:7:8]/") is None
    assert request_url_form_problem("https://example..com/") == "its host has an empty label"
