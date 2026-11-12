"""RFC 9421 HTTP Message Signatures (parity: sdk/tests/HttpSignatures.test.ts, NonceStore.test.ts and
the HTTP signature tests in AgentIdentity.test.ts)."""

from __future__ import annotations

import base64
import hashlib
from collections.abc import Callable

import pytest
from nacl.signing import SigningKey

from agent_did_sdk import (
    AGENT_DID_HTTP_SIGNATURE_COMPONENTS,
    AGENT_DID_HTTP_SIGNATURE_TAG,
    AgentIdentity,
    AgentIdentityConfig,
    CreateAgentParams,
    InMemoryNonceStore,
    LocalKeySigner,
    SignHttpRequestParams,
    VerifyHttpRequestSignatureParams,
)
from agent_did_sdk.core.http_profile import compute_content_digest
from agent_did_sdk.core.http_signatures import (
    HttpRequestLike,
    HttpSignatureError,
    SignatureInput,
    build_signature_base,
    parse_signature_header,
    parse_signature_input_header,
    serialize_signature_input,
)

# RFC 9421 Appendix B.1.4 (test-key-ed25519) and B.2 (test-request).
TEST_KEY_D = "n4Ni-HpISpVObnQMW0wOhCKROaIKqKtW_2ZYb2p9KcU"
TEST_KEY_X = "JrQLj5P_89iXES9-vFgrIy29clF9CC_oPPsw3c5D0bs"
TEST_REQUEST = HttpRequestLike(
    method="POST",
    url="https://example.com/foo?param=Value&Pet=dog",
    headers={
        "Host": "example.com",
        "Date": "Tue, 20 Apr 2021 02:07:55 GMT",
        "Content-Type": "application/json",
        "Content-Digest": (
            "sha-512=:WZDPaVn/7XgHaAy8pmojAkGWoRx2UFChF41A2svX+TaPm+AbwAgBWnrIiYllu7BNNyealdVLvRwEmTHWXvJwew==:"
        ),
        "Content-Length": "18",
    },
)
B26_INPUT = (
    'sig-b26=("date" "@method" "@path" "@authority" "content-type" "content-length")'
    ';created=1618884473;keyid="test-key-ed25519"'
)
B26_SIGNATURE = (
    "sig-b26=:wqcAqbmYJ2ji2glfAMaRy4gruYYnx2nEFN2HN6jrnDnQCK1u02Gb04v9EDgwUPiu4A0w6vuQv5lIp5WPpBKRCw==:"
)
B26_BASE = "\n".join([
    '"date": Tue, 20 Apr 2021 02:07:55 GMT',
    '"@method": POST',
    '"@path": /foo',
    '"@authority": example.com',
    '"content-type": application/json',
    '"content-length": 18',
    '"@signature-params": ("date" "@method" "@path" "@authority" "content-type" "content-length")'
    ';created=1618884473;keyid="test-key-ed25519"',
])


def _b64url(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


class TestRfc9421Primitives:
    def test_reproduces_appendix_b26_base_and_signature_byte_for_byte(self) -> None:
        signature_input = parse_signature_input_header(B26_INPUT)["sig-b26"]
        base = build_signature_base(TEST_REQUEST, signature_input)
        assert base == B26_BASE

        key = SigningKey(_b64url(TEST_KEY_D))
        assert bytes(key.verify_key) == _b64url(TEST_KEY_X)
        assert key.sign(base.encode()).signature == parse_signature_header(B26_SIGNATURE)["sig-b26"]

    def test_derives_query_target_uri_scheme_and_request_target(self) -> None:
        signature_input = parse_signature_input_header(
            's=("@query" "@target-uri" "@scheme" "@request-target");created=1'
        )
        assert build_signature_base(TEST_REQUEST, signature_input["s"]).split("\n")[:4] == [
            '"@query": ?param=Value&Pet=dog',
            '"@target-uri": https://example.com/foo?param=Value&Pet=dog',
            '"@scheme": https',
            '"@request-target": /foo?param=Value&Pet=dog',
        ]
        no_query = HttpRequestLike(method="GET", url="https://example.com/", headers={})
        no_query_input = parse_signature_input_header('s=("@query")')["s"]
        assert build_signature_base(no_query, no_query_input).startswith('"@query": ?\n')

    def test_round_trips_parameters_with_canonical_serialization(self) -> None:
        value = (
            '("@method" "content-digest");created=1;expires=2;nonce="a\\"b\\\\c";keyid="did:x#k"'
            ';alg="ed25519";tag="agent-did";flag;neg=-5;tok=abc'
        )
        assert serialize_signature_input(parse_signature_input_header(f"sig1={value}")["sig1"]) == value

    def test_parses_dictionaries_with_several_members_and_whitespace(self) -> None:
        parsed = parse_signature_input_header('a=("@method");created=1 ,  b=("date");created=2')
        assert list(parsed) == ["a", "b"]
        assert parse_signature_header("a=:AAAA:, b=:AQID:")["b"] == bytes([1, 2, 3])

    @pytest.mark.parametrize(
        "value",
        [
            's=("@method);created=1',
            's=("a\\n")',
            's=("@query-param";name="x")',
            's=("@method");created=1;created=2',
            's=("@method");created=1.5',
            'S=("@method")',
            's=("@method"),',
            "s",
            "s=1",
            "s=(@method)",
            's=("@method");created=:AAAA:',
            's=("@method");created=@1',
        ],
    )
    def test_rejects_malformed_signature_input(self, value: str) -> None:
        with pytest.raises(HttpSignatureError):
            parse_signature_input_header(value)

    def test_does_not_mistake_semicolons_inside_strings_for_parameters(self) -> None:
        parsed = parse_signature_input_header('s=("a;b");keyid="x;\\"y;z";tag="t"')
        assert parsed["s"].params == [("keyid", 'x;"y;z'), ("tag", "t")]

    @pytest.mark.parametrize("value", ["s=:@@@@:", "s=:AAAA", 's="x"', "s=:AAAA:;x=1", "s=(:AAAA:)"])
    def test_rejects_malformed_signature(self, value: str) -> None:
        with pytest.raises(HttpSignatureError):
            parse_signature_header(value)

    @pytest.mark.parametrize(
        "value", ['s=("x-missing")', 's=("@method" "@method")', 's=("Date")', 's=("@status")']
    )
    def test_rejects_an_invalid_signature_base(self, value: str) -> None:
        with pytest.raises(HttpSignatureError):
            build_signature_base(TEST_REQUEST, parse_signature_input_header(value)["s"])

    def test_combines_repeated_header_lines_and_trims_values(self) -> None:
        request = HttpRequestLike(method="GET", url="https://example.com/", headers={"X-Multi": ["  a ", "b"]})
        assert build_signature_base(request, parse_signature_input_header('s=("x-multi")')["s"]).startswith(
            '"x-multi": a, b\n'
        )


class TestInMemoryNonceStore:
    async def test_accepts_a_key_once_until_it_expires(self) -> None:
        now = [1_000]
        store = InMemoryNonceStore(now=lambda: now[0])
        assert await store.check_and_store("k", 1_010) is True
        assert await store.check_and_store("k", 1_010) is False
        now[0] = 1_011
        assert await store.check_and_store("k", 1_020) is True

    async def test_purges_expired_entries_and_fails_closed_when_full(self) -> None:
        now = [1_000]
        store = InMemoryNonceStore(max_entries=2, now=lambda: now[0])
        assert await store.check_and_store("a", 1_005) is True
        assert await store.check_and_store("b", 1_100) is True
        assert await store.check_and_store("c", 1_100) is False
        now[0] = 1_006
        assert await store.check_and_store("c", 1_100) is True
        assert store.size == 2


REQUEST = {"method": "POST", "url": "https://api.example.com/v1/data?x=1", "body": "{}"}


@pytest.fixture()
def identity() -> AgentIdentity:
    return AgentIdentity(AgentIdentityConfig(controller_signer=LocalKeySigner.generate()[0]))


async def _signed(identity: AgentIdentity, name: str = "HttpBot") -> tuple[str, str, dict[str, str]]:
    result = await identity.create(CreateAgentParams(name=name, core_model="m", system_prompt="p"))
    headers = await identity.sign_http_request(
        SignHttpRequestParams(**REQUEST, agent_private_key=result.agent_private_key, agent_did=result.document.id,
            verification_method_id=f"{result.document.id}#key-1")
    )
    return result.document.id, result.agent_private_key, headers


async def _verify(headers: dict[str, str], **overrides: object) -> bool:
    params = {**REQUEST, **overrides}
    return await AgentIdentity.verify_http_request_signature(
        VerifyHttpRequestSignatureParams(headers=headers, **params)  # type: ignore[arg-type]
    )


class TestAgentDidHttpSignatureProfile:
    async def test_signs_the_profile_with_nonce_expires_and_tag(self, identity: AgentIdentity) -> None:
        result = await identity.create(CreateAgentParams(name="ProfileBot", core_model="m", system_prompt="p"))
        headers = await identity.sign_http_request(
            SignHttpRequestParams(
                method="post",
                url=REQUEST["url"],
                body=REQUEST["body"],
                agent_private_key=result.agent_private_key,
                agent_did=result.document.id, verification_method_id=f"{result.document.id}#key-1",
                expires_in_seconds=60,
            )
        )

        assert "X-Request-Nonce" not in headers
        signature_input = parse_signature_input_header(headers["Signature-Input"])["sig1"]
        assert signature_input.components == list(AGENT_DID_HTTP_SIGNATURE_COMPONENTS)
        assert [name for name, _ in signature_input.params] == ["created", "expires", "nonce", "keyid", "alg", "tag"]
        params = dict(signature_input.params)
        assert params["expires"] == params["created"] + 60  # type: ignore[operator]
        assert isinstance(params["nonce"], str) and len(params["nonce"]) == 32
        assert params["keyid"] == f"{result.document.id}#key-1"
        assert params["alg"] == "ed25519"
        assert params["tag"] == "agent-did"
        assert await _verify(headers) is True

    async def test_rejects_a_replay_through_the_built_in_nonce_store(self, identity: AgentIdentity) -> None:
        _, private_key, headers = await _signed(identity)
        assert await _verify(headers) is True
        assert await _verify(headers) is False

        did, _, second = await _signed(identity, "SecondBot")
        store = InMemoryNonceStore()
        assert await _verify(second, nonce_store=store) is True
        assert store.size == 1
        assert await _verify(second, nonce_store=store) is False

    async def test_does_not_record_nonces_of_invalid_signatures(self, identity: AgentIdentity) -> None:
        _, _, headers = await _signed(identity)
        store = InMemoryNonceStore()

        assert await _verify(headers, body='{"amount":2}', nonce_store=store) is False
        forged = {**headers, "Signature": f"sig1=:{base64.b64encode(bytes(64)).decode()}:"}
        assert await _verify(forged, nonce_store=store) is False
        assert store.size == 0
        assert await _verify(headers, nonce_store=store) is True

    @pytest.mark.parametrize(
        "mutate",
        [
            lambda v: __import__("re").sub(r';nonce="[^"]*"', "", v),
            lambda v: v.replace(';tag="agent-did"', ""),
            lambda v: v.replace('tag="agent-did"', 'tag="web-bot-auth"'),
            lambda v: v.replace(';alg="ed25519"', ""),
            lambda v: __import__("re").sub(r";expires=\d+", "", v),
            lambda v: v.replace(' "signature-agent"', ""),
            lambda v: v.replace(' "@query"', ""),
            lambda v: v.replace("sig1=(", "sig1=["),
        ],
        ids=[
            "missing-nonce", "missing-tag", "foreign-tag", "missing-alg", "missing-expires",
            "dropped-signature-agent", "dropped-query", "malformed-dictionary",
        ],
    )
    async def test_rejects_profile_violations(self, identity: AgentIdentity, mutate: Callable[[str], str]) -> None:
        _, _, headers = await _signed(identity)
        headers["Signature-Input"] = mutate(headers["Signature-Input"])
        assert await _verify(headers) is False

    @pytest.mark.parametrize(
        "change",
        [
            {"method": "PUT"},
            {"url": "https://evil.example.com/v1/data?x=1"},
            {"url": "https://api.example.com/v1/admin?x=1"},
            {"url": "https://api.example.com/v1/data?x=2"},
        ],
        ids=["method", "host", "path", "query"],
    )
    async def test_rejects_a_request_that_differs_from_the_signed_one(
        self, identity: AgentIdentity, change: dict[str, str]
    ) -> None:
        _, _, headers = await _signed(identity)
        assert await _verify(headers, **change) is False

    async def test_rejects_a_signature_agent_swapped_to_another_did(self, identity: AgentIdentity) -> None:
        victim = await identity.create(CreateAgentParams(name="VictimBot", core_model="m", system_prompt="p"))
        _, _, headers = await _signed(identity, "AttackerBot")
        assert await _verify({**headers, "Signature-Agent": victim.document.id}) is False

    async def test_verifies_additional_covered_components_only_when_signed(self, identity: AgentIdentity) -> None:
        result = await identity.create(CreateAgentParams(name="ExtraBot", core_model="m", system_prompt="p"))
        signed = await identity.sign_http_request(
            SignHttpRequestParams(**REQUEST, agent_private_key=result.agent_private_key, agent_did=result.document.id,
                verification_method_id=f"{result.document.id}#key-1")
        )
        created = int(dict(parse_signature_input_header(signed["Signature-Input"])["sig1"].params)["created"])  # type: ignore[call-overload]
        headers = {
            "Signature-Agent": result.document.id,
            "Date": signed["Date"],
            "Content-Digest": signed["Content-Digest"],
            "X-Extra": "covered too",
        }
        signature_input = SignatureInput(
            components=[*AGENT_DID_HTTP_SIGNATURE_COMPONENTS, "x-extra"],
            params=[
                ("created", created),
                ("expires", created + 30),
                ("nonce", "f" * 32),
                ("keyid", f"{result.document.id}#key-1"),
                ("alg", "ed25519"),
                ("tag", AGENT_DID_HTTP_SIGNATURE_TAG),
            ],
        )
        request = HttpRequestLike(method="POST", url=REQUEST["url"], headers=headers)
        base = build_signature_base(request, signature_input)
        signature = SigningKey(bytes.fromhex(result.agent_private_key)).sign(base.encode()).signature
        headers["Signature-Input"] = f"sig-a={serialize_signature_input(signature_input)}"
        headers["Signature"] = f"sig-a=:{base64.b64encode(signature).decode()}:"

        assert await _verify(headers) is True
        tampered = {**headers, "X-Extra": "changed"}
        tampered["Signature-Input"] = tampered["Signature-Input"].replace("f" * 32, "e" * 32)
        assert await _verify(tampered) is False

    def test_content_digest_is_rfc9530_sha256(self) -> None:
        digest = base64.b64encode(hashlib.sha256(b"{}").digest()).decode()
        assert compute_content_digest("{}") == f"sha-256=:{digest}:"


class TestRfc9530ContentDigest:
    """RFC 9530 example (SHA-256 of ``{"hello": "world"}``); parity: sdk/tests/HttpSignatures.test.ts."""

    def test_matches_the_rfc_9530_sha256_example(self) -> None:
        assert (
            compute_content_digest('{"hello": "world"}')
            == "sha-256=:X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=:"
        )

    def test_absent_body_is_the_sha256_of_zero_bytes(self) -> None:
        assert compute_content_digest(None) == "sha-256=:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=:"
