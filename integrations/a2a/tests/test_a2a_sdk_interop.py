"""Cross-check against the official A2A Python SDK (``a2a-sdk``, dev dependency): Agent Card signatures in both
directions (A2A 1.0 §8.4) and the JSON shapes of the cards and JSON-RPC requests this integration builds.

``a2a-sdk`` is an independent implementation of A2A 1.0: its card resolver rebuilds the card from its Protocol Buffer
form (``parse_agent_card``), and its verifier canonicalizes that form. Known differences of ``a2a-sdk`` 1.3.0 from
A2A 1.0 §8.4.1, kept out of these cards: it drops empty ``REQUIRED`` members (``"description": ""``, ``"skills": []``)
and empty messages, including a set oneof member such as ``{"mtlsSecurityScheme": {}}`` (with the map entry that holds
it), which the Agent-DID SDKs keep (Protocol Buffer field presence).
"""

from __future__ import annotations

import json
import os
import pathlib
import warnings
from typing import Any

import pytest

# CI sets AGENT_DID_REQUIRE_A2A_SDK=1 so a missing a2a-sdk fails instead of skipping.
if not os.environ.get("AGENT_DID_REQUIRE_A2A_SDK"):
    pytest.importorskip("a2a.utils.signing")

from a2a.client.card_resolver import parse_agent_card  # noqa: E402
from a2a.types import GetTaskRequest, SendMessageRequest  # noqa: E402
from a2a.utils.proto_utils import validate_proto_required_fields  # noqa: E402
from a2a.utils.signing import (  # noqa: E402
    InvalidSignaturesError,
    create_agent_card_signer,
    create_signature_verifier,
)
from agent_did_sdk import (  # noqa: E402
    AgentIdentity,
    AgentIdentityConfig,
    CreateAgentParams,
    CreateAgentResult,
    InMemoryAgentRegistry,
    LocalKeySigner,
)
from agent_did_sdk.core.agent_card import bytes_to_base64url  # noqa: E402
from agent_did_sdk.crypto.multibase import decode_public_key_multibase  # noqa: E402
from google.protobuf.json_format import MessageToDict, ParseDict  # noqa: E402
from jwt import PyJWK  # noqa: E402

from agent_did_a2a import (  # noqa: E402
    A2AAgentCapabilities,
    A2AAgentProvider,
    A2ASkill,
    AgentDidA2AConfig,
    AgentDidA2AOAuthClientCredentials,
    build_get_task_request,
    build_send_message_request,
    create_agent_did_a2a_integration,
    text_message,
)
from agent_did_a2a.integration import AgentDidA2AIntegration  # noqa: E402

VECTORS: dict[str, Any] = json.loads(
    (pathlib.Path(__file__).resolve().parents[3] / "fixtures" / "composition-contract-vectors.json").read_text(
        encoding="utf-8"
    )
)
SKILLS = [
    A2ASkill(id="cards", name="Cards", description="Answers questions about cards", tags=["cards"], examples=[]),
]


def _public_jwk(public_key: bytes) -> PyJWK:
    return PyJWK({"kty": "OKP", "crv": "Ed25519", "x": bytes_to_base64url(public_key)}, algorithm="EdDSA")


def _verifier(keys: dict[str, bytes]) -> Any:
    def key_provider(kid: str | None, _jku: str | None) -> PyJWK:
        if kid not in keys:
            raise KeyError(kid)
        return _public_jwk(keys[kid])

    return create_signature_verifier(key_provider, ["EdDSA"])


def _parse(card: dict[str, Any]) -> Any:
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        return parse_agent_card(json.loads(json.dumps(card)))


async def _integration(config: AgentDidA2AConfig | None = None) -> tuple[AgentDidA2AIntegration, CreateAgentResult]:
    AgentIdentity.set_registry(InMemoryAgentRegistry())
    identity = AgentIdentity(AgentIdentityConfig(controller_signer=LocalKeySigner.generate()[0]))
    runtime = await identity.create(
        CreateAgentParams(name="InteropBot", description="Talks to a2a-sdk", core_model="m", system_prompt="p")
    )
    return create_agent_did_a2a_integration(agent_identity=identity, runtime_identity=runtime, config=config), runtime


def _document_keys(runtime: CreateAgentResult) -> dict[str, bytes]:
    return {
        method.id: decode_public_key_multibase(method.public_key_multibase)
        for method in runtime.document.verification_method
        if method.public_key_multibase
    }


@pytest.mark.asyncio
async def test_a2a_sdk_verifies_a_card_signed_by_the_integration() -> None:
    integration, runtime = await _integration(
        AgentDidA2AConfig(
            require_signed_requests=False,
            oauth_client_credentials=AgentDidA2AOAuthClientCredentials(
                token_url="https://as.example.com/token", scopes={"a2a": "Call the agent"}
            ),
            additional_security_schemes={"mtls": {"mtlsSecurityScheme": {"description": "Client certificates"}}},
        )
    )
    card = await integration.signed_agent_card_json(
        agent_url="https://agents.example.com/a2a",
        skills=SKILLS,
        capabilities=A2AAgentCapabilities(streaming=False),
        provider=A2AAgentProvider(url="https://example.com", organization="Example"),
    )
    # default values are present in the JSON (required: false, examples: []) and must not be covered
    assert card["capabilities"]["extensions"][-1]["required"] is False

    parsed = _parse(card)
    validate_proto_required_fields(parsed)
    _verifier(_document_keys(runtime))(parsed)
    assert MessageToDict(parsed)["capabilities"]["streaming"] is False


@pytest.mark.asyncio
async def test_the_sdk_verifies_a_card_signed_by_a2a_sdk() -> None:
    integration, runtime = await _integration()
    key_id = runtime.document.assertion_method[0] if runtime.document.assertion_method else ""
    seed = bytes.fromhex(runtime.agent_private_key)[:32]
    public_key = _document_keys(runtime)[key_id]
    private_jwk = PyJWK(
        {"kty": "OKP", "crv": "Ed25519", "x": bytes_to_base64url(public_key), "d": bytes_to_base64url(seed)},
        algorithm="EdDSA",
    )
    unsigned = integration.agent_card_json(agent_url="https://agents.example.com/a2a", skills=SKILLS)
    signer = create_agent_card_signer(private_jwk, {"alg": "EdDSA", "kid": key_id, "typ": "JOSE", "jku": None})
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        signed = MessageToDict(signer(_parse(unsigned)))

    assert (await integration.agent_identity.client.verify_agent_card(signed)).ok
    tampered = {**signed, "name": "Impostor"}
    result = await integration.agent_identity.client.verify_agent_card(tampered)
    assert (result.ok, result.reason) == (False, "tampered")


def _vector_keys() -> dict[str, bytes]:
    return {kid: decode_public_key_multibase(key["publicKeyMultibase"]) for kid, key in VECTORS["keys"].items()}


@pytest.mark.parametrize(
    "vector", [v for v in VECTORS["cards"] if v["expected"] == "ok"], ids=lambda v: v["name"]
)
def test_a2a_sdk_verifies_the_ok_card_vectors(vector: dict[str, Any]) -> None:
    _verifier(_vector_keys())(_parse(vector["card"]))


@pytest.mark.parametrize(
    "vector",
    # a2a-sdk drops members A2A does not define before it verifies; Agent-DID covers them (fixture comment)
    [v for v in VECTORS["cards"] if v["expected"] == "tampered" and "does not define" not in v["name"]],
    ids=lambda v: v["name"],
)
def test_a2a_sdk_rejects_the_tampered_card_vectors(vector: dict[str, Any]) -> None:
    with pytest.raises(InvalidSignaturesError):
        _verifier(_vector_keys())(_parse(vector["card"]))


def test_json_rpc_params_have_the_a2a_1_0_shape() -> None:
    send = build_send_message_request(
        request_id=1,
        message=text_message("Hello", message_id="m-1", context_id="c-1"),
        configuration={"acceptedOutputModes": ["text/plain"], "historyLength": 3},
        metadata={"k": "v"},
    )
    parsed = ParseDict(send.params, SendMessageRequest())
    validate_proto_required_fields(parsed)
    assert MessageToDict(parsed) == send.params

    get = build_get_task_request(request_id=2, task_id="t-1", history_length=5)
    assert MessageToDict(ParseDict(get.params, GetTaskRequest())) == get.params
