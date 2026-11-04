"""Python half of the live cross-SDK round trip (M-13).

    python sdk-python/scripts/cross_sdk_roundtrip.py emit   > bundle.json   # fresh identity, signed by the Python SDK
    python sdk-python/scripts/cross_sdk_roundtrip.py verify < bundle.json   # verifies a bundle produced by the TS SDK

Mirrors scripts/cross-sdk/ts-roundtrip.js. Exit code 0 means every check passed.
"""

from __future__ import annotations

import asyncio
import json
import sys

from agent_did_sdk import (
    AgentDidClient,
    AgentDidClientOptions,
    AgentIdentity,
    AgentIdentityConfig,
    InMemoryAgentRegistry,
    InMemoryDIDResolver,
    InMemoryNonceStore,
)
from agent_did_sdk.core.signer import LocalKeySigner
from agent_did_sdk.core.types import (
    AgentDIDDocument,
    CreateAgentParams,
    SignHttpRequestParams,
    VerifyHttpRequestSignatureParams,
)

MESSAGE = "cross-sdk-roundtrip:v1"
URL = "https://api.example.com/v1/roundtrip?mode=live"
BODY = '{"roundtrip":true}'


def _dump(doc: AgentDIDDocument) -> dict[str, object]:
    return doc.model_dump(by_alias=True, exclude_none=True, mode="json")


async def emit() -> None:
    controller_signer, _ = LocalKeySigner.generate()
    client = AgentDidClient()
    identity = AgentIdentity(AgentIdentityConfig(controller_signer=controller_signer, client=client))
    result = await identity.create(
        CreateAgentParams(name="CrossSdkPy", core_model="roundtrip-model", system_prompt="roundtrip-prompt")
    )
    document = result.document
    signature_hex = await identity.sign_message(MESSAGE, result.agent_private_key)
    headers = await identity.sign_http_request(
        SignHttpRequestParams(
            method="POST", url=URL, body=BODY, agent_private_key=result.agent_private_key, agent_did=document.id
        )
    )
    chain = await client.resolve_controller_chain(document.id)
    bundle = {
        "producer": "python",
        "document": _dump(document),
        "controllerDocuments": [_dump(d) for d in chain if d.id != document.id],
        "keyId": document.verification_method[0].id,
        "message": {"payload": MESSAGE, "signatureHex": signature_hex},
        "http": {"method": "POST", "url": URL, "body": BODY, "headers": headers},
    }
    sys.stdout.write(json.dumps(bundle, indent=2))


async def verify() -> int:
    bundle = json.load(sys.stdin)
    document = AgentDIDDocument(**bundle["document"])
    resolver = InMemoryDIDResolver()
    for raw in [bundle["document"], *bundle["controllerDocuments"]]:
        resolver.register_document(AgentDIDDocument(**raw))
    registry = InMemoryAgentRegistry()
    await registry.register(document.id, document.controller, "hash://sha256/roundtrip")
    client = AgentDidClient(AgentDidClientOptions(resolver=resolver, registry=registry))

    http = bundle["http"]

    def http_params(body: str) -> VerifyHttpRequestSignatureParams:
        return VerifyHttpRequestSignatureParams(
            method=http["method"], url=http["url"], body=body, headers=http["headers"], nonce_store=InMemoryNonceStore()
        )

    msg = bundle["message"]
    results = {
        "message": await client.verify_signature(document.id, msg["payload"], msg["signatureHex"], bundle["keyId"]),
        "http": await client.verify_http_request_signature(http_params(http["body"])),
        "tamperedMessage": await client.verify_signature(
            document.id, msg["payload"] + "x", msg["signatureHex"], bundle["keyId"]
        ),
        "tamperedHttp": await client.verify_http_request_signature(http_params(http["body"] + " ")),
    }
    ok = results["message"] and results["http"] and not results["tamperedMessage"] and not results["tamperedHttp"]
    print(f"python verify of {bundle['producer']} bundle: {json.dumps(results)}", file=sys.stderr)
    return 0 if ok else 1


def main() -> int:
    mode = sys.argv[1] if len(sys.argv) > 1 else ""
    if mode == "emit":
        asyncio.run(emit())
        return 0
    if mode == "verify":
        return asyncio.run(verify())
    print("usage: emit|verify", file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
