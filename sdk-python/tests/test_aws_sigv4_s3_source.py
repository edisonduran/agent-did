"""Tests for AwsSigV4S3DIDDocumentSource."""

from __future__ import annotations

import json
from datetime import datetime, timezone

import httpx

from agent_did_sdk.resolver.aws_sigv4_s3_source import (
    AwsSigV4S3DIDDocumentSource,
    AwsSigV4S3DIDDocumentSourceConfig,
)


def _make_document() -> dict[str, object]:
    did = "did:webvh:QmAwsScid:example.com:agents:aws-bot"
    return {
        "@context": ["https://www.w3.org/ns/did/v1", "https://agent-did.org/v1"],
        "id": did,
        "controller": "did:webvh:QmAwsScid:example.com:organizations:ops-root",
        "created": "2026-05-07T00:00:00.000Z",
        "updated": "2026-05-07T00:00:00.000Z",
        "agentMetadata": {
            "name": "AwsResolverBot",
            "version": "1.0.0",
            "coreModelHash": "hash://sha256/model",
            "systemPromptHash": "hash://sha256/prompt",
        },
        "verificationMethod": [
            {
                "id": f"{did}#key-1",
                "type": "Ed25519VerificationKey2020",
                "controller": "did:webvh:QmAwsScid:example.com:organizations:ops-root",
                "publicKeyMultibase": "zabc",
            }
        ],
        "authentication": [f"{did}#key-1"],
        "assertionMethod": [f"{did}#key-1"],
    }


class TestAwsSigV4S3DIDDocumentSource:
    async def test_signs_get_requests_with_sigv4_headers(self) -> None:
        seen_requests: list[httpx.Request] = []

        def handler(request: httpx.Request) -> httpx.Response:
            seen_requests.append(request)
            return httpx.Response(200, json=_make_document())

        client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
        source = AwsSigV4S3DIDDocumentSource(AwsSigV4S3DIDDocumentSourceConfig(
            bucket="agent-did-history",
            endpoint="https://s3.us-east-1.amazonaws.com",
            region="us-east-1",
            access_key_id="AKIDEXAMPLE",
            secret_access_key="wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
            now=lambda: datetime(2026, 5, 7, 12, 34, 56, tzinfo=timezone.utc),
            http_client=client,
        ))

        loaded = await source.get_by_reference("hash://sha256/aws-doc")

        assert loaded is not None
        assert loaded.id == _make_document()["id"]
        assert len(seen_requests) == 1
        assert seen_requests[0].headers["x-amz-date"] == "20260507T123456Z"
        assert seen_requests[0].headers["x-amz-content-sha256"] == (
            "e3b0c44298fc1c149afbf4c8996fb924"
            "27ae41e4649b934ca495991b7852b855"
        )
        assert "Credential=AKIDEXAMPLE/20260507/us-east-1/s3/aws4_request" in seen_requests[0].headers["authorization"]

    async def test_signs_did_log_writes_and_includes_session_token(self) -> None:
        seen_requests: list[httpx.Request] = []

        def handler(request: httpx.Request) -> httpx.Response:
            seen_requests.append(request)
            return httpx.Response(200)

        did_log = json.dumps({"versionId": "1-QmAwsScid", "state": _make_document()})
        client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
        source = AwsSigV4S3DIDDocumentSource(AwsSigV4S3DIDDocumentSourceConfig(
            bucket="agent-did-history",
            endpoint="https://s3.us-east-1.amazonaws.com",
            region="us-east-1",
            access_key_id="AKIDEXAMPLE",
            secret_access_key="wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
            session_token="session-token-example",
            did_log_store_method="POST",
            now=lambda: datetime(2026, 5, 7, 12, 34, 56, tzinfo=timezone.utc),
            http_client=client,
        ))

        await source.store_did_log_by_reference("history://aws/bot", did_log)

        assert len(seen_requests) == 1
        assert seen_requests[0].method == "POST"
        assert seen_requests[0].headers["x-amz-date"] == "20260507T123456Z"
        assert seen_requests[0].headers["x-amz-security-token"] == "session-token-example"
        assert (
            "SignedHeaders=content-type;host;x-amz-content-sha256;x-amz-date;x-amz-security-token"
            in seen_requests[0].headers["authorization"]
        )
        assert seen_requests[0].content.decode("utf-8") == did_log
