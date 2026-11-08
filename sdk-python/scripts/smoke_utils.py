"""Helpers shared by the Python smokes (resolver HA drill, JSON-RPC resolver)."""

from __future__ import annotations

import json
import threading
from collections.abc import Callable
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from agent_did_sdk.core.identity import AgentIdentity
from agent_did_sdk.core.types import AgentDIDDocument
from agent_did_sdk.registry.in_memory import InMemoryAgentRegistry
from agent_did_sdk.resolver.in_memory import InMemoryDIDResolver

JSON_CONTENT_TYPE = "application/json"


def reset_agent_identity_state() -> None:
    AgentIdentity.set_resolver(InMemoryDIDResolver())
    AgentIdentity.set_registry(InMemoryAgentRegistry())
    AgentIdentity.get_default_client()._history_store = {}
    AgentIdentity.get_default_client()._did_webvh_log_store = {}
    AgentIdentity.get_default_client()._did_webvh_signer_store = {}
    AgentIdentity.get_default_client()._bootstrap_controllers = {}


def build_sample_document(did: str) -> AgentDIDDocument:
    verification_method_id = f"{did}#key-1"
    document = AgentDIDDocument(
        **{
            "@context": ["https://www.w3.org/ns/did/v1", "https://agent-did.org/v1"],
            "id": did,
            "controller": "did:ethr:0xcontroller",
            "created": "2026-01-01T00:00:00.000Z",
            "updated": "2026-01-01T00:00:00.000Z",
            "agentMetadata": {
                "name": "SmokeBot",
                "version": "1.0.0",
                "coreModelHash": "hash://sha256/model",
                "systemPromptHash": "hash://sha256/prompt",
            },
            "verificationMethod": [
                {
                    "id": verification_method_id,
                    "type": "Ed25519VerificationKey2020",
                    "controller": "did:ethr:0xcontroller",
                    "publicKeyMultibase": "zabc",
                }
            ],
            "authentication": [verification_method_id],
        }
    )
    return document


@dataclass
class JsonRpcResponse:
    payload: dict[str, Any]
    http_status: int = 200


class JsonRpcTestServer:
    def __init__(self, handler: Callable[[dict[str, Any]], JsonRpcResponse]) -> None:
        self._handler = handler
        self._server: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None

    def start(self) -> int:
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self) -> None:  # noqa: N802
                if self.path != "/":
                    self.send_response(404)
                    self.end_headers()
                    return

                content_length = int(self.headers.get("Content-Length", "0"))
                raw_body = self.rfile.read(content_length) if content_length else b"{}"
                try:
                    payload = json.loads(raw_body.decode("utf-8") or "{}")
                    response = outer._handler(payload)
                    self.send_response(response.http_status)
                    self.send_header("Content-Type", JSON_CONTENT_TYPE)
                    self.end_headers()
                    self.wfile.write(json.dumps(response.payload).encode("utf-8"))
                except Exception as exc:  # noqa: BLE001
                    self.send_response(500)
                    self.send_header("Content-Type", JSON_CONTENT_TYPE)
                    self.end_headers()
                    self.wfile.write(
                        json.dumps(
                            {
                                "jsonrpc": "2.0",
                                "id": None,
                                "error": {"code": -32000, "message": str(exc)},
                            }
                        ).encode("utf-8")
                    )

            def log_message(self, format: str, *args: Any) -> None:  # noqa: A003
                return

        self._server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()
        return int(self._server.server_address[1])

    def stop(self) -> None:
        if self._server is None:
            return
        self._server.shutdown()
        self._server.server_close()
        if self._thread is not None:
            self._thread.join(timeout=5)
