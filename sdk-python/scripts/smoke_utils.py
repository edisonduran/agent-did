from __future__ import annotations

import json
import os
import signal
import subprocess
import threading
import time
import urllib.error
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from agent_did_sdk.core.identity import AgentIdentity
from agent_did_sdk.core.types import AgentDIDDocument
from agent_did_sdk.registry.in_memory import InMemoryAgentRegistry
from agent_did_sdk.resolver.in_memory import InMemoryDIDResolver

ROOT = Path(__file__).resolve().parents[2]
CONTRACTS_DIR = ROOT / "contracts"
SDK_PYTHON_DIR = ROOT / "sdk-python"
CONTRACT_ARTIFACT_PATH = CONTRACTS_DIR / "artifacts" / "src" / "AgentRegistry.sol" / "AgentRegistry.json"
NPM_COMMAND = "npm.cmd" if os.name == "nt" else "npm"
JSON_CONTENT_TYPE = "application/json"


def run(command: list[str], cwd: Path, env: dict[str, str] | None = None) -> str:
    completed = subprocess.run(
        command,
        cwd=cwd,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )
    if completed.returncode != 0:
        raise RuntimeError(
            f"Command failed: {' '.join(command)}\n"
            f"stdout:\n{completed.stdout}\n"
            f"stderr:\n{completed.stderr}"
        )
    return completed.stdout


def spawn_hardhat_node() -> subprocess.Popen[str]:
    kwargs: dict[str, Any] = {
        "cwd": CONTRACTS_DIR,
        "text": True,
        "stdout": subprocess.DEVNULL,
        "stderr": subprocess.DEVNULL,
    }
    if os.name == "nt":
        kwargs["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP
    else:
        kwargs["start_new_session"] = True
    process = subprocess.Popen([NPM_COMMAND, "run", "node:local"], **kwargs)
    return process


def wait_for_hardhat_node(process: subprocess.Popen[str], timeout_seconds: int = 30) -> None:
    deadline = time.time() + timeout_seconds
    while time.time() < deadline:
        if process.poll() is not None:
            raise RuntimeError(f"Hardhat node exited before startup with code {process.returncode}")
        request = urllib.request.Request(
            "http://127.0.0.1:8545",
            data=json.dumps(
                {"jsonrpc": "2.0", "id": 1, "method": "eth_chainId", "params": []}
            ).encode("utf-8"),
            headers={"Content-Type": JSON_CONTENT_TYPE},
        )
        try:
            with urllib.request.urlopen(request, timeout=2) as response:  # noqa: S310
                payload = json.loads(response.read().decode("utf-8"))
            if payload.get("result"):
                return
        except (TimeoutError, urllib.error.URLError, json.JSONDecodeError):
            time.sleep(0.5)
            continue
        time.sleep(0.5)
    raise RuntimeError("Timeout waiting for Hardhat node startup")


def stop_process_tree(process: subprocess.Popen[str]) -> None:
    if process.poll() is not None:
        return
    if os.name == "nt":
        subprocess.run(
            ["taskkill", "/PID", str(process.pid), "/T", "/F"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )
        return
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        return

def reset_agent_identity_state() -> None:
    AgentIdentity.set_resolver(InMemoryDIDResolver())
    AgentIdentity.set_registry(InMemoryAgentRegistry())
    AgentIdentity.get_default_client()._history_store = {}
    AgentIdentity.get_default_client()._did_webvh_log_store = {}
    AgentIdentity.get_default_client()._did_webvh_signer_store = {}
    AgentIdentity.get_default_client()._bootstrap_controllers = {}


def load_contract_artifact() -> dict[str, Any]:
    if not CONTRACT_ARTIFACT_PATH.exists():
        raise RuntimeError(f"Contract artifact not found: {CONTRACT_ARTIFACT_PATH}")
    return json.loads(CONTRACT_ARTIFACT_PATH.read_text(encoding="utf-8"))


def load_contract_abi() -> list[dict[str, Any]]:
    return load_contract_artifact()["abi"]


def load_contract_bytecode() -> str:
    artifact = load_contract_artifact()
    bytecode = artifact.get("bytecode")
    if not isinstance(bytecode, str) or not bytecode:
        raise RuntimeError("Contract bytecode not found in compiled artifact")
    return bytecode


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
