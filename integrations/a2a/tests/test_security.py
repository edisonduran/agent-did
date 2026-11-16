"""Security tests for the Agent-DID A2A integration."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from agent_did_a2a.config import AgentDidA2AConfig, AgentDidA2AExposureConfig
from agent_did_a2a.jsonrpc import JsonRpcRequest
from agent_did_a2a.sanitization import sanitize_output


def test_default_exposure_has_secure_defaults() -> None:
    config = AgentDidA2AExposureConfig()

    assert config.sign_requests is True
    assert config.verify_requests is True
    assert config.enrich_agent_card is True
    # Flags without an operation behind them were removed in 1.0.0-rc.5
    for removed in ("resolve_remote_did", "document_history", "rotate_keys"):
        with pytest.raises(ValidationError):
            AgentDidA2AExposureConfig(**{removed: True})
    with pytest.raises(ValidationError):
        AgentDidA2AConfig(default_request_timeout_seconds=30)  # type: ignore[call-arg]


def test_config_rejects_extra_fields() -> None:
    with pytest.raises(ValidationError):
        AgentDidA2AConfig(unknown_field="bad")  # type: ignore[call-arg]


def test_sanitize_output_redacts_sensitive_fields() -> None:
    data = {
        "did": "did:agent:0x123",
        "private_key": "deadbeef",
        "agent_private_key": "secret",
        "name": "TestBot",
        "nested": {
            "signature": "sig-value",
            "safe_field": "visible",
        },
    }

    sanitized = sanitize_output(data)

    assert sanitized["did"] == "did:agent:0x123"
    assert sanitized["private_key"] == "[REDACTED]"
    assert sanitized["agent_private_key"] == "[REDACTED]"
    assert sanitized["name"] == "TestBot"
    assert sanitized["nested"]["signature"] == "[REDACTED]"
    assert sanitized["nested"]["safe_field"] == "visible"


def test_sanitize_output_handles_lists() -> None:
    data = [
        {"signature": "abc", "did": "did:agent:0x1"},
        {"signature": "def", "did": "did:agent:0x2"},
    ]

    sanitized = sanitize_output(data)

    assert all(item["signature"] == "[REDACTED]" for item in sanitized)
    assert sanitized[0]["did"] == "did:agent:0x1"


def test_jsonrpc_request_forbids_extra() -> None:
    with pytest.raises(ValidationError):
        JsonRpcRequest(id=1, method="SendMessage", extra_field="bad")  # type: ignore[call-arg]


def test_allow_private_network_defaults_false() -> None:
    config = AgentDidA2AConfig()
    assert config.allow_private_network_targets is False
